"""Safe display-filter language (Wireshark-flavoured subset).

Filters are tokenised and parsed by a hand-written recursive-descent parser into closures. There is no
eval(), no user regex, and every field/operator is checked against an allowlist at parse time, with hard
limits on length, nesting and the number of comparisons.

    ip.addr == 10.0.0.0/8 and tcp.port in {80 8080} and not dns
    http.host contains "example" or frame contains "flag{"
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable

MAX_LEN, MAX_COMPARISONS, MAX_DEPTH, MAX_VALUE = 300, 20, 8, 100


class FilterError(ValueError):
    def __init__(self, message: str, pos: int = 0) -> None:
        super().__init__(message)
        self.pos = pos


@dataclass(frozen=True)
class Field:
    kind: str                      # int | str | ip | port
    get: Callable[[dict], object]  # extracts from a packet summary record
    doc: str


def _rec(key: str, default=None):
    return lambda p: p.get(key, default)


FIELDS: dict[str, Field] = {
    "frame.number": Field("int", _rec("n"), "Packet number"),
    "frame.len": Field("int", _rec("length"), "Original frame length in bytes"),
    "frame.time_rel": Field("int", _rec("rel"), "Seconds since first packet"),
    "eth.src": Field("str", _rec("eth_src", ""), "Ethernet source MAC"),
    "eth.dst": Field("str", _rec("eth_dst", ""), "Ethernet destination MAC"),
    "ip.src": Field("ip", _rec("src", ""), "Source IP (supports CIDR)"),
    "ip.dst": Field("ip", _rec("dst", ""), "Destination IP (supports CIDR)"),
    "ip.addr": Field("ip", lambda p: (p.get("src", ""), p.get("dst", "")), "Either IP (supports CIDR)"),
    "tcp.srcport": Field("port", lambda p: p.get("sport") if p.get("l4") == "TCP" else None, "TCP source port"),
    "tcp.dstport": Field("port", lambda p: p.get("dport") if p.get("l4") == "TCP" else None, "TCP destination port"),
    "tcp.port": Field("port", lambda p: (p.get("sport"), p.get("dport")) if p.get("l4") == "TCP" else (), "Either TCP port"),
    "udp.srcport": Field("port", lambda p: p.get("sport") if p.get("l4") == "UDP" else None, "UDP source port"),
    "udp.dstport": Field("port", lambda p: p.get("dport") if p.get("l4") == "UDP" else None, "UDP destination port"),
    "udp.port": Field("port", lambda p: (p.get("sport"), p.get("dport")) if p.get("l4") == "UDP" else (), "Either UDP port"),
    "port": Field("port", lambda p: (p.get("sport"), p.get("dport")) if "sport" in p else (), "Either TCP/UDP port"),
    "tcp.stream": Field("int", _rec("stream"), "TCP stream index"),
    "tcp.flags": Field("str", _rec("flags", ""), "TCP flag names, e.g. SYN,ACK (use contains)"),
    "proto": Field("str", _rec("proto", ""), "Application/transport label, e.g. HTTP, DNS, TCP"),
    "http.method": Field("str", _rec("http_method", ""), "HTTP request method"),
    "http.uri": Field("str", _rec("http_uri", ""), "HTTP request URI"),
    "http.host": Field("str", _rec("http_host", ""), "HTTP Host header"),
    "http.status": Field("int", _rec("http_status"), "HTTP response status code"),
    "dns.qry.name": Field("str", _rec("dns_name", ""), "First DNS question name"),
    "dns.qry.type": Field("str", _rec("dns_type", ""), "First DNS question type"),
    "info": Field("str", _rec("info", ""), "The Info column text"),
}
FIELDS["frame.time_rel"] = Field("float", _rec("rel"), "Seconds since first packet")
BARE = {"tcp": lambda p: p.get("l4") == "TCP", "udp": lambda p: p.get("l4") == "UDP",
        "icmp": lambda p: p.get("l4") in ("ICMP", "ICMPv6"), "arp": lambda p: p.get("l4") == "ARP",
        "ip": lambda p: bool(p.get("src")) and p.get("l4") != "ARP", "ipv6": lambda p: ":" in p.get("src", "") and p.get("l4") != "ARP",
        "dns": lambda p: p.get("proto") == "DNS", "http": lambda p: p.get("proto") == "HTTP",
        "tls": lambda p: p.get("proto") == "TLS", "ftp": lambda p: p.get("proto") == "FTP",
        "ssh": lambda p: p.get("proto") == "SSH", "smtp": lambda p: p.get("proto") == "SMTP"}
OPS_BY_KIND = {"int": {"==", "!=", "<", "<=", ">", ">=", "in"}, "float": {"==", "!=", "<", "<=", ">", ">="},
               "port": {"==", "!=", "<", "<=", ">", ">=", "in"}, "ip": {"==", "!=", "in"},
               "str": {"==", "!=", "contains", "in"}}
CONTAINS_FRAME = "frame"
TOKEN_RE = re.compile(r'\s*(?:(&&|\|\||==|!=|<=|>=|[()<>!{}])|"([^"]*)"|\'([^\']*)\'|([A-Za-z0-9_.:/\-\[\]*+%@~]+))')


def _tokenise(text: str) -> list[tuple[str, str, int]]:
    out, pos = [], 0
    text = text.rstrip()
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise FilterError(f"unexpected character {text[pos:].lstrip()[:1]!r}", pos)
        start = m.start() + (len(m.group()) - len(m.group().lstrip()))
        if m.group(1):
            out.append(("op", m.group(1), start))
        elif m.group(2) is not None or m.group(3) is not None:
            out.append(("str", m.group(2) if m.group(2) is not None else m.group(3), start))
        else:
            out.append(("word", m.group(4), start))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, text: str, frame_reader) -> None:
        self.toks = _tokenise(text)
        self.i = 0
        self.comparisons = 0
        self.frame_reader = frame_reader   # callable(packet_record) -> bytes, used by `frame contains`
        self.needs_frame = False

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else ("eof", "", -1)

    def take(self):
        t = self.peek()
        self.i += 1
        return t

    def is_word(self, *names: str) -> bool:
        t = self.peek()
        return t[0] == "word" and t[1].lower() in names

    def parse(self):
        if not self.toks:
            return lambda p: True
        node = self.or_expr(0)
        if self.peek()[0] != "eof":
            raise FilterError(f"unexpected {self.peek()[1]!r}", self.peek()[2])
        return node

    def or_expr(self, depth):
        left = self.and_expr(depth)
        while self.is_word("or") or self.peek()[1] == "||":
            self.take()
            right, l = self.and_expr(depth), left
            left = (lambda a, b: lambda p: a(p) or b(p))(l, right)
        return left

    def and_expr(self, depth):
        left = self.not_expr(depth)
        while self.is_word("and") or self.peek()[1] == "&&":
            self.take()
            right, l = self.not_expr(depth), left
            left = (lambda a, b: lambda p: a(p) and b(p))(l, right)
        return left

    def not_expr(self, depth):
        if self.is_word("not") or self.peek() == ("op", "!", self.peek()[2]):
            self.take()
            inner = self.not_expr(depth + 1)
            if depth + 1 > MAX_DEPTH:
                raise FilterError("filter nested too deeply", self.peek()[2])
            return lambda p: not inner(p)
        return self.primary(depth)

    def primary(self, depth):
        kind, val, pos = self.peek()
        if kind == "op" and val == "(":
            if depth + 1 > MAX_DEPTH:
                raise FilterError("filter nested too deeply", pos)
            self.take()
            node = self.or_expr(depth + 1)
            if self.take()[1] != ")":
                raise FilterError("missing closing parenthesis", pos)
            return node
        if kind != "word":
            raise FilterError(f"expected a field name, got {val!r}" if val else "unexpected end of filter", pos)
        self.take()
        name = val.lower()
        nxt = self.peek()
        is_cmp = nxt[0] == "op" and nxt[1] in ("==", "!=", "<", "<=", ">", ">=") or (nxt[0] == "word" and nxt[1].lower() in ("contains", "in"))
        if name in BARE and not is_cmp:
            return BARE[name]
        if not is_cmp:
            if name in FIELDS or name == CONTAINS_FRAME:
                raise FilterError(f"{name!r} needs an operator, e.g. {name} == value", pos)
            raise FilterError(f"unknown field {val!r} (see the filter help for allowed fields)", pos)
        self.comparisons += 1
        if self.comparisons > MAX_COMPARISONS:
            raise FilterError(f"too many comparisons (max {MAX_COMPARISONS})", pos)
        op = self.take()[1].lower()
        if name == CONTAINS_FRAME:
            if op != "contains":
                raise FilterError("frame only supports the 'contains' operator", pos)
            needle = self.value()[0].lower().encode("latin-1", "replace")
            if not needle:
                raise FilterError("empty search string", pos)
            self.needs_frame = True
            reader = self.frame_reader
            return lambda p: needle in reader(p).lower()
        field = FIELDS.get(name)
        if field is None:
            raise FilterError(f"unknown field {val!r} (see the filter help for allowed fields)", pos)
        if op not in OPS_BY_KIND[field.kind]:
            raise FilterError(f"operator {op!r} is not valid for {name} ({field.kind})", pos)
        if op == "in":
            values = self.value_set()
        else:
            values = [self.value()]
        return self.compile(field, op, [self.coerce(field, v, p) for v, p in values], name)

    def value(self) -> tuple[str, int]:
        kind, val, pos = self.take()
        if kind not in ("word", "str"):
            raise FilterError("expected a value", pos)
        if len(val) > MAX_VALUE:
            raise FilterError(f"value too long (max {MAX_VALUE} characters)", pos)
        return val, pos

    def value_set(self) -> list[tuple[str, int]]:
        if self.take()[1] != "{":
            raise FilterError("'in' expects a set like {80 443}", self.peek()[2])
        out = []
        while self.peek()[1] != "}":
            if self.peek()[0] == "eof" or len(out) >= 50:
                raise FilterError("unterminated or oversized set", self.peek()[2])
            out.append(self.value())
        self.take()
        if not out:
            raise FilterError("empty set", self.peek()[2])
        return out

    @staticmethod
    def coerce(field: Field, raw: str, pos: int):
        try:
            if field.kind in ("int", "port"):
                v = int(raw, 0) if raw[:2].lower() == "0x" else int(raw)
                if field.kind == "port" and not 0 <= v <= 65535:
                    raise ValueError
                return v
            if field.kind == "float":
                return float(raw)
            if field.kind == "ip":
                return ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise FilterError(f"{raw!r} is not a valid {field.kind} value", pos) from None
        return raw.lower()

    @staticmethod
    def compile(field: Field, op: str, values: list, name: str):
        get, kind = field.get, field.kind

        def one(actual, expected) -> bool:
            if actual is None or actual == "":
                return False
            if kind == "ip":
                try:
                    return ipaddress.ip_address(actual) in expected
                except ValueError:
                    return False
            if kind == "str":
                a = str(actual).lower()
                return expected in a if op == "contains" else a == expected
            return {"==": actual == expected, "!=": actual != expected, "<": actual < expected, "<=": actual <= expected,
                    ">": actual > expected, ">=": actual >= expected, "in": actual == expected}[op]

        def test(p: dict) -> bool:
            raw = get(p)
            actuals = raw if isinstance(raw, tuple) else (raw,)
            if op == "!=":   # Wireshark semantics: no side may equal the value
                return not any(one_eq(kind, a, values[0]) for a in actuals if a not in (None, ""))
            return any(one(a, v) for a in actuals for v in values)

        def one_eq(k, a, e) -> bool:
            if k == "ip":
                try:
                    return ipaddress.ip_address(a) in e
                except ValueError:
                    return False
            return str(a).lower() == e if k == "str" else a == e
        return test


def compile_filter(text: str, frame_reader=None) -> Callable[[dict], bool]:
    """Compile a filter string into a predicate over packet-summary records."""
    text = (text or "").strip()
    if len(text) > MAX_LEN:
        raise FilterError(f"filter too long (max {MAX_LEN} characters)")
    if any(ord(c) < 32 for c in text):
        raise FilterError("control characters are not allowed in filters")
    return _Parser(text, frame_reader or (lambda p: b"")).parse()


def describe() -> dict:
    return {
        "fields": [{"name": n, "type": f.kind, "description": f.doc} for n, f in FIELDS.items()]
                  + [{"name": "frame", "type": "str", "description": "Raw frame bytes; only 'frame contains \"text\"' is allowed"}],
        "protocols": sorted(BARE),
        "operators": ["==", "!=", "<", "<=", ">", ">=", "contains", "in {a b c}"],
        "logic": ["and / &&", "or / ||", "not / !", "( )"],
        "examples": ["dns", "ip.addr == 10.0.0.5 and tcp.port == 80", "http.method == POST",
                     "tcp.flags contains SYN and not tcp.flags contains ACK", "tcp.stream == 3",
                     "frame contains \"flag{\"", "port in {21 22 23}", "dns.qry.name contains example"],
        "limits": {"max_length": MAX_LEN, "max_comparisons": MAX_COMPARISONS, "max_depth": MAX_DEPTH},
    }
