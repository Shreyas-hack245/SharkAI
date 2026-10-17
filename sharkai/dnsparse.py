"""Minimal, defensive DNS message parser (handles name compression, loop guards)."""
from __future__ import annotations

import ipaddress
import struct

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
         33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 65: "HTTPS", 252: "AXFR", 255: "ANY"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def type_name(t: int) -> str:
    return TYPES.get(t, f"TYPE{t}")


def _label(raw: bytes) -> str:
    return "".join(chr(b) if 32 < b < 127 and b != 46 else f"\\{b:03d}" for b in raw)


def _name(msg: bytes, pos: int) -> tuple[str, int]:
    labels: list[str] = []
    end, hops, total = None, 0, 0
    while True:
        if pos >= len(msg):
            raise ValueError("name overruns message")
        ln = msg[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise ValueError("bad pointer")
            if end is None:
                end = pos + 2
            hops += 1
            if hops > 20:
                raise ValueError("compression loop")
            pos = ((ln & 0x3F) << 8) | msg[pos + 1]
            continue
        if ln & 0xC0:
            raise ValueError("bad label")
        raw = msg[pos + 1:pos + 1 + ln]
        if len(raw) < ln:
            raise ValueError("label overruns message")
        total += ln + 1
        if total > 255:
            raise ValueError("name too long")
        labels.append(_label(raw))
        pos += 1 + ln
    return (".".join(labels) or "."), (end if end is not None else pos)


def _rdata(msg: bytes, rtype: int, start: int, length: int) -> str:
    raw = msg[start:start + length]
    try:
        if rtype == 1 and length == 4:
            return str(ipaddress.IPv4Address(raw))
        if rtype == 28 and length == 16:
            return str(ipaddress.IPv6Address(raw))
        if rtype in (2, 5, 12):
            return _name(msg, start)[0]
        if rtype == 15:
            return f"{struct.unpack('>H', raw[:2])[0]} {_name(msg, start + 2)[0]}"
        if rtype == 16:
            out, i = [], 0
            while i < len(raw):
                ln = raw[i]
                out.append(raw[i + 1:i + 1 + ln].decode("latin-1"))
                i += 1 + ln
            return "".join(out)
    except (ValueError, struct.error):
        pass
    return raw[:48].hex() + ("..." if length > 48 else "")


def parse(msg: bytes) -> dict | None:
    """Return a dict describing the DNS message, or None if it is not valid DNS."""
    if len(msg) < 12:
        return None
    try:
        txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12])
        if qd > 16 or an > 200 or ns > 200 or ar > 200 or (flags >> 11) & 0xF > 5:
            return None
        pos, questions = 12, []
        for _ in range(qd):
            name, pos = _name(msg, pos)
            qtype, qclass = struct.unpack_from(">HH", msg, pos)
            pos += 4
            questions.append({"name": name, "type": type_name(qtype), "class": qclass})
        answers = []
        for _ in range(an + ns):
            name, pos = _name(msg, pos)
            rtype, rclass, ttl, rdlen = struct.unpack_from(">HHIH", msg, pos)
            pos += 10
            if pos + rdlen > len(msg):
                raise ValueError("rdata overruns message")
            answers.append({"name": name, "type": type_name(rtype), "ttl": ttl, "data": _rdata(msg, rtype, pos, rdlen)})
            pos += rdlen
        if not questions and not answers:
            return None
        return {"id": txid, "response": bool(flags & 0x8000), "opcode": (flags >> 11) & 0xF,
                "rcode": RCODES.get(flags & 0xF, f"RCODE{flags & 0xF}"), "questions": questions, "answers": answers}
    except (ValueError, struct.error):
        return None
