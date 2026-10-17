"""CTF flag detection across plain text and common encodings.

Only *prefix allowlists* are configurable (letters/digits/underscore); no user-supplied regex is ever
compiled, so there is no ReDoS surface.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
from itertools import islice
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

KNOWN_PREFIXES = ("flag", "ctf", "picoctf", "htb", "thm", "ductf", "csictf", "uiuctf", "corctf", "lactf", "rarctf",
                  "dicectf", "justctf", "hackthebox", "tamuctf", "bsidessf", "idek", "sekai", "cyberthreat")
MAX_ENCODED_SCAN = 4 * 1024 * 1024
BODY = rb"[\x20-\x7e]{1,200}?"

_IDCHAR = bytes(1 if chr(c).isalnum() and c < 128 or c == 95 else 0 for c in range(256))
_KNOWN_BODY = re.compile(rb"\{" + BODY + rb"\}")
_GENERIC_TAIL = re.compile(rb"(?<![A-Za-z0-9_$])[A-Za-z][A-Za-z0-9_]{1,20}\Z")
_GENERIC_BODY = re.compile(rb"\{([A-Za-z0-9_\-!@#%^&*+=.,?/~]{6,100})\}")
_B64 = re.compile(rb"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX = re.compile(rb"(?:[0-9a-fA-F]{2}){8,}")
_B32 = re.compile(rb"[A-Z2-7]{16,}={0,6}")


@dataclass(slots=True)
class Finding:
    flag: str
    encoding: str     # plain | url | base64 | hex | base32 | rot13 | reversed (+ "+" for chained, e.g. base64+hex)
    confidence: str   # high (known prefix) | low (generic NAME{...} shape)
    pos: int          # byte offset in the scanned buffer where the (encoded) data starts
    context: str


def _clean(b: bytes, limit: int = 160) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b[:limit])


def _printable_ratio(b: bytes) -> float:
    return sum(1 for c in b[:4096] if 32 <= c < 127 or c in (9, 10, 13)) / max(1, len(b[:4096]))


class FlagScanner:
    def __init__(self, extra_prefixes: tuple[str, ...] = ()) -> None:
        prefixes = tuple(dict.fromkeys(KNOWN_PREFIXES + tuple(p.lower() for p in extra_prefixes)))
        short = b"|".join(re.escape(p.encode()) for p in prefixes if len(p) <= 3)
        long_ = b"|".join(re.escape(p.encode()) for p in prefixes if len(p) > 3)
        # Short prefixes (ctf, htb, thm) need a word boundary ("algorithm{" must not match thm{...});
        # longer ones may be glued to preceding text, which is common in real payloads.
        alts = []
        if long_:
            alts.append(rb"(?:" + long_ + rb")")
        if short:
            alts.append(rb"(?<![A-Za-z0-9_])(?:" + short + rb")")
        self._known_tail = re.compile(rb"(?i)(?:" + b"|".join(alts) + rb")\Z")
        self._prefixes = {p.lower() for p in prefixes}

    def _plain(self, data: bytes, allow_generic: bool) -> list[tuple[int, bytes, str]]:
        """Brace-driven scan: every flag contains '{', so find each one with bytes.find and only look at the
        few bytes before it. Cost is proportional to the number of braces, not the size of the buffer."""
        out: list[tuple[int, bytes, str]] = []
        pos = data.find(b"{")
        while pos != -1:
            if pos == 0 or not _IDCHAR[data[pos - 1]]:   # a prefix must end right before '{'
                pos = data.find(b"{", pos + 1)
                continue
            lo = max(0, pos - 40)
            window = data[lo:pos]
            m = self._known_tail.search(window)
            if m:
                body = _KNOWN_BODY.match(data, pos)
                if body:
                    out.append((lo + m.start(), data[lo + m.start():body.end()], "high"))
            elif allow_generic:
                g = _GENERIC_TAIL.search(window)
                body = _GENERIC_BODY.match(data, pos) if g else None
                if g and body and re.search(rb"[0-9_]", body.group(1)) and g.group().decode().lower() not in self._prefixes:
                    out.append((lo + g.start(), data[lo + g.start():body.end()], "low"))
            pos = data.find(b"{", pos + 1)
        return out

    def scan(self, data: bytes) -> list[Finding]:
        found: list[Finding] = []
        if len(data) < 6:
            return found
        self._scan(data, "plain", 0, found, generic=True, depth=0, base=None)
        if len(data) > MAX_ENCODED_SCAN:
            return self._dedupe(found)
        # reversed / rot13: known prefixes only (generic shapes would be far too noisy). Both keep '{' in place,
        # so buffers without a brace cannot contain one.
        variants = (("reversed", data[::-1]), ("rot13", codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1"))) \
            if b"{" in data else ()
        for name, buf in variants:
            for pos, text, conf in self._plain(buf, False):
                if name == "reversed":
                    pos = len(data) - pos - len(text)
                found.append(Finding(text.decode(), name, conf, pos, _clean(text)))
        if b"%" in data:
            decoded = unquote_to_bytes(data)
            if decoded != data:
                self._scan(decoded, "url", 0, found, generic=False, depth=0, base=None)
        self._scan_encoded(data, "", found, 0)
        return self._dedupe(found)

    def _scan(self, buf: bytes, enc: str, origin: int, found: list, generic: bool, depth: int, base) -> None:
        for pos, text, conf in self._plain(buf, generic):
            ctx = _clean(buf[max(0, pos - 30):pos + len(text) + 30])
            found.append(Finding(text.decode(), enc, conf, origin if enc != "plain" else pos, ctx))

    def _scan_encoded(self, data: bytes, chain: str, found: list, depth: int, origin_base: int = 0) -> None:
        if depth >= 3:
            return
        cands: list[tuple[str, int, bytes]] = []
        for m in islice(_B64.finditer(data), 300):
            raw = m.group().rstrip(b"=").replace(b"-", b"+").replace(b"_", b"/")
            try:
                cands.append(("base64", m.start(), base64.b64decode(raw + b"=" * (-len(raw) % 4))))
            except (binascii.Error, ValueError):
                pass
        for m in islice(_HEX.finditer(data), 300):
            try:
                cands.append(("hex", m.start(), binascii.unhexlify(m.group())))
            except (binascii.Error, ValueError):
                pass
        for m in islice(_B32.finditer(data), 300):
            try:
                cands.append(("base32", m.start(), base64.b32decode(m.group() + b"=" * (-len(m.group()) % 8))))
            except (binascii.Error, ValueError):
                pass
        for enc, pos, decoded in cands:
            if len(decoded) < 6:
                continue
            name = f"{chain}+{enc}" if chain else enc
            origin = origin_base if chain else pos
            ratio = _printable_ratio(decoded)
            for p, text, conf in self._plain(decoded, ratio >= 0.9):
                ctx = _clean(decoded[max(0, p - 30):p + len(text) + 30])
                found.append(Finding(text.decode(), name, conf, origin, ctx))
            if ratio >= 0.9 and len(decoded) <= 200_000:
                self._scan_encoded(decoded, name, found, depth + 1, origin)

    @staticmethod
    def _dedupe(found: list[Finding]) -> list[Finding]:
        seen, out = set(), []
        for f in found:
            key = (f.flag, f.encoding)
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out
