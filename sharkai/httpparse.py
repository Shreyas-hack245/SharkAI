"""HTTP/1.x message extraction from reassembled TCP streams."""
from __future__ import annotations

import re
import zlib
from dataclasses import dataclass, field

METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE")
MAX_DECODED = 64 * 1024 * 1024


@dataclass
class Message:
    start: int
    end: int
    headers: list[tuple[str, str]]
    body: bytes
    method: str = ""
    uri: str = ""
    version: str = ""
    status: int = 0
    reason: str = ""
    decoded_body: bytes | None = None
    note: str = ""

    def header(self, name: str) -> str:
        n = name.lower()
        return next((v for k, v in self.headers if k.lower() == n), "")


def looks_like_request(buf: bytes) -> bool:
    return buf.split(b" ", 1)[0] in METHODS and b" HTTP/1." in buf[:4096].split(b"\r\n", 1)[0]


def looks_like_response(buf: bytes) -> bool:
    return buf.startswith(b"HTTP/1.")


def _split_head(buf: bytes, pos: int) -> tuple[bytes, int] | None:
    i = buf.find(b"\r\n\r\n", pos)
    if i != -1:
        return buf[pos:i], i + 4
    i = buf.find(b"\n\n", pos)
    return (buf[pos:i], i + 2) if i != -1 else None


def _headers(lines: list[str]) -> list[tuple[str, str]]:
    out = []
    for line in lines:
        if ":" in line and not line[0].isspace():
            k, _, v = line.partition(":")
            out.append((k.strip(), v.strip()))
    return out


def _dechunk(buf: bytes, pos: int) -> tuple[bytes, int, bool]:
    out = bytearray()
    while True:
        eol = buf.find(b"\r\n", pos)
        if eol == -1:
            return bytes(out), len(buf), False
        try:
            size = int(buf[pos:eol].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return bytes(out), len(buf), False
        pos = eol + 2
        if size == 0:
            end = buf.find(b"\r\n\r\n", pos - 2)
            return bytes(out), (end + 4 if end != -1 else len(buf)), True
        out += buf[pos:pos + size]
        pos += size + 2
        if pos > len(buf):
            return bytes(out), len(buf), False


def decode_body(body: bytes, encoding: str) -> tuple[bytes, str]:
    enc = encoding.lower().strip()
    if not body or enc in ("", "identity"):
        return body, ""
    try:
        if enc in ("gzip", "x-gzip"):
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif enc == "deflate":
            d = zlib.decompressobj()
        else:
            return body, f"unsupported Content-Encoding: {enc}"
        out = d.decompress(body, MAX_DECODED)
        return out, ""
    except zlib.error:
        if enc == "deflate":
            try:
                return zlib.decompressobj(-zlib.MAX_WBITS).decompress(body, MAX_DECODED), ""
            except zlib.error:
                pass
        return body, "body could not be decompressed"


def _parse(buf: bytes, request: bool, req_methods: list[str] | None = None) -> list[Message]:
    msgs, pos, idx = [], 0, 0
    while pos < len(buf):
        head = _split_head(buf, pos)
        if head is None:
            break
        raw, body_start = head
        lines = raw.decode("latin-1").replace("\r\n", "\n").split("\n")
        first = lines[0].split(" ", 2)
        if request:
            if len(first) < 3 or first[0].encode() not in METHODS:
                break
            m = Message(pos, 0, _headers(lines[1:]), b"", method=first[0], uri=first[1], version=first[2])
        else:
            if not first[0].startswith("HTTP/") or len(first) < 2 or not first[1].isdigit():
                break
            m = Message(pos, 0, _headers(lines[1:]), b"", version=first[0], status=int(first[1]),
                        reason=first[2] if len(first) > 2 else "")
        te, cl = m.header("Transfer-Encoding").lower(), m.header("Content-Length")
        method = (req_methods[idx] if req_methods and idx < len(req_methods) else "")
        if "chunked" in te:
            body, end, complete = _dechunk(buf, body_start)
            if not complete:
                m.note = "incomplete chunked body"
        elif cl.isdigit():
            n = int(cl)
            body, end = buf[body_start:body_start + n], min(body_start + n, len(buf))
            if len(body) < n:
                m.note = f"body truncated ({len(body)} of {n} bytes captured)"
        elif request or method == "HEAD" or m.status in (204, 304) or 100 <= m.status < 200:
            body, end = b"", body_start
        else:
            body, end = buf[body_start:], len(buf)
        m.body, m.end = body, end
        enc = m.header("Content-Encoding")
        if enc and body:
            m.decoded_body, why = decode_body(body, enc)
            m.note = m.note or why
        msgs.append(m)
        idx += 1
        if m.status == 101 or end <= pos:
            break
        pos = end
    return msgs


def parse_requests(buf: bytes) -> list[Message]:
    return _parse(buf, True)


def parse_responses(buf: bytes, req_methods: list[str] | None = None) -> list[Message]:
    return _parse(buf, False, req_methods)


def parse_multipart(body: bytes, content_type: str) -> list[dict]:
    m = re.search(r'boundary="?([^";]+)"?', content_type, re.I)
    if not m:
        return []
    delim = b"--" + m.group(1).encode("latin-1")
    parts = []
    for chunk in body.split(delim)[1:]:
        if chunk.startswith(b"--"):
            break
        head = _split_head(chunk.lstrip(b"\r\n"), 0)
        if not head:
            continue
        raw, off = head
        hdrs = dict((k.lower(), v) for k, v in _headers(raw.decode("latin-1").replace("\r\n", "\n").split("\n")))
        data = chunk.lstrip(b"\r\n")[off:]
        data = data[:-2] if data.endswith(b"\r\n") else data
        disp = hdrs.get("content-disposition", "")
        name = re.search(r'\bname="([^"]*)"', disp)
        fn = re.search(r'filename="([^"]*)"', disp)
        parts.append({"name": name.group(1) if name else "", "filename": fn.group(1) if fn else "",
                      "content_type": hdrs.get("content-type", ""), "data": data})
    return parts
