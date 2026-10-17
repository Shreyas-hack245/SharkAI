"""Pure-Python readers for libpcap (.pcap/.cap) and pcapng files. Handles both byte orders,
micro/nanosecond timestamps, and per-interface pcapng time resolution."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MAX_RECORD = 0x400000  # sanity bound for one captured frame


class CaptureFormatError(ValueError):
    """Raised when the file is not a readable pcap/pcapng capture."""


@dataclass(slots=True)
class RawPacket:
    number: int
    ts: float
    caplen: int
    origlen: int
    linktype: int
    offset: int  # byte offset of the frame inside the capture file


def sniff_format(head: bytes) -> str | None:
    head = bytes(head[:4])
    if head in PCAP_MAGICS:
        return "pcap"
    if head == PCAPNG_MAGIC:
        return "pcapng"
    return None


class CaptureReader:
    def __init__(self, data) -> None:
        self.data = data
        self.format = sniff_format(data[:4])
        if self.format is None:
            raise CaptureFormatError("not a pcap or pcapng capture (unrecognised magic bytes)")
        self.warnings: list[str] = []
        self.linktypes: set[int] = set()

    def packets(self) -> Iterator[tuple[RawPacket, bytes]]:
        yield from (self._pcap() if self.format == "pcap" else self._pcapng())

    # -- libpcap ---------------------------------------------------------------------------
    def _pcap(self):
        d, n = self.data, len(self.data)
        if n < 24:
            raise CaptureFormatError("truncated pcap global header")
        endian, res = PCAP_MAGICS[bytes(d[:4])]
        network = struct.unpack_from(endian + "I", d, 20)[0] & 0x0FFFFFFF
        self.linktypes.add(network)
        pos, num = 24, 0
        while pos + 16 <= n:
            sec, frac, caplen, origlen = struct.unpack_from(endian + "IIII", d, pos)
            if caplen > MAX_RECORD:
                self.warnings.append(f"corrupt record after packet {num}; stopped reading")
                return
            start = pos + 16
            if start + caplen > n:
                self.warnings.append(f"capture truncated inside packet {num + 1}")
                return
            num += 1
            yield RawPacket(num, sec + frac * res, caplen, origlen, network, start), bytes(d[start:start + caplen])
            pos = start + caplen
        if pos != n:
            self.warnings.append("trailing bytes after last packet record ignored")

    # -- pcapng ----------------------------------------------------------------------------
    def _pcapng(self):
        d, n = self.data, len(self.data)
        pos, num, endian = 0, 0, "<"
        ifaces: list[tuple[int, float, int]] = []  # (linktype, seconds per tick, snaplen)
        while pos + 12 <= n:
            if bytes(d[pos:pos + 4]) == PCAPNG_MAGIC:
                bom = bytes(d[pos + 8:pos + 12])
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    self.warnings.append("bad pcapng byte-order magic; stopped reading")
                    return
                ifaces = []
            btype, blen = struct.unpack_from(endian + "II", d, pos)
            if blen < 12 or blen % 4 or pos + blen > n:
                self.warnings.append("truncated or corrupt pcapng block; stopped reading")
                return
            body, end = pos + 8, pos + blen - 4
            if btype == 1 and body + 8 <= end:  # Interface Description Block
                linktype, _, snaplen = struct.unpack_from(endian + "HHI", d, body)
                res, off = 1e-6, body + 8
                while off + 4 <= end:
                    code, length = struct.unpack_from(endian + "HH", d, off)
                    if code == 0:
                        break
                    if code == 9 and length >= 1:
                        v = d[off + 4]
                        res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                    off += 4 + ((length + 3) & ~3)
                ifaces.append((linktype, res, snaplen))
                self.linktypes.add(linktype)
            elif btype == 6 and body + 20 <= end:  # Enhanced Packet Block
                iid, hi, lo, caplen, origlen = struct.unpack_from(endian + "IIIII", d, body)
                start = body + 20
                if start + caplen > end:
                    self.warnings.append(f"bad packet length in block {num + 1}; skipped")
                else:
                    lt, res, _ = ifaces[iid] if iid < len(ifaces) else (1, 1e-6, 0)
                    num += 1
                    yield RawPacket(num, ((hi << 32) | lo) * res, caplen, origlen, lt, start), bytes(d[start:start + caplen])
            elif btype == 3 and body + 4 <= end:  # Simple Packet Block
                origlen = struct.unpack_from(endian + "I", d, body)[0]
                lt = ifaces[0][0] if ifaces else 1
                caplen = min(origlen, end - body - 4)
                num += 1
                yield RawPacket(num, 0.0, caplen, origlen, lt, body + 4), bytes(d[body + 4:body + 4 + caplen])
            pos += blen
