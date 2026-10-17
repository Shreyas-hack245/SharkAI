"""TCP stream tracking and reassembly (out-of-order, retransmission and overlap aware)."""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field

from .decode import Decoded


@dataclass(slots=True)
class Segment:
    pkt: int
    ts: float
    direction: int   # 0 client->server, 1 server->client
    start: int       # offset inside this direction's reassembled stream
    length: int


@dataclass
class Stream:
    id: int
    client: tuple[str, int]
    server: tuple[str, int]
    start_ts: float
    end_ts: float = 0.0
    packets: int = 0
    packet_numbers: list[int] = field(default_factory=list)
    syn_seq: dict = field(default_factory=dict)
    fin: set = field(default_factory=set)
    rst: bool = False
    raw: list = field(default_factory=lambda: [[], []])      # (seq, pkt, ts, data)
    data: list = field(default_factory=lambda: [b"", b""])
    segments: list = field(default_factory=lambda: [[], []])
    starts: list = field(default_factory=lambda: [[], []])
    gaps: int = 0
    retransmits: int = 0
    truncated: bool = False
    protocol: str = "TCP"

    @property
    def closed(self) -> bool:
        return self.rst or len(self.fin) == 2

    @property
    def state(self) -> str:
        return "reset" if self.rst else "closed" if len(self.fin) == 2 else "open"

    def locate(self, direction: int, offset: int) -> tuple[int, float]:
        """Packet number and timestamp that carried byte `offset` of one direction."""
        segs = self.segments[direction]
        if not segs:
            return 0, self.start_ts
        seg = segs[max(0, bisect_right(self.starts[direction], offset) - 1)]
        return seg.pkt, seg.ts

    def messages(self) -> list[dict]:
        """Conversation view. Consecutive same-direction bursts (in arrival order) form one message; inside a
        burst, segments are put in sequence order so reordered packets still read correctly. Each message
        carries `ranges` ([start, length] pairs into that direction's reassembled bytes)."""
        segs = sorted((s for d in (0, 1) for s in self.segments[d]), key=lambda s: (s.pkt, s.direction))
        bursts: list[list[Segment]] = []
        for s in segs:
            if bursts and bursts[-1][0].direction == s.direction:
                bursts[-1].append(s)
            else:
                bursts.append([s])
        out: list[dict] = []
        for burst in bursts:
            ranges: list[list[int]] = []
            for s in sorted(burst, key=lambda s: s.start):
                if ranges and ranges[-1][0] + ranges[-1][1] == s.start:
                    ranges[-1][1] += s.length
                else:
                    ranges.append([s.start, s.length])
            first = burst[0]
            out.append({"dir": first.direction, "pkt": first.pkt, "ts": first.ts, "start": ranges[0][0],
                        "length": sum(r[1] for r in ranges), "ranges": ranges})
        return out


def message_bytes(data: bytes, msg: dict) -> bytes:
    return b"".join(data[st:st + ln] for st, ln in msg["ranges"])


class StreamTable:
    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self.streams: list[Stream] = []
        self._open: dict[tuple, Stream] = {}

    @staticmethod
    def _key(d: Decoded) -> tuple:
        a, b = (d.src, d.sport), (d.dst, d.dport)
        return (a, b) if a <= b else (b, a)

    def add(self, number: int, ts: float, d: Decoded) -> int:
        key = self._key(d)
        syn, ack = bool(d.flags & 0x02), bool(d.flags & 0x10)
        s = self._open.get(key)
        sender = (d.src, d.sport)
        if s is not None and syn and not ack:
            direction = 0 if sender == s.client else 1
            prior = s.syn_seq.get(direction)
            if s.closed or (prior is not None and prior != d.seq):
                s = None
        if s is None:
            if syn and not ack:
                client, server = (d.src, d.sport), (d.dst, d.dport)
            elif syn and ack:
                client, server = (d.dst, d.dport), (d.src, d.sport)
            elif d.sport < 1024 <= d.dport:
                client, server = (d.dst, d.dport), (d.src, d.sport)
            else:
                client, server = (d.src, d.sport), (d.dst, d.dport)
            s = Stream(len(self.streams), client, server, ts)
            self.streams.append(s)
            self._open[key] = s
        direction = 0 if sender == s.client else 1
        s.packets += 1
        s.end_ts = ts
        if len(s.packet_numbers) < 5000:
            s.packet_numbers.append(number)
        if syn:
            s.syn_seq.setdefault(direction, d.seq)
        if d.flags & 0x01:
            s.fin.add(direction)
        if d.flags & 0x04:
            s.rst = True
        if d.payload:
            s.raw[direction].append((d.seq, number, ts, d.payload))
        return s.id

    def finalize(self) -> list[Stream]:
        for s in self.streams:
            for direction in (0, 1):
                self._assemble(s, direction)
        return self.streams

    def _assemble(self, s: Stream, direction: int) -> None:
        raw = s.raw[direction]
        if not raw:
            return
        syn = s.syn_seq.get(direction)
        base = (syn + 1) & 0xFFFFFFFF if syn is not None else raw[0][0]
        items = []
        for seq, pkt, ts, data in raw:
            rel = ((seq - base + 0x80000000) & 0xFFFFFFFF) - 0x80000000
            items.append((rel, pkt, ts, data))
        if syn is None:
            shift = min(i[0] for i in items)
            items = [(r - shift, p, t, d) for r, p, t, d in items]
        items.sort(key=lambda i: (i[0], i[1]))
        buf, expected, total = bytearray(), 0, 0
        for rel, pkt, ts, data in items:
            end = rel + len(data)
            if end <= expected:
                s.retransmits += 1
                continue
            if rel > expected:
                s.gaps += 1
                expected = rel
            chunk = data[expected - rel:]
            if total + len(chunk) > self.max_bytes:
                chunk = chunk[: max(0, self.max_bytes - total)]
                s.truncated = True
            if chunk:
                s.segments[direction].append(Segment(pkt, ts, direction, len(buf), len(chunk)))
                s.starts[direction].append(len(buf))
                buf += chunk
                total += len(chunk)
            expected = end
            if s.truncated:
                break
        s.data[direction] = bytes(buf)
        s.raw[direction] = []  # release memory
