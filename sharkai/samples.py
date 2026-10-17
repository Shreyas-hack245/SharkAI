"""Synthetic packet/capture builder. Used by the test-suite and to generate the demo CTF capture
(`python scripts/make_sample.py`). Checksums are left zero; SharkAI does not validate them."""
from __future__ import annotations

import base64
import gzip
import ipaddress
import struct

CLIENT_MAC, SERVER_MAC = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"


def eth(payload: bytes, etype: int = 0x0800, src: bytes = CLIENT_MAC, dst: bytes = SERVER_MAC) -> bytes:
    return dst + src + struct.pack(">H", etype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 1, ttl: int = 64) -> bytes:
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0, ttl, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return hdr + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"", win: int = 64240) -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, win, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo(payload: bytes, reply: bool = False, ident: int = 1, seq: int = 1) -> bytes:
    return struct.pack(">BBHHH", 0 if reply else 8, 0, 0, ident, seq) + payload


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\x00"


def dns_query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack(">HH", qtype, 1)


def dns_response(name: str, answer_ip: str | None, txid: int = 0x1234, qtype: int = 1, txt: str | None = None) -> bytes:
    q = dns_name(name) + struct.pack(">HH", qtype, 1)
    if txt is not None:
        rdata = bytes([len(txt)]) + txt.encode()
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(rdata)) + rdata
        return struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0) + q + ans
    if answer_ip is None:
        return struct.pack(">HHHHHH", txid, 0x8183, 1, 0, 0, 0) + q
    rdata = ipaddress.IPv4Address(answer_ip).packed
    ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + rdata
    return struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0) + q + ans


class CaptureBuilder:
    """Accumulates (timestamp, frame) pairs and serialises them as pcap or pcapng."""

    def __init__(self, t0: float = 1_700_000_000.0) -> None:
        self.t = t0
        self.frames: list[tuple[float, bytes]] = []
        self._ident = 1

    def tick(self, dt: float = 0.01) -> float:
        self.t += dt
        return self.t

    def add(self, frame: bytes, ts: float | None = None) -> None:
        self.frames.append((self.tick() if ts is None else ts, frame))

    def ip(self, src: str, dst: str, proto: int, l4: bytes, ts: float | None = None) -> None:
        self._ident += 1
        a_to_b = src < dst
        self.add(eth(ipv4(src, dst, proto, l4, self._ident), src=CLIENT_MAC if a_to_b else SERVER_MAC,
                     dst=SERVER_MAC if a_to_b else CLIENT_MAC), ts)

    def udp_pkt(self, src, dst, sport, dport, payload, ts=None) -> None:
        self.ip(src, dst, 17, udp(sport, dport, payload), ts)

    def tcp_session(self, client: str, cport: int, server: str, sport: int, script: list[tuple[str, bytes]],
                    mss: int = 1400, isn_c: int = 1000, isn_s: int = 5000, close: bool = True,
                    shuffle: bool = False, duplicate_first: bool = False) -> None:
        """script: [("c"|"s", data)...]. Emits handshake, MSS-sized segments with ACKs, and FIN close."""
        c_seq, s_seq = isn_c, isn_s
        self.ip(client, server, 6, tcp(cport, sport, c_seq, 0, 0x02))
        self.ip(server, client, 6, tcp(sport, cport, s_seq, c_seq + 1, 0x12))
        c_seq += 1
        s_seq += 1
        self.ip(client, server, 6, tcp(cport, sport, c_seq, s_seq, 0x10))
        for who, data in script:
            segs = [data[i:i + mss] for i in range(0, len(data), mss)] or [b""]
            frames = []
            for seg in segs:
                if who == "c":
                    frames.append((client, server, tcp(cport, sport, c_seq, s_seq, 0x18, seg)))
                    c_seq += len(seg)
                else:
                    frames.append((server, client, tcp(sport, cport, s_seq, c_seq, 0x18, seg)))
                    s_seq += len(seg)
            if shuffle and len(frames) > 1:
                frames[0], frames[1] = frames[1], frames[0]
            if duplicate_first and frames:
                frames.insert(1, frames[0])
            for src, dst, seg in frames:
                self.ip(src, dst, 6, seg)
            ack = (server, client, tcp(sport, cport, s_seq, c_seq, 0x10)) if who == "c" else \
                  (client, server, tcp(cport, sport, c_seq, s_seq, 0x10))
            self.ip(ack[0], ack[1], 6, ack[2])
        if close:
            self.ip(client, server, 6, tcp(cport, sport, c_seq, s_seq, 0x11))
            self.ip(server, client, 6, tcp(sport, cport, s_seq, c_seq + 1, 0x11))
            self.ip(client, server, 6, tcp(cport, sport, c_seq + 1, s_seq + 1, 0x10))

    # -- serialisation ---------------------------------------------------------------------
    def to_pcap(self, big_endian: bool = False, nano: bool = False, linktype: int = 1) -> bytes:
        e = ">" if big_endian else "<"
        magic = 0xA1B23C4D if nano else 0xA1B2C3D4
        out = bytearray(struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype))
        for ts, frame in self.frames:
            sec = int(ts)
            frac = int(round((ts - sec) * (1e9 if nano else 1e6)))
            out += struct.pack(e + "IIII", sec, frac, len(frame), len(frame)) + frame
        return bytes(out)

    def to_pcapng(self, big_endian: bool = False, tsresol: int = 6) -> bytes:
        e = ">" if big_endian else "<"

        def block(btype: int, body: bytes) -> bytes:
            body += b"\x00" * (-len(body) % 4)
            return struct.pack(e + "II", btype, len(body) + 12) + body + struct.pack(e + "I", len(body) + 12)

        shb = block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1))
        opt = struct.pack(e + "HH", 9, 1) + bytes([tsresol]) + b"\x00\x00\x00" + struct.pack(e + "HH", 0, 0)
        idb = block(1, struct.pack(e + "HHI", 1, 0, 65535) + opt)
        out = bytearray(shb + idb)
        for ts, frame in self.frames:
            ticks = int(round(ts * 10 ** tsresol))
            out += block(6, struct.pack(e + "IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)) + frame)
        return bytes(out)


# --------------------------------------------------------------------------------------------
# Demo CTF capture
# --------------------------------------------------------------------------------------------
DEMO_FLAGS = {
    "split": "flag{split_across_segments}",
    "b64": "flag{base64_in_http_body}",
    "dns": "flag{dns_exfil_chunks}",
    "icmp": "picoCTF{icmp_payload_secret}",
    "ftp": "HTB{hex_in_ftp_file}",
}


def sample_ctf_capture() -> bytes:
    cap = CaptureBuilder()
    user, web, ftp, dns_srv, attacker, c2 = "10.0.0.5", "10.0.0.80", "10.0.0.21", "10.0.0.2", "10.0.0.66", "203.0.113.9"

    # DNS lookups + a failed one
    cap.udp_pkt(user, dns_srv, 40001, 53, dns_query("ctf-chall.local", 1, 0x0101))
    cap.udp_pkt(dns_srv, user, 53, 40001, dns_response("ctf-chall.local", web, 0x0101))
    cap.udp_pkt(user, dns_srv, 40002, 53, dns_query("update.bad-cdn.example", 1, 0x0102))
    cap.udp_pkt(dns_srv, user, 53, 40002, dns_response("update.bad-cdn.example", None, 0x0102))

    # HTTP: HTML page, then a gzip'd/base64 secret, then a PNG download, then a login form POST
    png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 13 + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    html = b"<html><body><h1>Welcome</h1><!-- try /secret.txt --></body></html>"
    secret = base64.b64encode(DEMO_FLAGS["b64"].encode()) + b"\n"
    gz = gzip.compress(b"nothing to see here\n")
    form = b"username=admin&password=s3cr3t-pass"

    def resp(body: bytes, ctype: str, extra: str = "") -> bytes:
        return (f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n{extra}\r\n").encode() + body

    cap.tcp_session(user, 50001, web, 80, [
        ("c", b"GET / HTTP/1.1\r\nHost: ctf-chall.local\r\nUser-Agent: curl/8.4.0\r\n\r\n"), ("s", resp(html, "text/html")),
        ("c", b"GET /secret.txt HTTP/1.1\r\nHost: ctf-chall.local\r\nUser-Agent: curl/8.4.0\r\n\r\n"), ("s", resp(secret, "text/plain")),
        ("c", b"GET /logo.png HTTP/1.1\r\nHost: ctf-chall.local\r\n\r\n"),
        ("s", resp(png, "image/png", 'Content-Disposition: attachment; filename="logo.png"\r\n')),
        ("c", b"GET /notes.gz HTTP/1.1\r\nHost: ctf-chall.local\r\n\r\n"),
        ("s", resp(gz, "application/octet-stream", "Content-Encoding: gzip\r\n")),
        ("c", b"POST /login HTTP/1.1\r\nHost: ctf-chall.local\r\nContent-Type: application/x-www-form-urlencoded\r\n"
              + f"Content-Length: {len(form)}\r\n\r\n".encode() + form),
        ("s", resp(b"welcome admin", "text/plain")),
    ])

    # Plain-text service where the flag is split across two TCP segments (and one arrives out of order)
    half = DEMO_FLAGS["split"]
    cap.tcp_session(attacker, 50002, user, 9001, [("s", b"banner: " + half[:7].encode()), ("s", half[7:].encode() + b"\n"),
                                                  ("c", b"thanks\n")], mss=9, shuffle=True)

    # FTP control + passive data channel
    ftp_data = ("# notes\nkey=" + DEMO_FLAGS["ftp"].encode().hex() + "\n").encode()
    cap.tcp_session(user, 50003, ftp, 21, [
        ("s", b"220 FTP ready\r\n"), ("c", b"USER admin\r\n"), ("s", b"331 Password required\r\n"),
        ("c", b"PASS hunter2\r\n"), ("s", b"230 Logged in\r\n"), ("c", b"PASV\r\n"),
        ("s", b"227 Entering Passive Mode (10,0,0,21,200,10)\r\n"), ("c", b"RETR notes.txt\r\n"),
        ("s", b"150 Opening data connection\r\n"), ("s", b"226 Transfer complete\r\n")])
    cap.tcp_session(user, 50004, ftp, 51210, [("s", ftp_data)])

    # DNS exfiltration: hex chunks of a flag in subdomains
    payload = DEMO_FLAGS["dns"].encode().hex()
    for i in range(0, len(payload), 12):
        n = 0x0200 + i
        name = f"{payload[i:i + 12]}.exfil.bad-cdn.example"
        cap.udp_pkt(user, dns_srv, 41000 + i, 53, dns_query(name, 16, n))
        cap.udp_pkt(dns_srv, user, 53, 41000 + i, dns_response(name, None, n, 16, txt="ok"))

    # ICMP tunnel carrying a flag
    cap.ip(user, c2, 1, icmp_echo(b"abcdefgh" + DEMO_FLAGS["icmp"].encode(), ident=7, seq=1))
    cap.ip(c2, user, 1, icmp_echo(b"abcdefgh" + DEMO_FLAGS["icmp"].encode(), reply=True, ident=7, seq=1))

    # Port scan from attacker
    for port in range(1, 26):
        cap.ip(attacker, web, 6, tcp(44444, port, 100 + port, 0, 0x02))
    return cap.to_pcap()
