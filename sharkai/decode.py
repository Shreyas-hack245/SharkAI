"""Frame decoding: Ethernet/VLAN/SLL/raw -> IPv4/IPv6/ARP -> TCP/UDP/ICMP, plus light app-layer labelling."""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from . import dnsparse

TCP_FLAGS = ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"))
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
              123: "NTP", 137: "NBNS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "TLS", 445: "SMB",
              465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S", 1900: "SSDP", 3306: "MySQL", 3389: "RDP",
              5353: "mDNS", 5432: "PostgreSQL", 8080: "HTTP", 8000: "HTTP", 8443: "TLS"}
ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 5: "Redirect", 8: "Echo request", 11: "Time exceeded"}


@dataclass(slots=True)
class Decoded:
    l3: str = ""
    l4: str = ""
    eth_src: str = ""
    eth_dst: str = ""
    vlan: int | None = None
    src: str = ""
    dst: str = ""
    ttl: int = 0
    sport: int = 0
    dport: int = 0
    flags: int = 0
    seq: int = 0
    ack: int = 0
    win: int = 0
    icmp_type: int = -1
    icmp_code: int = 0
    payload: bytes = b""
    fragment: bool = False
    app: str = ""
    info: str = ""
    dns: dict | None = None
    http: dict | None = None
    sni: str = ""
    ip_header_len: int = 0
    l4_header_len: int = 0
    malformed: bool = False

    @property
    def flag_names(self) -> str:
        return ",".join(name for bit, name in TCP_FLAGS if self.flags & bit)


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def printable(data: bytes, limit: int = 120) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])


def parse_sni(payload: bytes) -> str:
    """Extract the SNI hostname from a TLS ClientHello, or ''."""
    try:
        if len(payload) < 48 or payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        pos = 43
        pos += 1 + payload[pos]                                   # session id
        pos += 2 + struct.unpack_from(">H", payload, pos)[0]      # cipher suites
        pos += 1 + payload[pos]                                   # compression
        end = pos + 2 + struct.unpack_from(">H", payload, pos)[0]
        pos += 2
        while pos + 4 <= min(end, len(payload)):
            etype, elen = struct.unpack_from(">HH", payload, pos)
            if etype == 0 and elen >= 5:
                nlen = struct.unpack_from(">H", payload, pos + 7)[0]
                return payload[pos + 9:pos + 9 + nlen].decode("ascii", "replace")
            pos += 4 + elen
    except (struct.error, IndexError):
        pass
    return ""


def http_summary(payload: bytes) -> dict | None:
    head = payload[:2048]
    if head.startswith(HTTP_METHODS):
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split(" ")
        host = ""
        for hl in head.split(b"\r\n")[1:]:
            if hl[:5].lower() == b"host:":
                host = hl[5:].strip().decode("latin-1")
                break
        return {"method": parts[0], "uri": parts[1] if len(parts) > 1 else "", "host": host}
    if head.startswith(b"HTTP/1."):
        parts = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            return {"status": int(parts[1]), "reason": parts[2] if len(parts) > 2 else ""}
    return None


def label_app(l4: str, sport: int, dport: int, payload: bytes) -> str:
    if payload:
        if payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/1."):
            return "HTTP"
        if len(payload) > 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3 and payload[2] <= 4:
            return "TLS"
        if payload.startswith(b"SSH-"):
            return "SSH"
    for port in (dport, sport):
        if l4 == "UDP" and port in (53, 5353) or l4 == "TCP" and port == 53:
            return "DNS"
        if port in PORT_NAMES and port not in (53, 5353):
            return PORT_NAMES[port]
    return l4


def _tcp_info(d: Decoded) -> str:
    return f"{d.sport} → {d.dport} [{d.flag_names}] Seq={d.seq} Ack={d.ack} Win={d.win} Len={len(d.payload)}"


def _decode_l4(d: Decoded, proto: int, seg: bytes) -> None:
    if proto == 6 and len(seg) >= 20:
        d.l4 = "TCP"
        d.sport, d.dport, d.seq, d.ack, off_flags, d.win = struct.unpack_from(">HHIIHH", seg, 0)
        off = (off_flags >> 12) * 4
        d.flags, d.l4_header_len = off_flags & 0xFF, off
        d.payload = seg[off:] if 20 <= off <= len(seg) else b""
    elif proto == 17 and len(seg) >= 8:
        d.l4 = "UDP"
        d.sport, d.dport, ulen = struct.unpack_from(">HHH", seg, 0)
        d.l4_header_len = 8
        d.payload = seg[8:ulen] if 8 <= ulen <= len(seg) else seg[8:]
    elif proto in (1, 58) and len(seg) >= 4:
        d.l4 = "ICMP" if proto == 1 else "ICMPv6"
        d.icmp_type, d.icmp_code = seg[0], seg[1]
        d.l4_header_len = 8 if proto == 1 else 4
        d.payload = seg[8:] if proto == 1 else seg[4:]
    else:
        d.l4 = f"IP-{proto}"
        d.payload = seg
        d.info = f"IP protocol {proto}"
        d.app = d.l4
        return

    if d.l4 == "TCP":
        d.info = _tcp_info(d)
    elif d.l4 == "UDP":
        d.info = f"{d.sport} → {d.dport} Len={len(d.payload)}"
    else:
        name = ICMP_TYPES.get(d.icmp_type, f"type {d.icmp_type}") if d.l4 == "ICMP" else f"type {d.icmp_type}"
        d.info = f"{name} (code {d.icmp_code}), payload {len(d.payload)} bytes"

    d.app = label_app(d.l4, d.sport, d.dport, d.payload) if d.l4 in ("TCP", "UDP") else d.l4
    if d.l4 == "UDP" and d.app == "DNS" and d.payload:
        msg = dnsparse.parse(d.payload)
        if msg:
            d.dns = msg
            q = msg["questions"][0] if msg["questions"] else {"name": "?", "type": "?"}
            ans = ", ".join(a["data"] for a in msg["answers"][:3])
            d.info = (f"Standard query response 0x{msg['id']:04x} {msg['rcode']} {q['type']} {q['name']} {ans}".strip()
                      if msg["response"] else f"Standard query 0x{msg['id']:04x} {q['type']} {q['name']}")
        else:
            d.app = "UDP"
    elif d.l4 == "TCP" and d.payload:
        if d.app == "HTTP":
            d.http = http_summary(d.payload)
            if d.http:
                d.info = (f"{d.http['method']} {d.http['uri']}" if "method" in d.http
                          else f"HTTP {d.http['status']} {d.http.get('reason', '')}")
        elif d.app == "TLS":
            d.sni = parse_sni(d.payload)
            if d.sni:
                d.info = f"Client Hello (SNI={d.sni})"
        elif d.app in ("FTP", "SMTP", "POP3", "IMAP", "Telnet"):
            d.info += " | " + printable(d.payload, 60).strip()


def _decode_ip(d: Decoded, ip: bytes) -> None:
    ver = ip[0] >> 4 if ip else 0
    if ver == 4 and len(ip) >= 20:
        d.l3 = "IPv4"
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack_from(">H", ip, 2)[0]
        frag = struct.unpack_from(">H", ip, 6)[0]
        d.ttl, proto = ip[8], ip[9]
        d.src, d.dst = str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20]))
        d.ip_header_len = ihl
        end = total if ihl <= total <= len(ip) else len(ip)  # total==0 happens with TSO captures
        if frag & 0x1FFF:
            d.fragment, d.l4, d.app = True, "IPv4-frag", "IPv4"
            d.info = f"Fragmented IP protocol (proto={proto}, offset={(frag & 0x1FFF) * 8})"
            d.payload = ip[ihl:end]
            return
        if frag & 0x2000:
            d.fragment = True
        _decode_l4(d, proto, ip[ihl:end])
    elif ver == 6 and len(ip) >= 40:
        d.l3 = "IPv6"
        plen = struct.unpack_from(">H", ip, 4)[0]
        nxt, d.ttl = ip[6], ip[7]
        d.src, d.dst = str(ipaddress.IPv6Address(ip[8:24])), str(ipaddress.IPv6Address(ip[24:40]))
        d.ip_header_len = 40
        end = 40 + plen if plen and 40 + plen <= len(ip) else len(ip)
        pos = 40
        for _ in range(8):  # walk extension headers
            if nxt in (0, 43, 60) and pos + 8 <= end:
                nxt, pos = ip[pos], pos + (ip[pos + 1] + 1) * 8
            elif nxt == 44 and pos + 8 <= end:
                if struct.unpack_from(">H", ip, pos + 2)[0] & 0xFFF8:
                    d.fragment, d.l4, d.app, d.info = True, "IPv6-frag", "IPv6", "Fragmented IPv6 packet"
                    return
                nxt, pos = ip[pos], pos + 8
            else:
                break
        d.ip_header_len = pos
        _decode_l4(d, nxt, ip[pos:end])
    else:
        d.malformed, d.app, d.info = True, "Malformed", "Unrecognised or truncated IP header"


def decode_frame(frame: bytes, linktype: int) -> Decoded:
    d = Decoded()
    try:
        if linktype == 1:  # Ethernet
            if len(frame) < 14:
                raise ValueError
            d.eth_dst, d.eth_src = _mac(frame[0:6]), _mac(frame[6:12])
            etype, pos = struct.unpack_from(">H", frame, 12)[0], 14
            for _ in range(2):
                if etype in (0x8100, 0x88A8) and pos + 4 <= len(frame):
                    d.vlan = struct.unpack_from(">H", frame, pos)[0] & 0x0FFF
                    etype, pos = struct.unpack_from(">H", frame, pos + 2)[0], pos + 4
            body = frame[pos:]
        elif linktype == 113 and len(frame) >= 16:  # Linux cooked v1
            etype, body = struct.unpack_from(">H", frame, 14)[0], frame[16:]
        elif linktype == 276 and len(frame) >= 20:  # Linux cooked v2
            etype, body = struct.unpack_from(">H", frame, 0)[0], frame[20:]
        elif linktype == 0 and len(frame) >= 4:  # BSD loopback
            etype, body = 0x0800 if frame[4] >> 4 == 4 else 0x86DD, frame[4:]
        elif linktype in (101, 12, 228, 229):  # raw IP
            etype, body = 0x0800 if frame and frame[0] >> 4 == 4 else 0x86DD, frame
        else:
            d.app, d.info = "Unsupported", f"Unsupported link type {linktype}"
            return d
        if etype == 0x0806 and len(body) >= 28:
            d.l3 = d.app = d.l4 = "ARP"
            op = struct.unpack_from(">H", body, 6)[0]
            sha, spa, tpa = _mac(body[8:14]), str(ipaddress.IPv4Address(body[14:18])), str(ipaddress.IPv4Address(body[24:28]))
            d.src, d.dst = spa, tpa
            d.info = f"Who has {tpa}? Tell {spa}" if op == 1 else f"{spa} is at {sha}"
        elif etype in (0x0800, 0x86DD):
            _decode_ip(d, body)
        else:
            d.app, d.l4, d.info = "Other", f"eth-0x{etype:04x}", f"EtherType 0x{etype:04x}"
    except (struct.error, ValueError, IndexError):
        d.malformed, d.app, d.info = True, "Malformed", "Malformed packet"
    return d
