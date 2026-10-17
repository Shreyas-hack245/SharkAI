"""The analysis pipeline: capture file -> packets, TCP streams, HTTP, DNS, files, credentials, flags,
IOCs, timeline and graph. Everything is written under the capture's directory as plain JSON/binary."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import mmap
import os
import re
import shutil
import struct
from collections import Counter, defaultdict
from pathlib import Path

from . import dnsparse, httpparse, insights
from .capture_io import CaptureFormatError, CaptureReader
from .config import Settings
from .decode import decode_frame, label_app, printable
from .flags import Finding, FlagScanner
from .streams import Stream, StreamTable, message_bytes

ANALYSIS_VERSION = 1
MAX_FILES = 3000
MAGIC = [(b"\x89PNG\r\n\x1a\n", "PNG image"), (b"\xff\xd8\xff", "JPEG image"), (b"GIF87a", "GIF image"),
         (b"GIF89a", "GIF image"), (b"%PDF-", "PDF document"), (b"PK\x03\x04", "ZIP archive"),
         (b"\x1f\x8b\x08", "gzip data"), (b"\x7fELF", "ELF executable"), (b"Rar!\x1a\x07", "RAR archive"),
         (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"), (b"SQLite format 3\x00", "SQLite database")]
CARVE = [(b"\x89PNG\r\n\x1a\n", "PNG image", b"IEND\xaeB`\x82"), (b"\xff\xd8\xff", "JPEG image", b"\xff\xd9"),
         (b"GIF89a", "GIF image", b"\x00\x3b"), (b"%PDF-", "PDF document", b"%%EOF"),
         (b"PK\x03\x04", "ZIP archive", b"PK\x05\x06"), (b"\x1f\x8b\x08", "gzip data", None),
         (b"\x7fELF", "ELF executable", None)]


def detect_type(data: bytes) -> str:
    head = data[:2048]
    for sig, name in MAGIC:
        if head.startswith(sig):
            return name
    if head.startswith(b"MZ") and b"PE\x00\x00" in head:
        return "Windows executable"
    if head.lstrip()[:5].lower() in (b"<!doc", b"<html"):
        return "HTML document"
    if head and sum(1 for c in head if 32 <= c < 127 or c in (9, 10, 13)) / len(head) > 0.95:
        return "text"
    return "binary data"


def safe_name(name: str, fallback: str) -> str:
    name = re.split(r"[\\/]", name.strip())[-1]
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")[:100]
    return name or fallback


def _dump(path: Path, obj) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, separators=(",", ":")), encoding="utf-8")
    os.replace(tmp, path)


class FlagCollector:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict] = {}

    def add(self, f: Finding, loc: dict) -> None:
        item = self.items.setdefault((f.flag, f.encoding), {
            "flag": f.flag, "encoding": f.encoding, "confidence": f.confidence, "context": f.context, "locations": []})
        sig = (loc.get("source"), loc.get("packet"), loc.get("stream"), loc.get("file_id"), loc.get("direction"))
        if len(item["locations"]) < 10 and all((l.get("source"), l.get("packet"), l.get("stream"), l.get("file_id"),
                                                 l.get("direction")) != sig for l in item["locations"]):
            item["locations"].append(loc)

    def result(self) -> list[dict]:
        out = sorted(self.items.values(), key=lambda i: (i["confidence"] != "high", i["locations"][0]["ts"]))
        for n, it in enumerate(out, 1):
            it["id"] = n
        return out


def _stream_text(s: Stream, m: dict) -> bytes:
    return message_bytes(s.data[m["dir"]], m)


def _tcp_dns(s: Stream) -> list[tuple[int, float, dict]]:
    out = []
    for direction in (0, 1):
        buf, pos = s.data[direction], 0
        while pos + 2 <= len(buf):
            n = struct.unpack_from(">H", buf, pos)[0]
            msg = dnsparse.parse(buf[pos + 2:pos + 2 + n])
            if msg is None or pos + 2 + n > len(buf):
                break
            pkt, ts = s.locate(direction, pos)
            out.append((pkt, ts, msg))
            pos += 2 + n
    return out


def analyze_capture(original: Path, out_dir: Path, settings: Settings, extra_prefixes: tuple[str, ...] = ()) -> dict:
    prefixes = tuple(dict.fromkeys(settings.flag_prefixes + tuple(extra_prefixes)))
    scanner = FlagScanner(prefixes)
    for sub in ("streams", "files"):
        shutil.rmtree(out_dir / sub, ignore_errors=True)
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    packets: list[dict] = []
    table = StreamTable(settings.max_stream_bytes)
    dns_events: list[dict] = []
    sni: list[dict] = []
    icmp_payloads: list[tuple] = []
    collector = FlagCollector()
    truncated, t0 = False, None

    if original.stat().st_size < 24:
        raise CaptureFormatError("file is too small to be a capture")
    with original.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        reader = CaptureReader(mm)
        for raw, frame in reader.packets():
            if raw.number > settings.max_packets:
                truncated = True
                break
            d = decode_frame(frame, raw.linktype)
            t0 = raw.ts if t0 is None else t0
            p = {"n": raw.number, "ts": raw.ts, "rel": round(raw.ts - t0, 6), "length": raw.origlen, "src": d.src,
                 "dst": d.dst, "l4": d.l4, "proto": d.app or d.l4, "info": d.info, "off": raw.offset,
                 "cap": raw.caplen, "lt": raw.linktype}
            if d.sport or d.dport:
                p["sport"], p["dport"] = d.sport, d.dport
            if d.eth_src:
                p["eth_src"], p["eth_dst"] = d.eth_src, d.eth_dst
            if d.l4 == "TCP":
                p["stream"] = table.add(raw.number, raw.ts, d)
                p["flags"] = d.flag_names
            if d.http:
                for k, v in d.http.items():
                    p["http_" + k] = v
            if d.dns:
                q = d.dns["questions"][0] if d.dns["questions"] else {"name": "", "type": ""}
                p["dns_name"], p["dns_type"] = q["name"], q["type"]
                dns_events.append(_dns_event(raw.number, raw.ts, d.src, d.dst, "UDP", d.dns))
            if d.sni:
                sni.append({"domain": d.sni, "packet": raw.number, "ts": raw.ts, "src": d.src, "dst": d.dst})
            if d.l4 == "ICMP" and d.icmp_type in (0, 8):
                icmp_payloads.append((raw.number, raw.ts, d.src, d.dst, d.payload))
            if d.l4 != "TCP" and d.dns is None and len(d.payload) >= 6:   # DNS names are scanned decoded, below
                for f in scanner.scan(d.payload):
                    collector.add(f, {"source": "packet", "packet": raw.number, "ts": raw.ts})
            packets.append(p)
        warnings, fmt, linktypes = list(reader.warnings), reader.format, sorted(reader.linktypes)
    if not packets:
        raise CaptureFormatError("capture contains no packets")
    if truncated:
        warnings.append(f"analysis stopped after {settings.max_packets} packets (limit)")

    streams = table.finalize()
    files: list[dict] = []
    creds: list[dict] = []
    http_records: list[dict] = []
    text_blobs: list[tuple[bytes, int, float]] = []
    claimed: set[int] = set()

    def add_file(name: str, data: bytes, source: str, stream: Stream | None, packet: int, ts: float, **extra) -> int | None:
        if len(files) >= MAX_FILES or not data:
            return None
        fid = len(files) + 1
        (out_dir / "files" / f"{fid}.bin").write_bytes(data)
        files.append({"id": fid, "name": safe_name(name, f"object-{fid}"), "source": source, "size": len(data),
                      "type": detect_type(data), "sha256": hashlib.sha256(data).hexdigest(),
                      "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
                      "stream": stream.id if stream else None, "packet": packet, "ts": ts,
                      "preview": printable(data, 160) if detect_type(data) in ("text", "HTML document") else "", **extra})
        return fid

    def add_cred(kind: str, user: str, secret: str, host: str, stream: Stream | None, packet: int, ts: float) -> None:
        if not any(c["kind"] == kind and c["user"] == user and c["secret"] == secret and c["host"] == host for c in creds):
            creds.append({"id": len(creds) + 1, "kind": kind, "user": user, "secret": secret, "host": host,
                          "stream": stream.id if stream else None, "packet": packet, "ts": ts})

    # ---- FTP control channels, credentials and data transfers ------------------------------
    for s in streams:
        c2s, s2c = s.data
        is_ftp = s.server[1] == 21 or (s2c.startswith(b"220 ") and b"ftp" in s2c[:200].lower())
        if not is_ftp or not s.messages():
            continue
        claimed.add(s.id)
        user, pending, transfers = "", None, []
        for m in s.messages():
            text = _stream_text(s, m).decode("latin-1")
            for line in text.splitlines():
                u = line.upper()
                if m["dir"] == 0:
                    if u.startswith("USER "):
                        user = line[5:].strip()
                    elif u.startswith("PASS "):
                        add_cred("ftp", user, line[5:].strip(), s.server[0], s, m["pkt"], m["ts"])
                    elif u.startswith("PORT "):
                        n = re.findall(r"\d+", line)
                        if len(n) >= 6:
                            pending = (".".join(n[:4]), int(n[4]) * 256 + int(n[5]))
                    elif u.startswith("EPRT "):
                        parts = line.split("|")
                        if len(parts) >= 4 and parts[3].isdigit():
                            pending = (parts[2], int(parts[3]))
                    elif u.split(" ")[0] in ("RETR", "STOR", "APPE", "LIST", "NLST", "MLSD"):
                        cmd, _, fn = line.partition(" ")
                        transfers.append({"ep": pending, "cmd": cmd.upper(), "name": fn.strip(), "pkt": m["pkt"], "ts": m["ts"]})
                        pending = None
                elif line.startswith("227"):
                    n = re.findall(r"\d+", line.split("(", 1)[-1])
                    if len(n) >= 6:
                        pending = (".".join(n[:4]), int(n[4]) * 256 + int(n[5]))
                elif line.startswith("229"):
                    mm_ = re.search(r"\|\|\|(\d+)\|", line)
                    if mm_:
                        pending = (s.server[0], int(mm_.group(1)))
        for tr in transfers:
            if not tr["ep"]:
                continue
            ip, port = tr["ep"]
            cands = [x for x in streams if x.id not in claimed and x.server[1] == port and x.id != s.id]
            data_stream = next((x for x in cands if x.server[0] == ip), cands[0] if cands else None)
            if data_stream is None:
                continue
            claimed.add(data_stream.id)
            blob = max(data_stream.data, key=len)
            name = tr["name"] or "directory-listing.txt"
            direction = "uploaded" if tr["cmd"] in ("STOR", "APPE") else "downloaded" if tr["cmd"] == "RETR" else "listing"
            add_file(name, blob, f"ftp-{direction}", data_stream, data_stream.segments[1 if blob is data_stream.data[1] else 0][0].pkt
                     if blob else 0, data_stream.start_ts, ftp_command=tr["cmd"])

    # ---- other cleartext logins (POP3 / IMAP / generic USER+PASS) ---------------------------
    for s in streams:
        if s.id in claimed or not s.data[0] or len(s.data[0]) > 1_000_000:
            continue
        if s.server[1] in (110, 143) or s.data[1][:4] in (b"+OK ", b"* OK"):
            user = ""
            for line in s.data[0].decode("latin-1").splitlines():
                m = re.match(r"(?:\S+ )?LOGIN (\S+) (\S+)", line, re.I)
                if m:
                    add_cred("imap", m.group(1).strip('"'), m.group(2).strip('"'), s.server[0], s, s.locate(0, 0)[0], s.start_ts)
                elif line.upper().startswith("USER "):
                    user = line[5:].strip()
                elif line.upper().startswith("PASS "):
                    add_cred("pop3", user, line[5:].strip(), s.server[0], s, s.locate(0, 0)[0], s.start_ts)

    # ---- HTTP ---------------------------------------------------------------------------
    for s in streams:
        if s.id in claimed:
            continue
        c2s, s2c = s.data
        reqs = httpparse.parse_requests(c2s) if httpparse.looks_like_request(c2s) else []
        resps = httpparse.parse_responses(s2c, [r.method for r in reqs]) if httpparse.looks_like_response(s2c) else []
        if not reqs and not resps:
            continue
        claimed.add(s.id)
        for i in range(max(len(reqs), len(resps))):
            rq = reqs[i] if i < len(reqs) else None
            rs = resps[i] if i < len(resps) else None
            rq_pkt, rq_ts = s.locate(0, rq.start) if rq else (0, 0.0)
            rs_pkt, rs_ts = s.locate(1, rs.start) if rs else (0, 0.0)
            host = rq.header("Host") if rq else ""
            uri = rq.uri if rq else ""
            url = f"http://{host}{uri}" if host and uri.startswith("/") else uri
            req_body = rq.decoded_body if rq and rq.decoded_body is not None else (rq.body if rq else b"")
            body = rs.decoded_body if rs and rs.decoded_body is not None else (rs.body if rs else b"")
            rec = {"id": len(http_records) + 1, "stream": s.id, "packet": rq_pkt or rs_pkt, "ts": rq_ts or rs_ts,
                   "client": s.client[0], "server": s.server[0], "server_port": s.server[1],
                   "method": rq.method if rq else "", "uri": uri, "host": host, "url": url,
                   "version": (rq.version if rq else rs.version if rs else ""),
                   "status": rs.status if rs else 0, "reason": rs.reason if rs else "",
                   "content_type": rs.header("Content-Type") if rs else "",
                   "content_encoding": rs.header("Content-Encoding") if rs else "",
                   "user_agent": rq.header("User-Agent") if rq else "", "location": rs.header("Location") if rs else "",
                   "req_headers": rq.headers if rq else [], "resp_headers": rs.headers if rs else [],
                   "req_size": len(req_body), "resp_size": len(body), "req_preview": printable(req_body, 200),
                   "resp_preview": printable(body, 200), "file_id": None,
                   "note": " ".join(x for x in ((rq.note if rq else ""), (rs.note if rs else "")) if x)}
            if rq:
                auth = rq.header("Authorization")
                if auth.lower().startswith("basic "):
                    try:
                        u, _, pw = base64.b64decode(auth[6:]).decode("latin-1").partition(":")
                        add_cred("http-basic", u, pw, host or s.server[0], s, rq_pkt, rq_ts)
                    except (binascii.Error, ValueError):
                        pass
                elif auth.lower().startswith("bearer "):
                    add_cred("http-bearer", "", auth[7:].strip(), host or s.server[0], s, rq_pkt, rq_ts)
                found = insights.extract_form_credentials(req_body, uri.partition("?")[2])
                if found:
                    add_cred("http-form", found[0], found[1], host or s.server[0], s, rq_pkt, rq_ts)
                ctype = rq.header("Content-Type")
                if "multipart/form-data" in ctype.lower():
                    for part in httpparse.parse_multipart(req_body, ctype):
                        if part["filename"]:
                            add_file(part["filename"], part["data"], "http-upload", s, rq_pkt, rq_ts, url=url)
                elif rq.method in ("PUT",) and req_body:
                    add_file(uri.split("?")[0].rsplit("/", 1)[-1], req_body, "http-upload", s, rq_pkt, rq_ts, url=url)
            if rs and body:
                cd = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)\"?", rs.header("Content-Disposition"), re.I)
                name = cd.group(1) if cd else uri.split("?")[0].rsplit("/", 1)[-1] or "index"
                rec["file_id"] = add_file(name, body, "http-response", s, rs_pkt, rs_ts, url=url, content_type=rec["content_type"])
                text_blobs.append((body, rs_pkt, rs_ts))
            http_records.append(rec)

    # ---- raw file carving in non-HTTP/FTP streams -----------------------------------------
    for s in streams:
        if s.id in claimed:
            continue
        for direction in (0, 1):
            data, found = s.data[direction], 0
            for sig, label, end_marker in CARVE:
                pos = data.find(sig)
                while pos != -1 and found < 20:
                    if end_marker:
                        e = data.find(end_marker, pos + len(sig))
                        end = e + len(end_marker) + (16 if sig == b"PK\x03\x04" else 0) if e != -1 else min(len(data), pos + 5_000_000)
                    else:
                        end = min(len(data), pos + 5_000_000)
                    if end - pos >= 16:
                        pkt, ts = s.locate(direction, pos)
                        add_file(f"carved-s{s.id}-{pos}", data[pos:end], "carved", s, pkt, ts, offset=pos)
                        found += 1
                    pos = data.find(sig, end)
        if s.data[0] or s.data[1]:
            for direction in (0, 1):
                if s.data[direction]:
                    text_blobs.append((s.data[direction][:500_000], s.locate(direction, 0)[0], s.start_ts))

    # ---- DNS over TCP ---------------------------------------------------------------------
    for s in streams:
        if s.server[1] == 53 and (s.data[0] or s.data[1]):
            for pkt, ts, msg in _tcp_dns(s):
                src, dst = (s.server[0], s.client[0]) if msg["response"] else (s.client[0], s.server[0])
                dns_events.append(_dns_event(pkt, ts, src, dst, "TCP", msg))
            claimed.add(s.id)
    dns_events.sort(key=lambda e: (e["ts"], e["packet"]))
    for n, e in enumerate(dns_events, 1):
        e["id"] = n

    # ---- stream metadata + persistence ------------------------------------------------------
    stream_meta = []
    for s in streams:
        c2s, s2c = s.data
        proto = "HTTP" if any(h["stream"] == s.id for h in http_records) else \
            label_app("TCP", s.client[1], s.server[1], (c2s or s2c)[:16])
        s.protocol = proto
        meta = {"id": s.id, "client": s.client[0], "client_port": s.client[1], "server": s.server[0],
                "server_port": s.server[1], "protocol": proto, "start": s.start_ts, "end": s.end_ts,
                "duration": round(s.end_ts - s.start_ts, 6), "packets": s.packets, "bytes_c2s": len(c2s),
                "bytes_s2c": len(s2c), "state": s.state, "gaps": s.gaps, "retransmits": s.retransmits,
                "truncated": s.truncated, "preview": printable(c2s or s2c, 80),
                "first_packet": s.packet_numbers[0] if s.packet_numbers else 0}
        stream_meta.append(meta)
        if c2s or s2c:
            for direction in (0, 1):
                (out_dir / "streams" / f"{s.id}.{direction}").write_bytes(s.data[direction])
            _dump(out_dir / "streams" / f"{s.id}.json", s.messages())

    # ---- flag hunting ---------------------------------------------------------------------
    for s in streams:
        for direction in (0, 1):
            if len(s.data[direction]) >= 6:
                for f in scanner.scan(s.data[direction]):
                    pkt, ts = s.locate(direction, f.pos)
                    collector.add(f, {"source": "stream", "stream": s.id, "packet": pkt, "ts": ts,
                                      "direction": "client→server" if direction == 0 else "server→client"})
    for fr in files:
        data = (out_dir / "files" / f"{fr['id']}.bin").read_bytes()
        for f in scanner.scan(data):
            collector.add(f, {"source": "file", "file_id": fr["id"], "name": fr["name"], "stream": fr["stream"],
                              "packet": fr["packet"], "ts": fr["ts"]})
    for e in dns_events:
        texts = [e["qname"]] + [a.split(" ", 1)[1] for a in e["answers"] if " " in a]
        for t in texts:
            for f in scanner.scan(t.encode("latin-1", "replace")):
                collector.add(f, {"source": "dns", "packet": e["packet"], "ts": e["ts"]})
    tunnels = insights.dns_tunnel_candidates(dns_events)
    for g in tunnels:
        for blob in (g["joined"],):
            for f in scanner.scan(blob.encode("latin-1", "replace")):
                f.context = f"reconstructed from {g['parent']} subdomain labels"
                collector.add(f, {"source": "dns-exfil", "packet": g["packet"], "ts": g["ts"]})
    flags = collector.result()
    flagged_streams = {l.get("stream") for f in flags for l in f["locations"]}
    for m in stream_meta:
        m["has_flag"] = m["id"] in flagged_streams

    # ---- insights ---------------------------------------------------------------------------
    suspicious = insights.detect_suspicious(packets, stream_meta, tunnels, files, creds, icmp_payloads)
    order = {"high": 0, "medium": 1, "low": 2}
    suspicious.sort(key=lambda x: (order.get(x["severity"], 3), x.get("ts") or 0))
    for n, x in enumerate(suspicious, 1):
        x["id"] = n
    iocs = insights.build_iocs(packets, dns_events, http_records, files, sni, text_blobs)
    timeline = insights.build_timeline(packets, stream_meta, http_records, dns_events, files, creds, flags, suspicious, t0)
    graph = insights.build_graph(packets)

    by_proto: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    talkers: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for p in packets:
        by_proto[p["proto"]][0] += 1
        by_proto[p["proto"]][1] += p["length"]
        for ip in (p["src"], p["dst"]):
            if ip:
                talkers[ip][0] += 1
                talkers[ip][1] += p["length"]
    total_bytes = sum(p["length"] for p in packets)
    duration = packets[-1]["ts"] - t0
    overview = {
        "format": fmt, "linktypes": linktypes, "packets": len(packets), "bytes": total_bytes, "start": t0,
        "end": packets[-1]["ts"], "duration": round(duration, 6), "truncated": truncated,
        "protocols": [{"name": k, "packets": v[0], "bytes": v[1]} for k, v in sorted(by_proto.items(), key=lambda kv: -kv[1][0])],
        "top_talkers": [{"ip": ip, "packets": v[0], "bytes": v[1], "scope": "private" if insights.is_private(ip) else "public"}
                        for ip, v in sorted(talkers.items(), key=lambda kv: -kv[1][1])[:10]],
        "hosts": len(talkers), "streams": len(streams), "http_transactions": len(http_records),
        "dns_messages": len(dns_events), "files": len(files), "flags": len(flags), "iocs": len(iocs),
        "credentials": len(creds), "suspicious": len(suspicious), "flag_prefixes": list(prefixes),
    }
    analysis = {"version": ANALYSIS_VERSION, "overview": overview, "streams": stream_meta, "http": http_records,
                "dns": dns_events, "files": files, "credentials": creds, "flags": flags, "suspicious": suspicious,
                "iocs": iocs, "timeline": timeline, "graph": graph, "warnings": warnings}
    _dump(out_dir / "packets.json", packets)
    _dump(out_dir / "analysis.json", analysis)
    return analysis


def _dns_event(pkt: int, ts: float, src: str, dst: str, transport: str, msg: dict) -> dict:
    q = msg["questions"][0] if msg["questions"] else {"name": "", "type": ""}
    return {"packet": pkt, "ts": ts, "src": src, "dst": dst, "transport": transport, "txid": msg["id"],
            "response": msg["response"], "rcode": msg["rcode"], "qname": q["name"], "qtype": q["type"],
            "answers": [f"{a['type']} {a['data']}" for a in msg["answers"]]}
