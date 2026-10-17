"""Derived views over analysed data: DNS tunnelling, suspicious-activity heuristics, IOCs, timeline, graph."""
from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import re
import statistics
from collections import Counter, defaultdict

from .flags import FlagScanner

EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\.[A-Za-z]{2,10}")
SECRET_KEY_RE = re.compile(r"(pass(word|wd)?|pwd|secret|token|api[_-]?key)$", re.I)
USER_KEY_RE = re.compile(r"(user(name)?|login|email|uname|account)$", re.I)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def parent_domain(name: str) -> str:
    parts = name.strip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name.lower()


_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "224.0.0.0/4", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")]


def is_private(ip: str) -> bool:
    """Internal = RFC1918/loopback/link-local/multicast/CGNAT. Documentation ranges (TEST-NET) count as
    external on purpose: CTF and lab captures use them to stand in for internet hosts."""
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in _INTERNAL if n.version == a.version)
    except ValueError:
        return False


# -- DNS ---------------------------------------------------------------------------------------
def _decode_label_stream(text: str) -> list[tuple[str, bytes]]:
    out = []
    t = text.strip()
    if len(t) >= 8 and len(t) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", t):
        try:
            out.append(("hex", binascii.unhexlify(t)))
        except binascii.Error:
            pass
    if len(t) >= 8 and re.fullmatch(r"[A-Za-z2-7]+=*", t):
        try:
            out.append(("base32", base64.b32decode(t.upper() + "=" * (-len(t) % 8))))
        except (binascii.Error, ValueError):
            pass
    if len(t) >= 8 and re.fullmatch(r"[A-Za-z0-9+/_-]+=*", t):
        try:
            raw = t.replace("-", "+").replace("_", "/")
            out.append(("base64", base64.b64decode(raw + "=" * (-len(raw) % 4))))
        except (binascii.Error, ValueError):
            pass
    return out


def dns_tunnel_candidates(events: list[dict]) -> list[dict]:
    """Group queries by zone (everything after the first label); many unique, long/high-entropy first
    labels under one zone is the classic shape of DNS tunnelling or exfiltration."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        parts = e["qname"].strip(".").lower().split(".") if e["qname"] else []
        if not e["response"] and len(parts) >= 3:
            groups[".".join(parts[1:])].append(e)
    results = []
    for zone, evs in groups.items():
        names, seen = [], set()
        for e in evs:
            lb = e["qname"].strip(".").lower().split(".")[0]
            if lb not in seen:
                seen.add(lb)
                names.append((lb, e))
        if len(names) < 4:
            continue
        avg_len = statistics.mean(len(lb) for lb, _ in names)
        ent = statistics.mean(entropy(lb) for lb, _ in names)
        if not (avg_len >= 10 or ent >= 3.0 or len(names) >= 20):
            continue
        joined = "".join(lb for lb, _ in names)
        recon = []
        for enc, raw in _decode_label_stream(joined):
            ratio = sum(1 for c in raw if 32 <= c < 127 or c in (9, 10, 13)) / max(1, len(raw))
            if ratio >= 0.8:
                recon.append({"encoding": enc, "text": raw.decode("latin-1")[:400]})
        results.append({"parent": zone, "unique_names": len(names), "avg_label_len": round(avg_len, 1),
                        "entropy": round(ent, 2), "qtypes": sorted({e["qtype"] for _, e in names}),
                        "packet": names[0][1]["packet"], "ts": names[0][1]["ts"], "reconstructed": recon,
                        "joined": joined, "severity": "high" if len(names) >= 20 or recon else "medium"})
    return results


# -- suspicious heuristics -----------------------------------------------------------------------
def _standard_ping(payload: bytes) -> bool:
    n = len(payload)
    win = bytes(97 + i % 23 for i in range(n))
    lin = bytes(i & 0xFF for i in range(8, 8 + n))
    return payload in (win, lin) or n == 0 or payload.count(payload[:1]) == n


def detect_suspicious(packets: list[dict], streams: list[dict], dns_groups: list[dict], files: list[dict],
                      creds: list[dict], icmp_payloads: list[tuple[int, float, str, str, bytes]]) -> list[dict]:
    out: list[dict] = []

    def add(severity: str, title: str, detail: str, **ref) -> None:
        out.append({"severity": severity, "title": title, "detail": detail, **ref})

    # SYN scan: one source probing many ports on one host
    probes: dict[tuple[str, str], dict[int, int]] = defaultdict(dict)
    for p in packets:
        if p.get("l4") == "TCP" and p.get("flags") == "SYN":
            probes[(p["src"], p["dst"])].setdefault(p["dport"], p["n"])
    for (src, dst), ports in probes.items():
        if len(ports) >= 15:
            add("high", "Possible port scan", f"{src} sent SYN probes to {len(ports)} distinct ports on {dst}",
                packet=min(ports.values()), ts=_ts(packets, min(ports.values())))
    sweep: dict[str, dict[str, int]] = defaultdict(dict)
    for p in packets:
        if p.get("l4") == "ICMP" and p.get("info", "").startswith("Echo request"):
            sweep[p["src"]].setdefault(p["dst"], p["n"])
    for src, dsts in sweep.items():
        if len(dsts) >= 10:
            add("medium", "Possible ICMP sweep", f"{src} pinged {len(dsts)} different hosts", packet=min(dsts.values()))

    for g in dns_groups:
        detail = f"{g['unique_names']} unique subdomains of {g['parent']} (avg label {g['avg_label_len']} chars, entropy {g['entropy']})"
        if g["reconstructed"]:
            detail += f"; labels decode as {g['reconstructed'][0]['encoding']}: {g['reconstructed'][0]['text'][:80]!r}"
        add(g["severity"], "Possible DNS tunnelling / exfiltration", detail, packet=g["packet"], ts=g["ts"])

    for n, ts, src, dst, payload in icmp_payloads:
        if len(payload) >= 16 and not _standard_ping(payload):
            ratio = sum(1 for c in payload if 32 <= c < 127) / len(payload)
            if ratio >= 0.85 or len(payload) > 128:
                add("medium", "ICMP payload carries non-standard data",
                    f"{src} → {dst}: {len(payload)} bytes ({'readable text' if ratio >= 0.85 else 'large payload'})",
                    packet=n, ts=ts)
                break

    for c in creds:
        add("high", "Cleartext credentials observed", f"{c['kind']} login as {c['user'] or '(no user)'} to {c['host']}",
            packet=c["packet"], stream=c.get("stream"), ts=c["ts"])
    for f in files:
        if f["type"] in ("ELF executable", "Windows executable"):
            add("medium", "Executable transferred", f"{f['name']} ({f['type']}, {f['size']} bytes, sha256 {f['sha256'][:16]}…)",
                packet=f["packet"], stream=f.get("stream"), ts=f["ts"])

    # Beaconing: regular-interval connections to one destination
    by_dest: dict[tuple, list[float]] = defaultdict(list)
    for s in streams:
        by_dest[(s["client"], s["server"], s["server_port"])].append(s["start"])
    for (client, server, port), times in by_dest.items():
        times.sort()
        if len(times) >= 6:
            gaps = [b - a for a, b in zip(times, times[1:])]
            mean = statistics.mean(gaps)
            if mean >= 1 and statistics.pstdev(gaps) / mean < 0.15:
                add("medium", "Possible beaconing", f"{client} connected to {server}:{port} {len(times)} times roughly every {mean:.1f}s",
                    ts=times[0])
    return out


def _ts(packets: list[dict], n: int) -> float:
    return packets[n - 1]["ts"] if 0 < n <= len(packets) else 0.0


# -- IOCs --------------------------------------------------------------------------------------
def build_iocs(packets: list[dict], dns_events: list[dict], http: list[dict], files: list[dict], sni: list[dict],
               text_blobs: list[tuple[bytes, int, float]]) -> list[dict]:
    items: dict[tuple[str, str], dict] = {}

    def add(kind: str, value: str, ts: float, packet: int, context: str = "", scope: str = "") -> None:
        if not value:
            return
        it = items.setdefault((kind, value), {"type": kind, "value": value, "count": 0, "first_seen": ts,
                                              "packet": packet, "context": context, "scope": scope})
        it["count"] += 1
        it["first_seen"] = min(it["first_seen"], ts)

    ip_counts: Counter = Counter()
    first: dict[str, tuple[float, int]] = {}
    for p in packets:
        for ip in (p["src"], p["dst"]):
            if ip:
                ip_counts[ip] += 1
                first.setdefault(ip, (p["ts"], p["n"]))
    for ip, n in ip_counts.items():
        if ip in ("0.0.0.0", "255.255.255.255"):
            continue
        ts, pk = first[ip]
        items[("ip", ip)] = {"type": "ip", "value": ip, "count": n, "first_seen": ts, "packet": pk, "context": "",
                             "scope": "private" if is_private(ip) else "public"}
    for e in dns_events:
        if e["qname"]:
            add("domain", e["qname"].lower().rstrip("."), e["ts"], e["packet"], f"DNS {e['qtype']} query")
    for h in http:
        if h.get("host"):
            add("domain", h["host"].split(":")[0].lower(), h["ts"], h["packet"], "HTTP Host header")
        if h.get("url"):
            add("url", h["url"], h["ts"], h["packet"], f"{h['method']} → {h.get('status') or 'no response'}")
        if h.get("user_agent"):
            add("user-agent", h["user_agent"], h["ts"], h["packet"])
        loc = h.get("location")
        if loc:
            add("url", loc, h["ts"], h["packet"], "redirect target")
    for s in sni:
        add("domain", s["domain"].lower(), s["ts"], s["packet"], "TLS SNI")
    for f in files:
        add("sha256", f["sha256"], f["ts"], f["packet"], f"{f['name']} ({f['type']})")
    emails = 0
    for blob, pkt, ts in text_blobs:
        for m in EMAIL_RE.finditer(blob[:2_000_000]):
            add("email", m.group().decode("latin-1").lower(), ts, pkt, "found in cleartext payload")
            emails += 1
            if emails > 300:
                break
    out = sorted(items.values(), key=lambda i: (i["type"], -i["count"], i["value"]))
    for n, it in enumerate(out, 1):
        it["id"] = n
    return out


def extract_form_credentials(body: bytes, query: str) -> tuple[str, str] | None:
    from urllib.parse import parse_qsl
    for source in (body.decode("latin-1", "replace"), query):
        pairs = parse_qsl(source, keep_blank_values=True)
        secret = next((v for k, v in pairs if SECRET_KEY_RE.search(k) and v), "")
        if secret:
            user = next((v for k, v in pairs if USER_KEY_RE.search(k)), "")
            return user, secret
    return None


# -- Timeline & graph ----------------------------------------------------------------------------
def build_timeline(packets: list[dict], streams: list[dict], http: list[dict], dns_events: list[dict],
                   files: list[dict], creds: list[dict], flags: list[dict], suspicious: list[dict], t0: float) -> dict:
    ev: list[dict] = []

    def add(ts: float, kind: str, title: str, detail: str = "", packet: int = 0, stream=None, severity: str = "info") -> None:
        ev.append({"ts": ts, "rel": round(ts - t0, 6), "kind": kind, "title": title, "detail": detail,
                   "packet": packet, "stream": stream, "severity": severity})

    if packets:
        add(packets[0]["ts"], "capture", "Capture starts", f"{len(packets)} packets in this file", packets[0]["n"])
        add(packets[-1]["ts"], "capture", "Capture ends", "", packets[-1]["n"])
    for s in streams:
        if s["bytes_c2s"] + s["bytes_s2c"] > 0:
            add(s["start"], "stream", f"TCP stream {s['id']} opened", f"{s['client']}:{s['client_port']} → {s['server']}:{s['server_port']} ({s['protocol']})",
                s["first_packet"], s["id"])
    for h in http:
        add(h["ts"], "http", f"{h['method'] or 'HTTP'} {h['url'] or h['uri']}", f"status {h.get('status') or '—'}", h["packet"], h["stream"])
    seen = set()
    for e in dns_events:
        if not e["response"] and e["qname"] not in seen and len(seen) < 300:
            seen.add(e["qname"])
            add(e["ts"], "dns", f"DNS query {e['qtype']} {e['qname']}", f"from {e['src']}", e["packet"])
    for f in files:
        add(f["ts"], "file", f"File {f['name']}", f"{f['type']}, {f['size']} bytes, from {f['source']}", f["packet"], f.get("stream"))
    for c in creds:
        add(c["ts"], "credential", f"{c['kind']} credentials", f"user {c['user'] or '—'} @ {c['host']}", c["packet"], c.get("stream"), "high")
    for f in flags:
        loc = f["locations"][0]
        add(loc["ts"], "flag", f"Flag candidate {f['flag']}", f"{f['encoding']} via {loc['source']}", loc.get("packet", 0), loc.get("stream"), "high")
    for s in suspicious:
        add(s.get("ts") or t0, "alert", s["title"], s["detail"], s.get("packet", 0), s.get("stream"), s["severity"])
    ev.sort(key=lambda e: (e["ts"], e["packet"]))
    buckets: list[int] = []
    if packets:
        end = packets[-1]["ts"]
        span = max(end - t0, 1e-6)
        buckets = [0] * 60
        for p in packets:
            buckets[min(59, int((p["ts"] - t0) / span * 60))] += 1
    return {"events": ev[:4000], "buckets": buckets, "truncated": len(ev) > 4000}


def build_graph(packets: list[dict], max_nodes: int = 60, max_edges: int = 200) -> dict:
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str], dict] = {}
    for p in packets:
        a, b = p["src"], p["dst"]
        if not a or not b:
            continue
        for ip in (a, b):
            n = nodes.setdefault(ip, {"id": ip, "packets": 0, "bytes": 0, "scope": "private" if is_private(ip) else "public"})
            n["packets"] += 1
            n["bytes"] += p["length"]
        key = (a, b) if a <= b else (b, a)
        e = edges.setdefault(key, {"source": key[0], "target": key[1], "packets": 0, "bytes": 0, "protocols": Counter()})
        e["packets"] += 1
        e["bytes"] += p["length"]
        e["protocols"][p["proto"]] += 1
    keep = {n["id"] for n in sorted(nodes.values(), key=lambda n: -n["bytes"])[:max_nodes]}
    out_edges = [e for e in sorted(edges.values(), key=lambda e: -e["bytes"]) if e["source"] in keep and e["target"] in keep][:max_edges]
    for e in out_edges:
        e["protocols"] = [{"name": k, "packets": v} for k, v in e["protocols"].most_common(4)]
    return {"nodes": [nodes[i] for i in keep], "edges": out_edges, "truncated": len(nodes) > max_nodes or len(edges) > max_edges}


def scan_text_for_flags(scanner: FlagScanner, text: str) -> list:
    return scanner.scan(text.encode("latin-1", "replace"))
