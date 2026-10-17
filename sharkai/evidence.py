"""Builds the *only* data the AI provider is ever shown: a bounded, sanitised, ID-tagged JSON bundle
derived from the analysis. Raw PCAP bytes and full payloads never leave the machine; snippets are
printable-ASCII and length-capped, and credentials are masked unless explicitly allowed."""
from __future__ import annotations

import json
import re
from collections import Counter

INTENTS = {
    "flags": ("flag", "ctf", "secret", "hidden", "encoded", "base64", "decode", "hex", "answer", "solve", "challenge"),
    "dns": ("dns", "domain", "tunnel", "exfil", "subdomain", "resolve", "query", "txt"),
    "http": ("http", "url", "request", "response", "download", "upload", "user-agent", "agent", "web", "post", "get", "cookie", "login"),
    "files": ("file", "extract", "carve", "malware", "exe", "binary", "zip", "png", "hash", "sha256", "image", "attachment"),
    "credentials": ("password", "credential", "login", "auth", "ftp", "telnet", "username", "secret", "token", "cleartext"),
    "iocs": ("ioc", "indicator", "ip", "address", "suspicious", "malicious", "scan", "c2", "beacon", "attack", "threat", "compromise", "anomal"),
    "timeline": ("timeline", "when", "order", "sequence", "first", "last", "happened", "chronolog"),
    "streams": ("stream", "conversation", "session", "tcp", "connection", "follow"),
    "hosts": ("host", "talker", "who", "top", "traffic", "communicat", "network", "graph"),
}
LIMITS = {"flags": 20, "alerts": 15, "credentials": 10, "http": 25, "dns": 30, "files": 20, "streams": 15, "iocs": 40, "timeline": 25, "hosts": 8}
FOCUS_LIMITS = {"flags": 30, "alerts": 20, "credentials": 20, "http": 60, "dns": 80, "files": 40, "streams": 40, "iocs": 80, "timeline": 60, "hosts": 15}
TRIM_ORDER = ("timeline", "iocs", "streams", "dns", "files", "http", "credentials", "hosts", "alerts", "flags")
SECRET_PAT = re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|token|secret|api[_-]?key)=([^&\s]+)")
CMD_PAT = re.compile(r"(?i)\b(PASS|AUTH)\s+\S+")
AUTH_PAT = re.compile(r"(?i)(authorization:\s*\w+\s+)\S+")


def clean(value, limit: int = 160) -> str:
    s = str(value if value is not None else "").replace("→", "->").replace("…", "...")
    return "".join(c if 32 <= ord(c) < 127 else "." for c in s[:limit])


def detect_intents(question: str) -> list[str]:
    q = question.lower()
    return [name for name, words in INTENTS.items() if any(w in q for w in words)]


def _terms(question: str) -> list[str]:
    q = question.lower()
    terms = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", q)                    # IPs
    terms += re.findall(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", q)               # domains / filenames
    terms += [f"stream {m}" for m in re.findall(r"stream\s+#?(\d+)", q)]
    terms += re.findall(r"\bport\s+(\d+)\b", q)
    terms += re.findall(r"\bpacket\s+#?(\d+)\b", q)
    return list(dict.fromkeys(terms))[:8]


class _Scrubber:
    def __init__(self, enabled: bool, secrets: list[str]) -> None:
        self.enabled = enabled
        self.secrets = sorted({s for s in secrets if len(s) >= 4}, key=len, reverse=True)

    def __call__(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        text = AUTH_PAT.sub(r"\1[redacted]", CMD_PAT.sub(r"\1 [redacted]", SECRET_PAT.sub(r"\1=[redacted]", text)))
        for s in self.secrets:
            text = text.replace(s, "[redacted]")
        return text


def build_evidence(analysis: dict, question: str, *, redact: bool = True, max_chars: int = 16000) -> dict:
    ov = analysis["overview"]
    intents = detect_intents(question)
    terms = _terms(question)
    scrub = _Scrubber(redact, [c["secret"] for c in analysis.get("credentials", [])])

    def c(v, n=160):
        return scrub(clean(v, n))

    def pick(items: list, section: str, haystack=lambda i: "") -> list:
        limit = FOCUS_LIMITS[section] if section in intents else LIMITS[section]
        if terms:
            hits = [i for i in items if any(t in json.dumps(haystack(i)).lower() for t in terms)]
            items = hits + [i for i in items if i not in hits]
        return items[:limit]

    sections: dict[str, list] = {}
    sections["flags"] = [{"id": f"F{f['id']}", "flag": clean(f["flag"], 200), "encoding": f["encoding"], "confidence": f["confidence"],
                          "context": c(f["context"]), "found_in": [
                              {k: v for k, v in {"source": l["source"], "packet": l.get("packet"), "stream": l.get("stream"),
                                                 "file": l.get("name")}.items() if v is not None} for l in f["locations"][:3]]}
                         for f in pick(analysis["flags"], "flags", lambda f: f)]
    sections["alerts"] = [{"id": f"A{a['id']}", "severity": a["severity"], "title": a["title"], "detail": c(a["detail"], 240),
                           "packet": a.get("packet"), "stream": a.get("stream")} for a in pick(analysis["suspicious"], "alerts", lambda a: a)]
    sections["credentials"] = [{"id": f"C{x['id']}", "kind": x["kind"], "user": c(x["user"], 60),
                                "secret": "[redacted]" if redact else c(x["secret"], 80), "host": x["host"],
                                "stream": x["stream"], "packet": x["packet"]} for x in pick(analysis["credentials"], "credentials", lambda x: [x["host"], x["user"]])]
    sections["http"] = [{"id": f"H{h['id']}", "method": h["method"], "url": c(h["url"], 200), "status": h["status"],
                         "content_type": h["content_type"], "resp_bytes": h["resp_size"], "user_agent": c(h["user_agent"], 80),
                         "stream": h["stream"], "packet": h["packet"], "request_body": c(h["req_preview"], 100),
                         "response_preview": c(h["resp_preview"], 100)} for h in pick(analysis["http"], "http", lambda h: [h["url"], h["client"], h["server"], h["stream"]])]
    names = Counter()
    first: dict[str, dict] = {}
    for e in analysis["dns"]:
        if not e["response"]:
            names[(e["qname"], e["qtype"])] += 1
            first.setdefault((e["qname"], e["qtype"]), e)
    answers = {}
    for e in analysis["dns"]:
        if e["response"]:
            answers.setdefault((e["qname"], e["qtype"]), (e["rcode"], e["answers"][:3]))
    dns_items = [{"id": f"D{first[k]['id']}", "name": clean(k[0], 120), "type": k[1], "queries": n, "client": first[k]["src"],
                  "rcode": answers.get(k, ("", []))[0], "answers": [c(a, 100) for a in answers.get(k, ("", []))[1]],
                  "packet": first[k]["packet"]} for k, n in names.most_common(300)]
    sections["dns"] = pick(dns_items, "dns", lambda d: [d["name"], d["client"], d["answers"]])
    sections["files"] = [{"id": f"X{f['id']}", "name": f["name"], "type": f["type"], "size": f["size"], "sha256": f["sha256"],
                          "source": f["source"], "stream": f["stream"], "packet": f["packet"], "preview": c(f["preview"], 100)}
                         for f in pick(analysis["files"], "files", lambda f: [f["name"], f["sha256"]])]
    sections["streams"] = [{"id": f"S{s['id']}", "client": f"{s['client']}:{s['client_port']}", "server": f"{s['server']}:{s['server_port']}",
                            "protocol": s["protocol"], "bytes_c2s": s["bytes_c2s"], "bytes_s2c": s["bytes_s2c"], "state": s["state"],
                            "has_flag": s.get("has_flag", False), "preview": c(s["preview"], 80)}
                           for s in pick(sorted(analysis["streams"], key=lambda s: -(s["bytes_c2s"] + s["bytes_s2c"])), "streams",
                                         lambda s: [s["client"], s["server"], s["server_port"], f"stream {s['id']}"])]
    public_first = sorted(analysis["iocs"], key=lambda i: (i["type"] == "ip" and i["scope"] == "private", i["type"]))
    sections["iocs"] = [{"id": f"I{i['id']}", "type": i["type"], "value": c(i["value"], 120), "count": i["count"],
                         **({"scope": i["scope"]} if i["scope"] else {})} for i in pick(public_first, "iocs", lambda i: i["value"])]
    sections["timeline"] = [{"t": round(e["rel"], 3), "kind": e["kind"], "title": c(e["title"], 120), "packet": e["packet"]}
                            for e in pick([e for e in analysis["timeline"]["events"] if e["kind"] != "capture"], "timeline", lambda e: e["title"])]
    sections["hosts"] = ov["top_talkers"][:LIMITS["hosts"]]

    evidence = {
        "capture": {"format": ov["format"], "packets": ov["packets"], "bytes": ov["bytes"], "duration_s": ov["duration"],
                    "hosts": ov["hosts"], "tcp_streams": ov["streams"], "http_transactions": ov["http_transactions"],
                    "dns_messages": ov["dns_messages"], "files_extracted": ov["files"], "flag_candidates": ov["flags"],
                    "protocols": ov["protocols"][:8], "warnings": [c(w, 120) for w in analysis["warnings"][:5]]},
        **sections,
        "notes": ["Evidence is a bounded sample of the analysis, not the whole capture.",
                  "Credential secrets are masked." if redact else "Credential secrets are included (redaction disabled)."],
    }
    # Always keep flags/alerts; bias the rest by intent. Drop low-signal sections when intent is specific.
    if intents:
        for name in ("timeline", "streams", "iocs", "dns", "http", "files", "credentials", "hosts"):
            wanted = name in intents or (name == "http" and "files" in intents) or (name == "credentials" and "http" in intents)
            if not wanted:
                evidence[name] = evidence[name][: max(3, len(evidence[name]) // 4)]
    def size() -> int:
        return len(json.dumps(evidence, separators=(",", ":")))

    # Trim to the configured budget: first shrink low-signal sections (keeping a few flags/alerts),
    # then relax those floors, then drop optional overview detail. Always converges.
    for floors in ({"flags": 5, "alerts": 5}, {"flags": 2, "alerts": 1}, {"flags": 1, "alerts": 0}, {"flags": 0, "alerts": 0}):
        while size() > max_chars:
            for name in TRIM_ORDER:
                items = evidence[name]
                if len(items) > floors.get(name, 0):
                    evidence[name] = items[: max(floors.get(name, 0), len(items) * 2 // 3 if len(items) > 2 else len(items) - 1)]
                    break
            else:
                break
        if size() <= max_chars:
            break
    if size() > max_chars:
        evidence["capture"]["protocols"], evidence["capture"]["warnings"] = [], []
        evidence["notes"] = ["evidence truncated to the configured size limit"]
    elif any(len(evidence[n]) < len(sections[n]) for n in sections):
        evidence["notes"].append("some items were omitted to fit the configured size limit")
    text = json.dumps(evidence, separators=(",", ":"))
    ids = sorted({i["id"] for name in TRIM_ORDER if name != "timeline" and name != "hosts" for i in evidence[name] if "id" in i})
    return {"evidence": evidence, "text": text, "chars": len(text), "ids": ids, "intents": intents,
            "counts": {k: len(v) for k, v in evidence.items() if isinstance(v, list) and k != "notes"}}
