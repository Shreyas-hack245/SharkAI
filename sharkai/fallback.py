"""Deterministic investigation answers, rendered from the same evidence bundle the AI would see.
Used when no provider is configured, when it is unreachable, or when the user turns AI off."""
from __future__ import annotations


def _t(v, n: int = 120) -> str:
    s = str(v).replace("`", "'").replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def _where(loc: dict) -> str:
    bits = [loc["source"]]
    if loc.get("packet"):
        bits.append(f"packet {loc['packet']}")
    if loc.get("stream") is not None:
        bits.append(f"stream {loc['stream']}")
    if loc.get("file"):
        bits.append(f"file {loc['file']}")
    return ", ".join(bits)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


def render_fallback(bundle: dict, question: str, reason: str) -> str:
    ev, intents = bundle["evidence"], bundle["intents"]
    general = not intents
    cap = ev["capture"]
    out = [f"> **Deterministic result** ({_t(reason or 'AI not used', 100)}). These findings come directly from SharkAI's "
           "analysis of the capture; no AI model was involved.", ""]

    def show(name: str, *also: str) -> bool:
        return general or name in intents or any(a in intents for a in also)

    if general or "hosts" in intents:
        protos = ", ".join(f"{p['name']} ({p['packets']})" for p in cap["protocols"][:5])
        out += [f"**Capture:** {cap['packets']} packets, {_fmt_bytes(cap['bytes'])} over {cap['duration_s']:.2f}s; "
                f"{cap['hosts']} hosts, {cap['tcp_streams']} TCP streams, {cap['http_transactions']} HTTP transactions, "
                f"{cap['dns_messages']} DNS messages, {cap['files_extracted']} extracted files.",
                f"**Protocols:** {protos or 'none'}."]
        if "hosts" in intents:
            out += ["", "**Top talkers**"] + [f"- `{h['ip']}` ({h['scope']}): {h['packets']} packets, {_fmt_bytes(h['bytes'])}" for h in ev["hosts"]]
        out.append("")

    if show("flags"):
        out.append("**Flag candidates**")
        if ev["flags"]:
            for f in ev["flags"]:
                where = "; ".join(_where(l) for l in f["found_in"])
                out.append(f"- `{_t(f['flag'], 200)}` [{f['id']}] — {f['confidence']} confidence, {f['encoding']} ({where})")
        else:
            out.append("- None of the common flag formats were found in packets, streams, HTTP bodies, DNS or extracted files.")
        out.append("")

    if show("iocs") and ev["alerts"]:
        out.append("**Suspicious activity**")
        out += [f"- [{a['id']}] **{a['severity']}** — {_t(a['title'])}: {_t(a['detail'], 200)}" for a in ev["alerts"]]
        out.append("")

    if show("credentials", "http"):
        if ev["credentials"]:
            out.append("**Cleartext credentials**")
            out += [f"- [{c['id']}] {c['kind']} user `{_t(c['user'], 40)}` secret `{_t(c['secret'], 40)}` → {c['host']} (stream {c['stream']}, packet {c['packet']})"
                    for c in ev["credentials"]]
            out.append("")
        elif "credentials" in intents:
            out += ["**Cleartext credentials:** none found.", ""]

    if "http" in intents:
        out.append("**HTTP transactions**")
        out += [f"- [{h['id']}] `{h['method'] or '?'} {_t(h['url'], 90)}` → {h['status'] or 'no response'} {_t(h['content_type'], 30)}, {h['resp_bytes']} bytes (stream {h['stream']})"
                for h in ev["http"][:25]] or ["- No HTTP traffic was reconstructed."]
        out.append("")

    if "dns" in intents:
        out.append("**DNS activity**")
        out += [f"- [{d['id']}] `{_t(d['name'], 80)}` {d['type']} ×{d['queries']} from {d['client']}" + (f" → {', '.join(d['answers'])}" if d["answers"] else (f" ({d['rcode']})" if d["rcode"] else ""))
                for d in ev["dns"][:30]] or ["- No DNS messages were found."]
        out.append("")

    if "files" in intents:
        out.append("**Extracted files**")
        out += [f"- [{f['id']}] `{_t(f['name'], 50)}` — {f['type']}, {f['size']} bytes, sha256 `{f['sha256'][:16]}…` ({f['source']}, stream {f['stream']})"
                for f in ev["files"][:20]] or ["- No files could be extracted."]
        out.append("")

    if "iocs" in intents:
        out.append("**Indicators**")
        out += [f"- [{i['id']}] {i['type']}: `{_t(i['value'], 80)}` ×{i['count']}" + (f" ({i['scope']})" if i.get("scope") else "") for i in ev["iocs"][:25]]
        out.append("")

    if "streams" in intents:
        out.append("**Largest TCP streams**")
        out += [f"- [{s['id']}] {s['client']} → {s['server']} {s['protocol']}, {_fmt_bytes(s['bytes_c2s'] + s['bytes_s2c'])}, {s['state']}" + (" — contains a flag candidate" if s["has_flag"] else "")
                for s in ev["streams"][:15]]
        out.append("")

    if "timeline" in intents:
        out.append("**Timeline (first events)**")
        out += [f"- +{e['t']}s {e['kind']}: {_t(e['title'], 100)}" for e in ev["timeline"][:20]]
        out.append("")

    steps = []
    if ev["flags"]:
        loc = ev["flags"][0]["found_in"][0] if ev["flags"][0]["found_in"] else {}
        steps.append("Open the **Flags** tab to jump to where each candidate was found." if loc.get("stream") is None
                     else f"Follow the stream behind the first flag: **Streams → {loc['stream']}**, or filter `tcp.stream == {loc['stream']}`.")
    elif general or "flags" in intents:
        steps.append("Search raw frames with a filter such as `frame contains \"flag\"`, or add your CTF's prefix in the Flags tab and re-analyse.")
    if ev["alerts"]:
        steps.append("Review the highlighted alerts, then pivot to the matching packets in the **Packets** tab.")
    if general:
        steps.append("Ask about a specific area: flags, DNS, HTTP downloads, credentials, files or a timeline.")
    if steps:
        out += ["**Next steps**"] + [f"- {s}" for s in steps]
    return "\n".join(out).strip() + "\n"
