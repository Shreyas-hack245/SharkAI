"""Report generation: Markdown, JSON and PDF, all built from the same stored analysis (never from the AI)."""
from __future__ import annotations

import io
import re
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from . import __version__


def _ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "-"


def _fmt_bytes(n: int) -> str:
    v = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024 or unit == "GB":
            return f"{int(v)} B" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024
    return f"{n} B"


def _secret(c: dict, redact: bool) -> str:
    return f"[redacted, {len(c['secret'])} chars]" if redact else c["secret"]


def _secrets(a: dict) -> list[str]:
    return sorted({c["secret"] for c in a["credentials"] if len(c["secret"]) >= 3}, key=len, reverse=True)


def scrub(obj, secrets: list[str]):
    """Replace every literal occurrence of a known secret anywhere in a nested structure."""
    if isinstance(obj, str):
        for sec in secrets:
            obj = obj.replace(sec, "[redacted]")
        return obj
    if isinstance(obj, list):
        return [scrub(x, secrets) for x in obj]
    if isinstance(obj, tuple):
        return tuple(scrub(x, secrets) for x in obj)
    if isinstance(obj, dict):
        return {k: scrub(v, secrets) for k, v in obj.items()}
    return obj


def _prepare(meta: dict, a: dict, redact: bool) -> dict:
    d = _prepare_raw(meta, a, redact)
    return scrub(d, _secrets(a)) if redact else d


def _prepare_raw(meta: dict, a: dict, redact: bool) -> dict:
    ov = a["overview"]
    dns_seen: dict = {}
    for e in a["dns"]:
        if not e["response"]:
            d = dns_seen.setdefault((e["qname"], e["qtype"]), {"name": e["qname"], "type": e["qtype"], "count": 0, "client": e["src"], "answers": ""})
            d["count"] += 1
    for e in a["dns"]:
        if e["response"] and (e["qname"], e["qtype"]) in dns_seen and not dns_seen[(e["qname"], e["qtype"])]["answers"]:
            dns_seen[(e["qname"], e["qtype"])]["answers"] = ", ".join(x.split(" ", 1)[-1] for x in e["answers"][:3]) or e["rcode"]
    iocs = sorted(a["iocs"], key=lambda i: (i["type"] == "ip" and i["scope"] == "private", i["type"], -i["count"]))
    return {
        "meta": meta, "overview": ov, "redacted": redact,
        "summary": [("Packets", f"{ov['packets']:,}"), ("Size", _fmt_bytes(ov["bytes"])), ("Duration", f"{ov['duration']:.2f} s"),
                    ("Start", _ts(ov["start"])), ("Hosts", ov["hosts"]), ("TCP streams", ov["streams"]),
                    ("HTTP transactions", ov["http_transactions"]), ("DNS messages", ov["dns_messages"]),
                    ("Extracted files", ov["files"]), ("Flag candidates", ov["flags"])],
        "flags": [[f["flag"], f["encoding"], f["confidence"], "; ".join(
            f"{l['source']} pkt {l.get('packet', '-')}" + (f" stream {l['stream']}" if l.get("stream") is not None else "") for l in f["locations"][:3])] for f in a["flags"]],
        "alerts": [[x["severity"], x["title"], x["detail"]] for x in a["suspicious"]],
        "credentials": [[c["kind"], c["user"], _secret(c, redact), c["host"], c["packet"]] for c in a["credentials"]],
        "iocs": [[i["type"], i["value"], i["count"], i["scope"] or "-"] for i in iocs[:80]],
        "http": [[h["id"], h["method"] or "-", h["url"] or h["uri"], h["status"] or "-", h["content_type"] or "-", h["resp_size"]] for h in a["http"][:60]],
        "dns": [[d["name"], d["type"], d["count"], d["client"], d["answers"] or "-"] for d in sorted(dns_seen.values(), key=lambda d: -d["count"])[:50]],
        "files": [[f["id"], f["name"], f["type"], f["size"], f["sha256"], f["source"]] for f in a["files"][:60]],
        "streams": [[s["id"], f"{s['client']}:{s['client_port']}", f"{s['server']}:{s['server_port']}", s["protocol"],
                     s["bytes_c2s"] + s["bytes_s2c"], s["state"]]
                    for s in sorted(a["streams"], key=lambda s: -(s["bytes_c2s"] + s["bytes_s2c"]))[:30]],
        "timeline": [[f"+{e['rel']:.3f}s", e["kind"], e["title"]] for e in a["timeline"]["events"] if e["kind"] != "capture"][:80],
        "warnings": a["warnings"],
    }


# -- Markdown -----------------------------------------------------------------------------------
def _cell(v) -> str:
    s = str(v).replace("\r", " ").replace("\n", " ").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")
    s = "".join(c if c.isprintable() else "." for c in s)
    return s[:200]


def _md_table(headers: list[str], rows: list[list]) -> list[str]:
    if not rows:
        return ["_None found._", ""]
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(f"`{_cell(c).replace('`', chr(39))}`" if i == 0 and headers[0] in ("Flag",) else _cell(c) for i, c in enumerate(r)) + " |" for r in rows]
    return out + [""]


def build_markdown(meta: dict, a: dict, redact: bool = False) -> str:
    d = _prepare(meta, a, redact)
    L = [f"# SharkAI report: {_cell(meta['name'])}", "",
         f"- **Generated:** {_ts(datetime.now(timezone.utc).timestamp())} by SharkAI {__version__}",
         f"- **SHA-256:** `{meta['sha256']}`", f"- **File size:** {_fmt_bytes(meta['size'])} ({d['overview']['format']})",
         f"- **Secrets:** {'masked' if redact else 'shown (this report may contain credentials; handle accordingly)'}", "",
         "## Summary", ""] + _md_table(["Metric", "Value"], [list(r) for r in d["summary"]])
    sections = [("Flag candidates", ["Flag", "Encoding", "Confidence", "Found in"], d["flags"]),
                ("Suspicious activity", ["Severity", "Finding", "Detail"], d["alerts"]),
                ("Cleartext credentials", ["Kind", "User", "Secret", "Host", "Packet"], d["credentials"]),
                ("Indicators of compromise", ["Type", "Value", "Count", "Scope"], d["iocs"]),
                ("HTTP transactions", ["#", "Method", "URL", "Status", "Content-Type", "Bytes"], d["http"]),
                ("DNS queries", ["Name", "Type", "Count", "Client", "Answer"], d["dns"]),
                ("Extracted files", ["#", "Name", "Type", "Size", "SHA-256", "Source"], d["files"]),
                ("Largest TCP streams", ["#", "Client", "Server", "Protocol", "Bytes", "State"], d["streams"]),
                ("Timeline", ["Time", "Kind", "Event"], d["timeline"])]
    for title, headers, rows in sections:
        L += [f"## {title}", ""] + _md_table(headers, rows)
    if d["warnings"]:
        L += ["## Analysis notes", ""] + [f"- {_cell(w)}" for w in d["warnings"]] + [""]
    L += ["---", "_Findings are heuristic. Verify important results in the Packets and Streams views._"]
    return "\n".join(L) + "\n"


# -- JSON -------------------------------------------------------------------------------------------
def build_json(meta: dict, a: dict, redact: bool = False) -> dict:
    creds = [{**c, "secret": _secret(c, True)} if redact else c for c in a["credentials"]]
    out = {"report": {"tool": "SharkAI", "version": __version__, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       "secrets_redacted": redact},
            "capture": {k: meta[k] for k in ("id", "name", "size", "sha256", "uploaded_at")},
            "overview": a["overview"], "flags": a["flags"], "suspicious": a["suspicious"], "credentials": creds,
            "iocs": a["iocs"], "http": [{k: v for k, v in h.items() if k not in ("req_headers", "resp_headers")} for h in a["http"]],
            "dns": a["dns"], "files": a["files"], "streams": a["streams"], "timeline": a["timeline"]["events"], "warnings": a["warnings"]}
    if redact:  # keep the masked credential rows, scrub the literal secret from every other field
        masked = out.pop("credentials")
        out = scrub(out, _secrets(a))
        out["credentials"] = masked
    return out


# -- PDF ----------------------------------------------------------------------------------------------
def _pdf_text(v) -> str:
    s = str(v).encode("latin-1", "replace").decode("latin-1")
    return escape("".join(c if c.isprintable() else "." for c in s))


def build_pdf(meta: dict, a: dict, redact: bool = False) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    d = _prepare(meta, a, redact)
    styles = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=styles["BodyText"], fontSize=9, leading=12)
    cell = ParagraphStyle("c", parent=body, fontSize=7.5, leading=9.5, wordWrap="CJK")
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#0b3a4a"))
    ink, rule = colors.HexColor("#1d2b33"), colors.HexColor("#b9c6cc")
    width = A4[0] - 30 * mm

    def table(headers, rows, weights):
        if not rows:
            return Paragraph("<i>None found.</i>", body)
        data = [[Paragraph(f"<b>{_pdf_text(h)}</b>", cell) for h in headers]] + [[Paragraph(_pdf_text(c)[:300], cell) for c in r] for r in rows]
        total = sum(weights)
        t = Table(data, colWidths=[width * w / total for w in weights], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e3ecef")), ("GRID", (0, 0), (-1, -1), 0.25, rule),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TEXTCOLOR", (0, 0), (-1, -1), ink),
                               ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]))
        return t

    story = [Paragraph(f"SharkAI report: {_pdf_text(meta['name'])}", styles["Title"]),
             Paragraph(f"Generated {_ts(datetime.now(timezone.utc).timestamp())} by SharkAI {__version__}<br/>"
                       f"SHA-256: {meta['sha256']}<br/>Secrets: {'masked' if redact else 'shown - handle this report accordingly'}", body),
             Paragraph("Summary", h2), table(["Metric", "Value"], [list(r) for r in d["summary"]], [2, 3])]
    spec = [("Flag candidates", ["Flag", "Encoding", "Confidence", "Found in"], d["flags"], [5, 2, 2, 5]),
            ("Suspicious activity", ["Severity", "Finding", "Detail"], d["alerts"], [1.5, 4, 8]),
            ("Cleartext credentials", ["Kind", "User", "Secret", "Host", "Packet"], d["credentials"], [2, 3, 4, 4, 1.5]),
            ("Indicators of compromise", ["Type", "Value", "Count", "Scope"], d["iocs"], [2, 9, 1.5, 2]),
            ("HTTP transactions", ["#", "Method", "URL", "Status", "Type", "Bytes"], d["http"], [1, 1.6, 9, 1.4, 3, 1.5]),
            ("DNS queries", ["Name", "Type", "Count", "Client", "Answer"], d["dns"], [6, 1.4, 1.4, 3, 4]),
            ("Extracted files", ["#", "Name", "Type", "Size", "SHA-256", "Source"], d["files"], [1, 3, 2.5, 1.5, 7, 2.5]),
            ("Largest TCP streams", ["#", "Client", "Server", "Protocol", "Bytes", "State"], d["streams"], [1, 4, 4, 2, 1.8, 1.8]),
            ("Timeline", ["Time", "Kind", "Event"], d["timeline"], [2, 2, 10])]
    for title, headers, rows, weights in spec:
        story += [Paragraph(title, h2), table(headers, rows, weights)]
    if d["warnings"]:
        story += [Paragraph("Analysis notes", h2)] + [Paragraph("- " + _pdf_text(w), body) for w in d["warnings"]]
    story += [Spacer(1, 8), Paragraph("<i>Findings are heuristic. Verify important results in the Packets and Streams views.</i>", body)]

    buf = io.BytesIO()

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#5b6b73"))
        canvas.drawString(15 * mm, 8 * mm, f"SharkAI {__version__}")
        canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=16 * mm,
                      title=f"SharkAI report: {meta['name']}", author="SharkAI").build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


def report_filename(meta: dict, ext: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", meta["name"].rsplit(".", 1)[0])[:60] or "capture"
    return f"sharkai-{stem}.{ext}"
