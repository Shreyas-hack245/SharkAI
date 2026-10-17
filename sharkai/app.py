"""FastAPI application: JSON API + static single-page UI."""
from __future__ import annotations

import hashlib
import logging
import mmap
import re
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__, filters, reports
from .ai import AIClient, answer_question
from .analyzer import analyze_capture, safe_name
from .capture_io import CaptureFormatError, sniff_format
from .config import PREFIX_RE, Settings
from .decode import decode_frame
from .evidence import build_evidence
from .store import CaptureStore, NotFound
from .streams import message_bytes

log = logging.getLogger("sharkai")
WEB_DIR = Path(__file__).parent / "web"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class AskBody(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    use_ai: bool = True
    history: list[dict] = Field(default_factory=list, max_length=12)


class ReanalyzeBody(BaseModel):
    flag_prefixes: list[str] = Field(default_factory=list, max_length=20)


class _FrameReader:
    """Lazily mmaps the original capture so `frame contains "x"` can inspect raw bytes."""

    def __init__(self, path: Path) -> None:
        self.path, self._fh, self._mm = path, None, None

    def __call__(self, p: dict) -> bytes:
        if self._mm is None:
            self._fh = self.path.open("rb")
            self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        return self._mm[p["off"]:p["off"] + p["cap"]]

    def close(self) -> None:
        if self._mm is not None:
            self._mm.close()
            self._fh.close()


def _hexdump(data: bytes, base: int = 0) -> list[str]:
    return [f"{base + i:04x}  {' '.join(f'{b:02x}' for b in data[i:i + 16]):<47}  "
            f"{''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i + 16])}" for i in range(0, len(data), 16)]


def _text(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data)


def create_app(settings: Settings | None = None, ai_transport=None) -> FastAPI:
    from .config import load_settings
    settings = settings or load_settings()
    store = CaptureStore(settings.data_dir)
    ai = AIClient(settings.ai, transport=ai_transport)
    app = FastAPI(title="SharkAI", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.headers.get("x-sharkai") != "1":
                return JSONResponse({"detail": "missing X-SharkAI header"}, status_code=403)
            origin = request.headers.get("origin")
            if origin and origin.split("://", 1)[-1] != request.headers.get("host"):
                return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.exception_handler(NotFound)
    async def _nf(_: Request, exc: NotFound):
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(filters.FilterError)
    async def _fe(_: Request, exc: filters.FilterError):
        return JSONResponse({"detail": str(exc), "position": exc.pos, "kind": "filter"}, status_code=400)

    def ready(cid: str) -> dict:
        meta = store.meta(cid)
        if meta["status"] != "ready":
            raise HTTPException(409, f"capture is {meta['status']}")
        return meta

    def run_analysis(cid: str, prefixes: tuple[str, ...]) -> dict:
        store.update_meta(cid, status="analyzing", error="")
        try:
            a = analyze_capture(store.original(cid), store.path(cid), settings, prefixes)
        except CaptureFormatError as exc:
            store.update_meta(cid, status="error", error=str(exc))
            raise
        except Exception:
            log.exception("analysis failed for %s", cid)
            store.update_meta(cid, status="error", error="analysis failed unexpectedly (see server log)")
            raise HTTPException(500, "analysis failed unexpectedly")
        ov = a["overview"]
        return store.update_meta(cid, status="ready", error="", format=ov["format"], packets=ov["packets"],
                                 duration=ov["duration"], flags=ov["flags"], suspicious=ov["suspicious"],
                                 flag_prefixes=ov["flag_prefixes"])

    # ---- meta ----------------------------------------------------------------------------
    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/config")
    def config():
        c = settings.ai
        return {"version": __version__, "max_upload_mb": settings.max_upload_mb, "flag_prefixes": list(settings.flag_prefixes),
                "ai": {"provider": c.provider if c.enabled else "none", "model": c.model if c.enabled else "",
                       "configured": c.enabled, "redact_secrets": c.redact_secrets}}

    @app.post("/api/ai/test")
    def ai_test():
        return ai.ping()

    @app.get("/api/filters/help")
    def filter_help():
        return filters.describe()

    # ---- captures ------------------------------------------------------------------------
    @app.get("/api/captures")
    def list_captures():
        return store.list()

    @app.post("/api/captures", status_code=201)
    async def upload(request: Request, filename: str = Query("capture.pcap", max_length=255),
                     flag_prefix: list[str] = Query(default=[], max_length=20)):
        for p in flag_prefix:
            if not PREFIX_RE.match(p):
                raise HTTPException(400, f"invalid flag prefix {p!r}: use letters, digits or underscores (max 24)")
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > settings.max_upload_bytes:
            raise HTTPException(413, f"file exceeds the {settings.max_upload_mb} MB limit")
        cid, dest = store.begin(filename)
        size, head, sha = 0, b"", hashlib.sha256()
        try:
            with dest.open("wb") as fh:
                async for chunk in request.stream():
                    if len(head) < 4:
                        head += chunk[:4 - len(head)]
                        if len(head) >= 4 and sniff_format(head) is None:
                            raise HTTPException(415, "not a pcap/pcapng capture (.pcap, .pcapng and .cap with libpcap/pcapng data are supported)")
                    size += len(chunk)
                    if size > settings.max_upload_bytes:
                        raise HTTPException(413, f"file exceeds the {settings.max_upload_mb} MB limit")
                    sha.update(chunk)
                    fh.write(chunk)
            if size < 24 or sniff_format(head) is None:
                raise HTTPException(415, "not a pcap/pcapng capture")
            dest.chmod(0o600)
            store.update_meta(cid, size=size, sha256=sha.hexdigest(), status="queued")
            return await run_in_threadpool(run_analysis, cid, tuple(flag_prefix))
        except CaptureFormatError as exc:
            store.abort(cid)
            raise HTTPException(422, str(exc))
        except BaseException:
            if store.meta(cid)["status"] not in ("ready",):
                store.abort(cid)
            raise

    @app.get("/api/captures/{cid}")
    def get_capture(cid: str):
        meta = ready(cid)
        return {"meta": meta, "overview": store.analysis(cid)["overview"], "warnings": store.analysis(cid)["warnings"]}

    @app.delete("/api/captures/{cid}", status_code=204)
    def delete_capture(cid: str):
        store.delete(cid)

    @app.post("/api/captures/{cid}/reanalyze")
    def reanalyze(cid: str, body: ReanalyzeBody):
        store.meta(cid)
        for p in body.flag_prefixes:
            if not PREFIX_RE.match(p):
                raise HTTPException(400, f"invalid flag prefix {p!r}")
        return run_analysis(cid, tuple(body.flag_prefixes))

    # ---- packets -------------------------------------------------------------------------
    @app.get("/api/captures/{cid}/packets")
    def packets(cid: str, filter: str = Query("", max_length=400), offset: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=1000)):
        ready(cid)
        reader = _FrameReader(store.original(cid))
        try:
            pred = filters.compile_filter(filter, reader)
            matched = [p for p in store.packets(cid) if pred(p)] if filter.strip() else store.packets(cid)
        finally:
            reader.close()
        keys = ("n", "rel", "src", "dst", "proto", "length", "info", "stream", "sport", "dport", "l4")
        return {"total": len(matched), "offset": offset,
                "packets": [{k: p[k] for k in keys if k in p} for p in matched[offset:offset + limit]]}

    @app.get("/api/captures/{cid}/packets/{n}")
    def packet_detail(cid: str, n: int):
        ready(cid)
        pk = store.packets(cid)
        if not 1 <= n <= len(pk):
            raise NotFound("packet not found")
        p = pk[n - 1]
        reader = _FrameReader(store.original(cid))
        try:
            frame = reader(p)
        finally:
            reader.close()
        d = decode_frame(frame, p["lt"])
        layers = [{"name": "Frame", "fields": [["Number", p["n"]], ["Length", f"{p['length']} bytes ({p['cap']} captured)"], ["Link type", p["lt"]]]}]
        if d.eth_src:
            layers.append({"name": "Ethernet", "fields": [["Source", d.eth_src], ["Destination", d.eth_dst]] + ([["VLAN", d.vlan]] if d.vlan is not None else [])})
        if d.l3 in ("IPv4", "IPv6"):
            layers.append({"name": d.l3, "fields": [["Source", d.src], ["Destination", d.dst], ["TTL / hop limit", d.ttl], ["Header length", d.ip_header_len]]})
        if d.l4 == "TCP":
            layers.append({"name": "TCP", "fields": [["Source port", d.sport], ["Destination port", d.dport], ["Flags", d.flag_names or "-"],
                                                      ["Sequence", d.seq], ["Acknowledgment", d.ack], ["Window", d.win], ["Payload", f"{len(d.payload)} bytes"]]})
        elif d.l4 == "UDP":
            layers.append({"name": "UDP", "fields": [["Source port", d.sport], ["Destination port", d.dport], ["Payload", f"{len(d.payload)} bytes"]]})
        elif d.l4 in ("ICMP", "ICMPv6"):
            layers.append({"name": d.l4, "fields": [["Type", d.icmp_type], ["Code", d.icmp_code], ["Payload", f"{len(d.payload)} bytes"]]})
        elif d.l4 == "ARP":
            layers.append({"name": "ARP", "fields": [["Detail", d.info]]})
        if d.dns:
            fields = [["Transaction ID", f"0x{d.dns['id']:04x}"], ["Type", "response" if d.dns["response"] else "query"], ["Response code", d.dns["rcode"]]]
            fields += [["Question", f"{q['name']} {q['type']}"] for q in d.dns["questions"]] + [["Answer", f"{a['name']} {a['type']} {a['data']}"] for a in d.dns["answers"]]
            layers.append({"name": "DNS", "fields": fields})
        elif d.http:
            layers.append({"name": "HTTP", "fields": [[k.capitalize(), v] for k, v in d.http.items()]})
        elif d.sni:
            layers.append({"name": "TLS", "fields": [["Server name (SNI)", d.sni]]})
        return {"summary": {k: v for k, v in p.items() if k not in ("off", "cap", "lt")}, "layers": layers,
                "hex": _hexdump(frame[:4096]), "truncated": len(frame) > 4096,
                "payload_text": _text(d.payload[:2000]) if d.payload else ""}

    # ---- streams ---------------------------------------------------------------------------
    @app.get("/api/captures/{cid}/streams")
    def streams(cid: str):
        ready(cid)
        return store.analysis(cid)["streams"]

    @app.get("/api/captures/{cid}/streams/{sid}")
    def stream_view(cid: str, sid: int, format: str = Query("text", pattern="^(text|hex)$"), limit: int = Query(200_000, ge=1000, le=2_000_000)):
        ready(cid)
        meta = next((s for s in store.analysis(cid)["streams"] if s["id"] == sid), None)
        if meta is None:
            raise NotFound("stream not found")
        msgs = store.stream_messages(cid, sid) if (meta["bytes_c2s"] or meta["bytes_s2c"]) else []
        data = [store.stream_bytes(cid, sid, 0) if meta["bytes_c2s"] else b"", store.stream_bytes(cid, sid, 1) if meta["bytes_s2c"] else b""]
        out, used, truncated = [], 0, False
        for m in msgs:
            chunk = message_bytes(data[m["dir"]], m)
            if used + len(chunk) > limit:
                chunk, truncated = chunk[: max(0, limit - used)], True
            used += len(chunk)
            out.append({"dir": m["dir"], "packet": m["pkt"], "ts": m["ts"], "length": m["length"],
                        "text": "\n".join(_hexdump(chunk, m["start"])) if format == "hex" else _text(chunk)})
            if truncated:
                break
        return {"stream": meta, "messages": out, "truncated": truncated}

    @app.get("/api/captures/{cid}/streams/{sid}/raw")
    def stream_raw(cid: str, sid: int, dir: int = Query(0, ge=0, le=1)):
        ready(cid)
        return Response(store.stream_bytes(cid, sid, dir), media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="stream-{sid}-{"s2c" if dir else "c2s"}.bin"'})

    # ---- derived views -------------------------------------------------------------------
    @app.get("/api/captures/{cid}/http")
    def http(cid: str):
        ready(cid)
        return store.analysis(cid)["http"]

    @app.get("/api/captures/{cid}/dns")
    def dns(cid: str, q: str = Query("", max_length=100), offset: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=1000)):
        ready(cid)
        items = store.analysis(cid)["dns"]
        if q:
            ql = q.lower()
            items = [e for e in items if ql in e["qname"].lower() or any(ql in a.lower() for a in e["answers"])]
        return {"total": len(items), "items": items[offset:offset + limit]}

    @app.get("/api/captures/{cid}/files")
    def files(cid: str):
        ready(cid)
        return store.analysis(cid)["files"]

    @app.get("/api/captures/{cid}/files/{fid}")
    def file_download(cid: str, fid: int):
        ready(cid)
        rec = next((f for f in store.analysis(cid)["files"] if f["id"] == fid), None)
        if rec is None:
            raise NotFound("file not found")
        name = safe_name(rec["name"], f"file-{fid}")
        return Response(store.file_bytes(cid, fid), media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    for route in ("iocs", "flags", "timeline", "graph", "credentials", "suspicious"):
        def make(route=route):
            @app.get(f"/api/captures/{{cid}}/{route}", name=route)
            def view(cid: str):
                ready(cid)
                return store.analysis(cid)[route]
        make()

    # ---- AI -------------------------------------------------------------------------------
    @app.get("/api/captures/{cid}/evidence")
    def evidence(cid: str, question: str = Query("summarize this capture", max_length=1000)):
        ready(cid)
        b = build_evidence(store.analysis(cid), question, redact=settings.ai.redact_secrets, max_chars=settings.ai.max_evidence_chars)
        return {"question": question, "chars": b["chars"], "counts": b["counts"], "intents": b["intents"], "evidence": b["evidence"]}

    @app.post("/api/captures/{cid}/ask")
    def ask(cid: str, body: AskBody):
        ready(cid)
        return answer_question(store.analysis(cid), body.question, ai, use_ai=body.use_ai, history=body.history)

    # ---- reports -------------------------------------------------------------------------------
    @app.get("/api/captures/{cid}/report")
    def report(cid: str, format: str = Query("md", pattern="^(md|json|pdf)$"), redact: bool = False, download: bool = True):
        meta = ready(cid)
        a = store.analysis(cid)
        if format == "pdf":
            body, mime = reports.build_pdf(meta, a, redact), "application/pdf"
        elif format == "json":
            import json
            body, mime = json.dumps(reports.build_json(meta, a, redact), indent=2).encode(), "application/json"
        else:
            body, mime = reports.build_markdown(meta, a, redact).encode(), "text/markdown; charset=utf-8"
        headers = {"Content-Disposition": f'{"attachment" if download else "inline"}; filename="{reports.report_filename(meta, format)}"'}
        return Response(body, media_type=mime, headers=headers)

    app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB_DIR / "index.html", media_type="text/html")

    return app
