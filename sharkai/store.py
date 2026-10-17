"""On-disk capture storage. Each capture lives in data/captures/<32-hex-id>/ and nothing user-supplied
ever becomes part of a path: the original upload is saved as `original.bin`, display names are only
metadata, and every id is validated against a strict pattern before use."""
from __future__ import annotations

import json
import os
import re
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

CAPTURE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class NotFound(LookupError):
    pass


def display_name(name: str) -> str:
    name = re.split(r"[\\/]", name or "")[-1]
    name = re.sub(r"[^A-Za-z0-9._ ()\-]", "_", name).strip(" .")[:120]
    return name or "capture.pcap"


class CaptureStore:
    def __init__(self, data_dir: Path) -> None:
        self.root = Path(data_dir) / "captures"
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        self._lock = threading.Lock()
        self._cache: dict[tuple, object] = {}

    # -- paths -----------------------------------------------------------------------------
    def path(self, cid: str) -> Path:
        if not isinstance(cid, str) or not CAPTURE_ID_RE.match(cid):
            raise NotFound("capture not found")
        p = self.root / cid
        if not p.is_dir():
            raise NotFound("capture not found")
        return p

    def original(self, cid: str) -> Path:
        return self.path(cid) / "original.bin"

    # -- lifecycle -----------------------------------------------------------------------
    def begin(self, filename: str) -> tuple[str, Path]:
        cid = uuid.uuid4().hex
        d = self.root / cid
        d.mkdir(mode=0o700)
        self.write_meta(cid, {"id": cid, "name": display_name(filename), "size": 0, "sha256": "",
                              "uploaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                              "status": "uploading", "error": ""})
        return cid, d / "original.bin"

    def abort(self, cid: str) -> None:
        shutil.rmtree(self.root / cid, ignore_errors=True)

    def delete(self, cid: str) -> None:
        shutil.rmtree(self.path(cid))
        with self._lock:
            self._cache = {k: v for k, v in self._cache.items() if k[0] != cid}

    # -- metadata -----------------------------------------------------------------------
    def write_meta(self, cid: str, meta: dict) -> None:
        p = self.root / cid / "meta.json"
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(meta), encoding="utf-8")
        os.replace(tmp, p)

    def meta(self, cid: str) -> dict:
        return json.loads((self.path(cid) / "meta.json").read_text(encoding="utf-8"))

    def update_meta(self, cid: str, **changes) -> dict:
        m = self.meta(cid)
        m.update(changes)
        self.write_meta(cid, m)
        return m

    def list(self) -> list[dict]:
        out = []
        for d in self.root.iterdir():
            if CAPTURE_ID_RE.match(d.name) and (d / "meta.json").is_file():
                try:
                    out.append(json.loads((d / "meta.json").read_text(encoding="utf-8")))
                except (OSError, ValueError):
                    continue
        return sorted(out, key=lambda m: m.get("uploaded_at", ""), reverse=True)

    # -- analysis artefacts (small cache keyed on file mtime) ----------------------------------
    def _load(self, cid: str, name: str):
        p = self.path(cid) / name
        try:
            key = (cid, name, p.stat().st_mtime_ns)
        except FileNotFoundError:
            raise NotFound("analysis not available yet") from None
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        data = json.loads(p.read_text(encoding="utf-8"))
        with self._lock:
            self._cache = {k: v for k, v in self._cache.items() if not (k[0] == cid and k[1] == name)}
            if len(self._cache) > 6:
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = data
        return data

    def analysis(self, cid: str) -> dict:
        return self._load(cid, "analysis.json")

    def packets(self, cid: str) -> list[dict]:
        return self._load(cid, "packets.json")

    def stream_messages(self, cid: str, sid: int) -> list[dict]:
        p = self.path(cid) / "streams" / f"{int(sid)}.json"
        if not p.is_file():
            raise NotFound("stream has no payload")
        return json.loads(p.read_text(encoding="utf-8"))

    def stream_bytes(self, cid: str, sid: int, direction: int) -> bytes:
        p = self.path(cid) / "streams" / f"{int(sid)}.{1 if direction else 0}"
        if not p.is_file():
            raise NotFound("stream has no payload")
        return p.read_bytes()

    def file_bytes(self, cid: str, fid: int) -> bytes:
        p = self.path(cid) / "files" / f"{int(fid)}.bin"
        if not p.is_file():
            raise NotFound("file not found")
        return p.read_bytes()
