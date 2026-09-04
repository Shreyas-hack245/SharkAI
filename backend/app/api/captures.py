"""Capture upload and management API."""

import asyncio
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, UploadFile, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import save_upload_file, safe_capture_id
from app.database.models import Capture
from app.database.session import get_db, async_session
from app.models.schemas import CaptureProgress, CaptureSummary, CaptureUploadResponse
from app.services.analysis_service import analysis_service

router = APIRouter(prefix="/api/captures", tags=["captures"])

progress_subscribers: dict[str, list[WebSocket]] = {}


@router.post("/upload", response_model=CaptureUploadResponse)
async def upload_capture(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    settings = get_settings()
    capture_id = str(uuid.uuid4())
    capture_dir = settings.captures_dir / capture_id
    capture_dir.mkdir(parents=True, exist_ok=True)

    dest = capture_dir / (file.filename or "capture.pcap")
    file_size = await save_upload_file(file, dest, settings)

    capture = Capture(
        id=capture_id,
        filename=dest.name,
        original_name=file.filename or "capture.pcap",
        file_path=str(dest),
        file_size=file_size,
        status="pending",
    )
    db.add(capture)
    await db.commit()

    asyncio.create_task(_run_analysis(capture_id))

    return CaptureUploadResponse(
        id=capture_id,
        filename=file.filename or "capture.pcap",
        status="analyzing",
        message="Capture uploaded. Analysis started.",
    )


async def _run_analysis(capture_id: str):
    async with async_session() as db:
        async def on_progress(data):
            subs = progress_subscribers.get(capture_id, [])
            for ws in subs:
                try:
                    await ws.send_json({"type": "progress", **data})
                except Exception:
                    pass

        try:
            await analysis_service.analyze_capture(db, capture_id, on_progress)
            subs = progress_subscribers.get(capture_id, [])
            for ws in subs:
                try:
                    await ws.send_json({"type": "complete", "capture_id": capture_id})
                except Exception:
                    pass
        except Exception as e:
            subs = progress_subscribers.get(capture_id, [])
            for ws in subs:
                try:
                    await ws.send_json({"type": "error", "message": str(e)})
                except Exception:
                    pass


@router.get("/{capture_id}", response_model=CaptureSummary)
async def get_capture(capture_id: str, db: AsyncSession = Depends(get_db)):
    safe_capture_id(capture_id)
    result = await db.execute(select(Capture).where(Capture.id == capture_id))
    capture = result.scalar_one_or_none()
    if not capture:
        from fastapi import HTTPException
        raise HTTPException(404, "Capture not found")
    return CaptureSummary(
        id=capture.id,
        filename=capture.filename,
        original_name=capture.original_name,
        file_size=capture.file_size,
        status=capture.status,
        progress=capture.progress,
        packet_count=capture.packet_count,
        tcp_streams=capture.tcp_streams,
        http_sessions=capture.http_sessions,
        dns_queries=capture.dns_queries,
        files_count=capture.files_count,
        findings_count=capture.findings_count,
        flags_count=capture.flags_count,
        iocs_count=capture.iocs_count,
        summary=capture.summary,
        created_at=capture.created_at,
        analyzed_at=capture.analyzed_at,
    )


@router.get("/{capture_id}/progress", response_model=CaptureProgress)
async def get_progress(capture_id: str, db: AsyncSession = Depends(get_db)):
    safe_capture_id(capture_id)
    result = await db.execute(select(Capture).where(Capture.id == capture_id))
    capture = result.scalar_one_or_none()
    if not capture:
        from fastapi import HTTPException
        raise HTTPException(404, "Capture not found")
    return CaptureProgress(
        id=capture.id,
        status=capture.status,
        progress=capture.progress,
        message=f"Status: {capture.status}",
        packet_count=capture.packet_count,
        tcp_streams=capture.tcp_streams,
        http_sessions=capture.http_sessions,
        dns_queries=capture.dns_queries,
        files_count=capture.files_count,
        findings_count=capture.findings_count,
    )


@router.websocket("/{capture_id}/ws")
async def capture_ws(websocket: WebSocket, capture_id: str):
    await websocket.accept()
    progress_subscribers.setdefault(capture_id, []).append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        progress_subscribers.get(capture_id, []).remove(websocket)
