"""Packet and stream analysis API."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import safe_capture_id, validate_display_filter
from app.database.models import Capture
from app.database.session import get_db
from app.models.schemas import (
    FilterRequest, PacketDetail, PacketListResponse, PacketRow,
    StreamContent, StreamSummary,
)
from app.services.analysis_service import analysis_service

router = APIRouter(prefix="/api", tags=["analysis"])


@router.get("/captures/{capture_id}/packets", response_model=PacketListResponse)
async def list_packets(
    capture_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    filter: str = Query(""),
    search: str = Query(""),
    db: AsyncSession = Depends(get_db),
):
    safe_capture_id(capture_id)
    if filter:
        valid, err = validate_display_filter(filter)
        if not valid:
            raise HTTPException(400, f"Invalid filter: {err}")

    packets, total = await analysis_service.get_packets(
        db, capture_id, page, page_size, filter, search
    )
    return PacketListResponse(
        packets=[
            PacketRow(
                id=p.id,
                frame_number=p.frame_number,
                timestamp=p.timestamp,
                src=p.src,
                dst=p.dst,
                protocol=p.protocol,
                length=p.length,
                info=p.info,
                stream=p.stream,
                severity=p.severity,
            )
            for p in packets
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/captures/{capture_id}/packets/{frame_number}", response_model=PacketDetail)
async def get_packet_detail(
    capture_id: str,
    frame_number: int,
    db: AsyncSession = Depends(get_db),
):
    safe_capture_id(capture_id)
    result = await db.execute(select(Capture).where(Capture.id == capture_id))
    capture = result.scalar_one_or_none()
    if not capture:
        raise HTTPException(404, "Capture not found")

    detail = await analysis_service.get_packet_detail(capture.file_path, frame_number)
    return PacketDetail(**detail)


@router.get("/captures/{capture_id}/streams")
async def list_streams(capture_id: str, db: AsyncSession = Depends(get_db)):
    safe_capture_id(capture_id)
    result = await db.execute(select(Capture).where(Capture.id == capture_id))
    capture = result.scalar_one_or_none()
    if not capture:
        raise HTTPException(404, "Capture not found")

    streams = await analysis_service.list_streams(capture.file_path)
    return {"streams": streams, "count": len(streams)}


@router.get("/captures/{capture_id}/streams/{stream_id}")
async def follow_stream(
    capture_id: str, stream_id: int, db: AsyncSession = Depends(get_db)
):
    safe_capture_id(capture_id)
    result = await db.execute(select(Capture).where(Capture.id == capture_id))
    capture = result.scalar_one_or_none()
    if not capture:
        raise HTTPException(404, "Capture not found")

    content = await analysis_service.follow_stream(capture.file_path, stream_id)
    return content


@router.post("/captures/{capture_id}/filter")
async def filter_packets(
    capture_id: str,
    body: FilterRequest,
    db: AsyncSession = Depends(get_db),
):
    safe_capture_id(capture_id)
    valid, err = validate_display_filter(body.filter)
    if not valid:
        raise HTTPException(400, f"Invalid filter: {err}")

    packets, total = await analysis_service.get_packets(
        db, capture_id, body.page, body.page_size, body.filter
    )
    return PacketListResponse(
        packets=[
            PacketRow(
                id=p.id, frame_number=p.frame_number, timestamp=p.timestamp,
                src=p.src, dst=p.dst, protocol=p.protocol, length=p.length,
                info=p.info, stream=p.stream, severity=p.severity,
            )
            for p in packets
        ],
        total=total, page=body.page, page_size=body.page_size,
    )


@router.get("/captures/{capture_id}/summary")
async def get_full_summary(capture_id: str):
    safe_capture_id(capture_id)
    summary = analysis_service.get_cached_summary(capture_id)
    if not summary:
        raise HTTPException(404, "Analysis not complete or not found")
    return summary


@router.get("/captures/{capture_id}/timeline")
async def get_timeline(capture_id: str):
    safe_capture_id(capture_id)
    return {"events": analysis_service.build_timeline(capture_id)}


@router.get("/captures/{capture_id}/graph")
async def get_graph(capture_id: str):
    safe_capture_id(capture_id)
    return analysis_service.build_graph(capture_id)


@router.get("/captures/{capture_id}/flags")
async def get_flags(capture_id: str, db: AsyncSession = Depends(get_db)):
    safe_capture_id(capture_id)
    summary = analysis_service.get_cached_summary(capture_id)
    if summary:
        return {"flags": summary.get("flags", [])}
    result = await db.execute(select(Capture).where(Capture.id == capture_id))
    capture = result.scalar_one_or_none()
    if not capture:
        raise HTTPException(404, "Capture not found")
    flags = analysis_service.flag_analyzer.search_flags(capture.file_path)
    return {"flags": flags}


@router.get("/captures/{capture_id}/iocs")
async def get_iocs(capture_id: str, format: str = "json"):
    safe_capture_id(capture_id)
    summary = analysis_service.get_cached_summary(capture_id)
    iocs = summary.get("iocs", []) if summary else []
    if format == "csv":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(analysis_service.ioc_analyzer.export_csv(iocs))
    if format == "txt":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(analysis_service.ioc_analyzer.export_txt(iocs))
    return {"iocs": iocs}


@router.get("/captures/{capture_id}/findings")
async def get_findings(capture_id: str):
    safe_capture_id(capture_id)
    summary = analysis_service.get_cached_summary(capture_id)
    if not summary:
        raise HTTPException(404, "Analysis not complete")
    return {"findings": summary.get("findings", [])}
