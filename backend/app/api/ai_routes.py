"""AI investigation and chat API."""

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agent import InvestigationAgent
from app.core.security import safe_capture_id
from app.database.models import Capture, Investigation
from app.database.session import get_db, async_session
from app.models.schemas import InvestigationRequest, InvestigationResponse, SearchRequest

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.post("/investigate", response_model=InvestigationResponse)
async def investigate(
    body: InvestigationRequest,
    db: AsyncSession = Depends(get_db),
):
    safe_capture_id(body.capture_id)
    result = await db.execute(select(Capture).where(Capture.id == body.capture_id))
    capture = result.scalar_one_or_none()
    if not capture:
        raise HTTPException(404, "Capture not found")
    if capture.status != "complete":
        raise HTTPException(400, f"Capture not ready (status: {capture.status})")

    investigation_id = str(uuid.uuid4())
    inv = Investigation(
        id=investigation_id,
        capture_id=body.capture_id,
        query=body.query,
        status="running",
    )
    db.add(inv)
    await db.commit()

    agent = InvestigationAgent(body.capture_id, capture.file_path, body.mode)
    result_data = await agent.investigate(body.query)

    inv.response = result_data.get("response", "")
    inv.evidence = result_data.get("evidence")
    inv.status = "complete"
    await db.commit()

    return InvestigationResponse(
        id=investigation_id,
        query=body.query,
        response=result_data.get("response", ""),
        evidence=result_data.get("evidence", []),
        filter_applied=result_data.get("filter_applied"),
        intent=result_data.get("intent"),
        status="complete",
    )


@router.post("/search")
async def global_search(body: SearchRequest, db: AsyncSession = Depends(get_db)):
    safe_capture_id(body.capture_id)
    result = await db.execute(select(Capture).where(Capture.id == body.capture_id))
    capture = result.scalar_one_or_none()
    if not capture:
        raise HTTPException(404, "Capture not found")

    query = body.query
    results = {}

    packets = analysis_service.packet_analyzer.search_payloads(
        capture.file_path, query, body.limit
    )
    results["packets"] = {"count": len(packets), "items": packets}

    summary = analysis_service.get_cached_summary(body.capture_id) or {}
    http_matches = [
        r for r in summary.get("http_requests", [])
        if query.lower() in str(r).lower()
    ]
    results["http"] = {"count": len(http_matches), "items": http_matches}

    cred_matches = [
        c for c in summary.get("credentials", [])
        if query.lower() in str(c).lower()
    ]
    results["credentials"] = {"count": len(cred_matches), "items": cred_matches}

    flag_matches = [
        f for f in summary.get("flags", [])
        if query.lower() in str(f).lower()
    ]
    results["flags"] = {"count": len(flag_matches), "items": flag_matches}

    return results


from app.services.analysis_service import analysis_service  # noqa: E402


investigation_ws_subscribers: dict[str, WebSocket] = {}


@router.websocket("/investigate/ws")
async def investigate_ws(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        capture_id = data.get("capture_id", "")
        query = data.get("query", "")
        mode = data.get("mode", "expert")

        safe_capture_id(capture_id)

        async with async_session() as db:
            result = await db.execute(select(Capture).where(Capture.id == capture_id))
            capture = result.scalar_one_or_none()
            if not capture:
                await websocket.send_json({"type": "error", "message": "Capture not found"})
                return

            agent = InvestigationAgent(capture_id, capture.file_path, mode)

            async def on_progress(step_data):
                await websocket.send_json({"type": "progress", **step_data})

            result_data = await agent.investigate(query, on_progress)

            await websocket.send_json({
                "type": "complete",
                "response": result_data.get("response", ""),
                "evidence": result_data.get("evidence", []),
                "intent": result_data.get("intent"),
                "steps": result_data.get("steps", []),
            })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
