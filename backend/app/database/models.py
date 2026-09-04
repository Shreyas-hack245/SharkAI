import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Capture(Base):
    __tablename__ = "captures"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    filename: Mapped[str] = mapped_column(String(512))
    original_name: Mapped[str] = mapped_column(String(512))
    file_path: Mapped[str] = mapped_column(String(1024))
    file_size: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    tcp_streams: Mapped[int] = mapped_column(Integer, default=0)
    http_sessions: Mapped[int] = mapped_column(Integer, default=0)
    dns_queries: Mapped[int] = mapped_column(Integer, default=0)
    files_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    flags_count: Mapped[int] = mapped_column(Integer, default=0)
    iocs_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    analyzed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class Packet(Base):
    __tablename__ = "packets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    capture_id: Mapped[str] = mapped_column(String(36), index=True)
    frame_number: Mapped[int] = mapped_column(Integer, index=True)
    timestamp: Mapped[float] = mapped_column(Float)
    src: Mapped[str] = mapped_column(String(128), default="")
    dst: Mapped[str] = mapped_column(String(128), default="")
    protocol: Mapped[str] = mapped_column(String(64), default="")
    length: Mapped[int] = mapped_column(Integer, default=0)
    info: Mapped[str] = mapped_column(Text, default="")
    stream: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    raw_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    capture_id: Mapped[str] = mapped_column(String(36), index=True)
    query: Mapped[str] = mapped_column(Text)
    response: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
