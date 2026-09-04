from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class CaptureStatus(str, Enum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    ERROR = "error"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CaptureUploadResponse(BaseModel):
    id: str
    filename: str
    status: str
    message: str


class CaptureProgress(BaseModel):
    id: str
    status: str
    progress: float
    message: str
    packet_count: int = 0
    tcp_streams: int = 0
    http_sessions: int = 0
    dns_queries: int = 0
    files_count: int = 0
    findings_count: int = 0


class CaptureSummary(BaseModel):
    id: str
    filename: str
    original_name: str
    file_size: int
    status: str
    progress: float
    packet_count: int
    tcp_streams: int
    http_sessions: int
    dns_queries: int
    files_count: int
    findings_count: int
    flags_count: int
    iocs_count: int
    summary: Optional[dict] = None
    created_at: Optional[datetime] = None
    analyzed_at: Optional[datetime] = None


class PacketRow(BaseModel):
    id: int
    frame_number: int
    timestamp: float
    src: str
    dst: str
    protocol: str
    length: int
    info: str
    stream: Optional[int] = None
    severity: str = "info"


class PacketListResponse(BaseModel):
    packets: list[PacketRow]
    total: int
    page: int
    page_size: int


class PacketDetail(BaseModel):
    frame_number: int
    timestamp: float
    layers: list[dict[str, Any]]
    hex_dump: str
    ascii_dump: str
    raw_data: Optional[str] = None


class StreamSummary(BaseModel):
    stream_id: int
    protocol: str
    src: str
    dst: str
    src_port: int
    dst_port: int
    packets: int
    bytes: int
    first_seen: float
    last_seen: float


class StreamContent(BaseModel):
    stream_id: int
    client_to_server: str
    server_to_client: str
    combined: str


class HttpRequest(BaseModel):
    stream_id: int
    packet_number: int
    method: str
    uri: str
    host: str
    user_agent: str = ""
    status_code: Optional[int] = None
    content_type: str = ""
    post_data: str = ""


class DnsQuery(BaseModel):
    packet_number: int
    client: str
    query_name: str
    query_type: str
    response: str = ""
    is_nxdomain: bool = False


class FlagFinding(BaseModel):
    flag: str
    pattern: str
    protocol: str
    stream_id: Optional[int] = None
    packet_numbers: list[int] = Field(default_factory=list)
    confidence: float = 0.0
    decode_chain: list[str] = Field(default_factory=list)
    context: str = ""


class IocItem(BaseModel):
    type: str
    value: str
    source: str
    packet_number: Optional[int] = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    confidence: float
    category: str
    description: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    fact: str = ""
    inference: str = ""
    hypothesis: str = ""


class TimelineEvent(BaseModel):
    timestamp: float
    time_str: str
    event_type: str
    description: str
    packet_number: Optional[int] = None
    stream_id: Optional[int] = None
    severity: str = "info"


class ChatMessage(BaseModel):
    role: str
    content: str


class InvestigationRequest(BaseModel):
    query: str
    mode: str = "expert"
    capture_id: str


class InvestigationResponse(BaseModel):
    id: str
    query: str
    response: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    filter_applied: Optional[str] = None
    intent: Optional[dict[str, Any]] = None
    status: str = "complete"


class SearchRequest(BaseModel):
    query: str
    capture_id: str
    limit: int = 100


class SearchResult(BaseModel):
    category: str
    count: int
    items: list[dict[str, Any]] = Field(default_factory=list)


class FilterRequest(BaseModel):
    capture_id: str
    filter: str
    page: int = 1
    page_size: int = 100


class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    label: str


class NetworkGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class ExportRequest(BaseModel):
    capture_id: str
    format: str = "json"
