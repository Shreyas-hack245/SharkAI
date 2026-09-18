"""Analysis service orchestrating all analyzers."""

import asyncio
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from sqlalchemy import or_, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.models import Capture, Packet

# Add analyzers to path
ANALYZERS_DIR = Path(__file__).resolve().parents[3] / "analyzers"
if str(ANALYZERS_DIR.parent) not in sys.path:
    sys.path.insert(0, str(ANALYZERS_DIR.parent))

from analyzers.packet_analyzer import PacketAnalyzer, TsharkError
from analyzers.stream_analyzer import StreamAnalyzer
from analyzers.http_analyzer import HttpAnalyzer
from analyzers.dns_analyzer import DnsAnalyzer
from analyzers.flag_analyzer import FlagAnalyzer
from analyzers.ioc_analyzer import IocAnalyzer
from analyzers.file_analyzer import FileAnalyzer


class AnalysisService:
    def __init__(self):
        settings = get_settings()
        self.settings = settings
        self.packet_analyzer = PacketAnalyzer(settings.tshark_path, settings.analysis_timeout_seconds)
        tshark_path = self.packet_analyzer.tshark_path
        self.stream_analyzer = StreamAnalyzer(tshark_path, settings.analysis_timeout_seconds)
        self.http_analyzer = HttpAnalyzer(tshark_path, settings.analysis_timeout_seconds)
        self.dns_analyzer = DnsAnalyzer(tshark_path, settings.analysis_timeout_seconds)
        self.flag_analyzer = FlagAnalyzer(tshark_path, settings.analysis_timeout_seconds)
        self.ioc_analyzer = IocAnalyzer(tshark_path, settings.analysis_timeout_seconds)
        self.file_analyzer = FileAnalyzer(tshark_path, settings.analysis_timeout_seconds)

        self._cache: dict[str, dict] = {}

    @property
    def tshark_available(self) -> bool:
        return self.packet_analyzer.available

    async def analyze_capture(
        self,
        db: AsyncSession,
        capture_id: str,
        progress_callback: Optional[Callable] = None,
    ) -> dict[str, Any]:
        result = await db.execute(select(Capture).where(Capture.id == capture_id))
        capture = result.scalar_one_or_none()
        if not capture:
            raise ValueError(f"Capture {capture_id} not found")

        capture.status = "analyzing"
        capture.progress = 0.0
        await db.commit()

        async def update_progress(pct: float, msg: str, **counts):
            capture.progress = pct
            for k, v in counts.items():
                if hasattr(capture, k):
                    setattr(capture, k, v)
            await db.commit()
            if progress_callback:
                await progress_callback({"progress": pct, "message": msg, **counts})

        try:
            if not self.tshark_available:
                raise TsharkError(
                    "tshark not found. Install Wireshark from https://www.wireshark.org/download.html"
                )

            pcap_path = capture.file_path

            # Step 1: Index packets
            await update_progress(10, "Indexing packets...")
            packets = await asyncio.to_thread(
                self.packet_analyzer.extract_packets, pcap_path
            )
            packet_count = len(packets)

            # Store packets in DB (batch insert)
            await update_progress(30, f"Storing {packet_count} packets...", packet_count=packet_count)
            batch_size = 500
            for i in range(0, len(packets), batch_size):
                batch = packets[i:i + batch_size]
                for pkt in batch:
                    db.add(Packet(
                        capture_id=capture_id,
                        frame_number=pkt["frame_number"],
                        timestamp=pkt["timestamp"],
                        src=pkt["src"],
                        dst=pkt["dst"],
                        protocol=pkt["protocol"],
                        length=pkt["length"],
                        info=pkt["info"],
                        stream=pkt.get("stream"),
                        severity=pkt.get("severity", "info"),
                        raw_json=pkt.get("raw"),
                    ))
                await db.commit()

            # Step 2: TCP streams
            await update_progress(45, "Analyzing TCP streams...")
            streams = await asyncio.to_thread(self.stream_analyzer.list_tcp_streams, pcap_path)
            tcp_count = len(streams)

            # Step 3: HTTP
            await update_progress(55, "Analyzing HTTP traffic...")
            http_requests = await asyncio.to_thread(self.http_analyzer.extract_requests, pcap_path)
            http_count = len(http_requests)
            credentials = await asyncio.to_thread(self.http_analyzer.find_credentials, pcap_path)
            suspicious_http = await asyncio.to_thread(
                self.http_analyzer.find_suspicious_requests, pcap_path
            )

            # Step 4: DNS
            await update_progress(65, "Analyzing DNS traffic...")
            dns_queries = await asyncio.to_thread(self.dns_analyzer.extract_queries, pcap_path)
            dns_count = len(dns_queries)
            suspicious_dns = await asyncio.to_thread(self.dns_analyzer.detect_suspicious, pcap_path)

            # Step 5: Files
            await update_progress(75, "Extracting files...")
            files = await asyncio.to_thread(self.file_analyzer.extract_files, pcap_path)

            # Step 6: Flag search
            await update_progress(82, "Searching for flags...")
            flags = await asyncio.to_thread(self.flag_analyzer.search_flags, pcap_path)

            # Step 7: IOC extraction
            await update_progress(90, "Extracting IOCs...")
            iocs = await asyncio.to_thread(self.ioc_analyzer.extract_all, pcap_path)

            # Step 8: Security triage
            await update_progress(95, "Running security triage...")
            protocol_stats = await asyncio.to_thread(
                self.packet_analyzer.get_protocol_stats, pcap_path
            )
            top_talkers = await asyncio.to_thread(
                self.packet_analyzer.get_top_talkers, pcap_path
            )

            findings = self._build_findings(
                credentials, suspicious_http, suspicious_dns, flags, streams
            )

            summary = {
                "protocol_stats": protocol_stats,
                "top_talkers": top_talkers,
                "http_requests": http_requests[:100],
                "dns_queries": dns_queries[:100],
                "streams": streams[:100],
                "files": files,
                "flags": flags,
                "iocs": iocs[:200],
                "credentials": credentials,
                "findings": findings,
                "suspicious_dns": suspicious_dns,
            }

            self._cache[capture_id] = summary

            capture.status = "complete"
            capture.progress = 100.0
            capture.packet_count = packet_count
            capture.tcp_streams = tcp_count
            capture.http_sessions = http_count
            capture.dns_queries = dns_count
            capture.files_count = len(files)
            capture.findings_count = len(findings)
            capture.flags_count = len(flags)
            capture.iocs_count = len(iocs)
            capture.summary = {
                "protocol_stats": protocol_stats,
                "top_talkers": top_talkers,
                "findings_count": len(findings),
            }
            capture.analyzed_at = datetime.now(timezone.utc)
            await db.commit()

            await update_progress(100, "Analysis complete!", packet_count=packet_count,
                                  tcp_streams=tcp_count, http_sessions=http_count,
                                  dns_queries=dns_count, files_count=len(files),
                                  findings_count=len(findings))

            return summary

        except Exception as e:
            capture.status = "error"
            capture.error_message = str(e)
            await db.commit()
            raise

    def _build_findings(self, credentials, suspicious_http, suspicious_dns, flags, streams) -> list[dict]:
        findings = []

        for cred in credentials:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": f"Credential exposure ({cred.get('type', 'unknown')})",
                "severity": "high",
                "confidence": cred.get("confidence", 0.9),
                "category": "credentials",
                "description": f"Possible {cred.get('type')} found in plaintext",
                "evidence": [cred],
                "fact": f"Found {cred.get('type')} in packet {cred.get('packet_number')}",
                "inference": "Credentials may have been transmitted insecurely",
            })

        for req in suspicious_http:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "Suspicious HTTP request",
                "severity": req.get("severity", "medium"),
                "confidence": req.get("confidence", 0.75),
                "category": "http",
                "description": "; ".join(req.get("reasons", [])),
                "evidence": [req],
                "fact": f"{req.get('method', '')} {req.get('uri', '')} in packet {req.get('packet_number')}",
            })

        for dns in suspicious_dns:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "Suspicious DNS activity",
                "severity": dns.get("severity", "medium"),
                "confidence": dns.get("confidence", 0.7),
                "category": "dns",
                "description": "; ".join(dns.get("reasons", [])),
                "evidence": [dns],
            })

        for flag in flags:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": f"Flag found: {flag.get('flag', '')[:50]}",
                "severity": "high",
                "confidence": flag.get("confidence", 0.99),
                "category": "ctf",
                "description": f"Flag detected via {flag.get('pattern', 'unknown')} pattern",
                "evidence": [flag],
                "fact": f"Flag '{flag.get('flag')}' found in {flag.get('protocol', 'unknown')}",
            })

        # Large transfers
        for stream in streams:
            if stream.get("bytes", 0) > 10_000_000:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": "Large data transfer",
                    "severity": "medium",
                    "confidence": 0.7,
                    "category": "network",
                    "description": f"{stream['bytes'] / 1_000_000:.1f} MB transferred",
                    "evidence": [stream],
                    "fact": f"Stream #{stream['stream_id']}: {stream['src']} → {stream['dst']}",
                })

        return findings

    def get_cached_summary(self, capture_id: str) -> Optional[dict]:
        return self._cache.get(capture_id)

    async def get_packets(
        self, db: AsyncSession, capture_id: str,
        page: int = 1, page_size: int = 100,
        display_filter: str = "", search: str = "",
    ) -> tuple[list, int]:
        query = select(Packet).where(Packet.capture_id == capture_id)

        if search:
            query = query.where(
                Packet.info.ilike(f"%{search}%") |
                Packet.src.ilike(f"%{search}%") |
                Packet.dst.ilike(f"%{search}%") |
                Packet.protocol.ilike(f"%{search}%")
            )

        if display_filter:
            filter_clause = self._packet_filter_clause(display_filter)
            if filter_clause is not None:
                query = query.where(filter_clause)

        count_query = select(func.count()).select_from(query.subquery())
        total = (await db.execute(count_query)).scalar() or 0

        query = query.order_by(Packet.frame_number)
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(query)
        packets = result.scalars().all()
        return packets, total

    @staticmethod
    def _packet_filter_clause(display_filter: str):
        """Map the documented filter subset to indexed packet metadata.

        More specialised filters are used by tshark within the analysis tools;
        this mapping keeps the paginated packet table fast without pretending a
        filter was applied when its indexed fields are unavailable.
        """
        expr = display_filter.strip()
        protocol = expr.lower()
        if protocol in {"tcp", "udp", "http", "dns", "icmp", "tls", "ssl", "ftp", "smtp", "arp", "sctp"}:
            return Packet.protocol.ilike(protocol)

        match = re.fullmatch(r"(ip\.(?:addr|src|dst)|ipv6\.(?:addr|src|dst)|http\.request\.method|http\.host|http\.request\.uri|dns\.qry\.name)\s*(==|!=|contains|matches)\s*(.+)", expr, re.IGNORECASE)
        if not match:
            return None
        field, operator, value = match.groups()
        value = value.strip().strip('"\'')
        field = field.lower()
        if field.endswith(".src"):
            column = Packet.src
        elif field.endswith(".dst"):
            column = Packet.dst
        elif field.endswith(".addr"):
            clause = or_(Packet.src == value, Packet.dst == value)
            return ~clause if operator == "!=" else clause
        else:
            column = Packet.info

        if operator == "==":
            return column == value if field.endswith((".src", ".dst")) else column.ilike(f"%{value}%")
        if operator == "!=":
            return column != value if field.endswith((".src", ".dst")) else ~column.ilike(f"%{value}%")
        return column.ilike(f"%{value}%")

    async def get_packet_detail(self, pcap_path: str, frame_number: int) -> dict:
        return await asyncio.to_thread(
            self.packet_analyzer.get_packet_detail, pcap_path, frame_number
        )

    async def follow_stream(self, pcap_path: str, stream_id: int) -> dict:
        return await asyncio.to_thread(
            self.stream_analyzer.follow_tcp_stream, pcap_path, stream_id
        )

    async def list_streams(self, pcap_path: str) -> list:
        return await asyncio.to_thread(self.stream_analyzer.list_tcp_streams, pcap_path)

    def build_timeline(self, capture_id: str) -> list[dict]:
        summary = self._cache.get(capture_id, {})
        events = []

        for req in summary.get("http_requests", []):
            events.append({
                "timestamp": req.get("timestamp", 0),
                "event_type": "http_request",
                "description": f"{req.get('method', '')} {req.get('uri', '')}",
                "packet_number": req.get("packet_number"),
                "stream_id": req.get("stream_id"),
                "severity": "info",
            })

        for dns in summary.get("dns_queries", []):
            events.append({
                "timestamp": dns.get("timestamp", 0),
                "event_type": "dns_query",
                "description": f"DNS query: {dns.get('query_name', '')}",
                "packet_number": dns.get("packet_number"),
                "severity": "info",
            })

        for finding in summary.get("findings", []):
            events.append({
                "event_type": "finding",
                "description": finding.get("title", ""),
                "severity": finding.get("severity", "info"),
            })

        return sorted(events, key=lambda event: (event.get("timestamp", 0) == 0, event.get("timestamp", 0)))

    def build_graph(self, capture_id: str) -> dict:
        summary = self._cache.get(capture_id, {})
        nodes = []
        edges = []
        node_ids = set()

        def add_node(nid: str, label: str, ntype: str, **meta):
            if nid not in node_ids:
                node_ids.add(nid)
                nodes.append({"id": nid, "label": label, "type": ntype, "metadata": meta})

        def add_edge(src: str, tgt: str, label: str):
            edges.append({"source": src, "target": tgt, "label": label})

        for stream in summary.get("streams", []):
            src_id = f"ip:{stream.get('src', '')}"
            dst_id = f"ip:{stream.get('dst', '')}"
            stream_id = f"stream:{stream.get('stream_id', '')}"
            add_node(src_id, stream.get("src", ""), "ip")
            add_node(dst_id, stream.get("dst", ""), "ip")
            add_node(stream_id, f"Stream #{stream.get('stream_id')}", "stream")
            add_edge(src_id, stream_id, "communicates")
            add_edge(stream_id, dst_id, "communicates")

        for dns in summary.get("dns_queries", [])[:50]:
            client_id = f"ip:{dns.get('client', '')}"
            domain_id = f"domain:{dns.get('query_name', '')}"
            add_node(client_id, dns.get("client", ""), "ip")
            add_node(domain_id, dns.get("query_name", ""), "domain")
            add_edge(client_id, domain_id, "queried")

        return {"nodes": nodes, "edges": edges}


analysis_service = AnalysisService()
