"""Core packet analysis using tshark."""

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional


class TsharkError(Exception):
    pass


# All known Windows installation paths for tshark
_WINDOWS_TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def _find_tshark(hint: str = "tshark") -> Optional[str]:
    """Return the absolute path to tshark, or None if not found."""
    # 1. Try the hint (or system PATH)
    found = shutil.which(hint)
    if found:
        return found
    # 2. Try hint as a literal path
    if Path(hint).is_file():
        return hint
    # 3. Scan known Windows install locations
    for candidate in _WINDOWS_TSHARK_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val) if val not in (None, "") else default
    except (ValueError, TypeError):
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val) if val not in (None, "") else default
    except (ValueError, TypeError):
        return default


class PacketAnalyzer:
    """Primary packet analysis via tshark."""

    FIELDS = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.protocols",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "udp.srcport",
        "udp.dstport",
        "_ws.col.Protocol",
        "_ws.col.Info",
        "_ws.col.Source",
        "_ws.col.Destination",
    ]

    def __init__(self, tshark_path: str = "tshark", timeout: int = 600):
        self.timeout = timeout
        resolved = _find_tshark(tshark_path)
        if resolved:
            self.tshark_path = resolved
            self._available = True
        else:
            self.tshark_path = tshark_path
            self._available = False

    @property
    def available(self) -> bool:
        # Re-probe on every call so that installing tshark while the server
        # is running is picked up without a restart.
        if not self._available:
            resolved = _find_tshark(self.tshark_path)
            if resolved:
                self.tshark_path = resolved
                self._available = True
        return self._available

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(self, args: list[str], pcap_path: str) -> str:
        """Run tshark in JSON mode and return raw stdout."""
        if not self.available:
            raise TsharkError(
                "tshark not found. Install Wireshark: https://www.wireshark.org/download.html"
            )
        cmd = [self.tshark_path, "-r", pcap_path, "-T", "json"] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TsharkError(f"tshark timed out after {self.timeout}s") from exc

        if result.returncode != 0:
            err = (result.stderr or result.stdout).strip()
            raise TsharkError(f"tshark error: {err}")

        return result.stdout

    def _run_fields(
        self, pcap_path: str, display_filter: str = ""
    ) -> list[dict[str, Any]]:
        """Run tshark in tab-separated fields mode."""
        if not self.available:
            raise TsharkError("tshark not available")

        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=\t",
            "-E", "quote=d",
        ]
        for field in self.FIELDS:
            cmd.extend(["-e", field])

        if display_filter:
            cmd.extend(["-Y", display_filter])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TsharkError(f"tshark timed out after {self.timeout}s") from exc

        if result.returncode != 0:
            raise TsharkError(f"tshark fields error: {result.stderr.strip()}")

        return self._parse_tsv(result.stdout)

    def _parse_tsv(self, output: str) -> list[dict[str, Any]]:
        """Parse tshark tab-separated output with -E quote=d quoting."""
        lines = output.strip().split("\n")
        if len(lines) < 2:
            return []

        # Strip surrounding double-quotes added by -E quote=d
        headers = [h.strip().strip('"') for h in lines[0].split("\t")]
        packets = []
        for line in lines[1:]:
            if not line.strip():
                continue
            values = [v.strip().strip('"') for v in line.split("\t")]
            row = dict(zip(headers, values))
            packets.append(row)
        return packets

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_packet_count(self, pcap_path: str) -> int:
        if not self.available:
            return 0
        cmd = [self.tshark_path, "-r", pcap_path, "-T", "fields", "-e", "frame.number"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
        except Exception:
            return 0
        if result.returncode != 0:
            return 0
        return len([ln for ln in result.stdout.strip().split("\n") if ln.strip()])

    def extract_packets(
        self,
        pcap_path: str,
        display_filter: str = "",
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        rows = self._run_fields(pcap_path, display_filter)
        if offset:
            rows = rows[offset:]
        if limit:
            rows = rows[:limit]
        return [self._normalize_packet(r) for r in rows]

    def _normalize_packet(self, row: dict[str, Any]) -> dict[str, Any]:
        src = (
            row.get("_ws.col.Source")
            or row.get("ip.src")
            or row.get("ipv6.src")
            or ""
        )
        dst = (
            row.get("_ws.col.Destination")
            or row.get("ip.dst")
            or row.get("ipv6.dst")
            or ""
        )
        protocol = row.get("_ws.col.Protocol") or row.get("frame.protocols", "").split(":")[-1]
        stream_raw = row.get("tcp.stream", "")
        try:
            stream_int: Optional[int] = int(stream_raw) if stream_raw else None
        except (ValueError, TypeError):
            stream_int = None

        return {
            "frame_number": _safe_int(row.get("frame.number")),
            "timestamp": _safe_float(row.get("frame.time_epoch")),
            "src": src,
            "dst": dst,
            "protocol": protocol.upper() if protocol else "UNKNOWN",
            "length": _safe_int(row.get("frame.len")),
            "info": row.get("_ws.col.Info", ""),
            "stream": stream_int,
            "severity": "info",
            "raw": row,
        }

    def get_packet_detail(self, pcap_path: str, frame_number: int) -> dict[str, Any]:
        output = self._run(["-Y", f"frame.number=={frame_number}"], pcap_path)
        try:
            packets = json.loads(output) if output.strip() else []
        except json.JSONDecodeError:
            packets = []
        if not packets:
            raise TsharkError(f"Packet {frame_number} not found")

        pkt = packets[0]
        layers = self._extract_layers(pkt.get("_source", {}).get("layers", {}))
        hex_dump, ascii_dump = self._get_hex_dump(pcap_path, frame_number)

        return {
            "frame_number": frame_number,
            "timestamp": _safe_float(
                pkt.get("_source", {})
                .get("layers", {})
                .get("frame", {})
                .get("frame.time_epoch", ["0"])[0]
            ),
            "layers": layers,
            "hex_dump": hex_dump,
            "ascii_dump": ascii_dump,
        }

    def _extract_layers(self, layers: dict, depth: int = 0) -> list[dict[str, Any]]:
        result = []
        for key, value in layers.items():
            if key.startswith("_"):
                continue
            node: dict[str, Any] = {"name": key, "fields": {}, "children": []}
            if isinstance(value, dict):
                for fk, fv in value.items():
                    if fk.startswith("_"):
                        continue
                    if isinstance(fv, list):
                        node["fields"][fk] = fv[0] if len(fv) == 1 else fv
                    else:
                        node["fields"][fk] = fv
            result.append(node)
        return result

    def _get_hex_dump(self, pcap_path: str, frame_number: int) -> tuple[str, str]:
        if not self.available:
            return "", ""

        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", f"frame.number=={frame_number}",
            "-x",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except Exception:
            return "", ""
        if result.returncode != 0:
            return "", ""

        hex_lines: list[str] = []
        for line in result.stdout.split("\n"):
            if re.match(r"^\s*[0-9a-f]{4,8}\s", line):
                hex_lines.append(line)

        return "\n".join(hex_lines), ""

    def get_protocol_stats(self, pcap_path: str) -> dict[str, int]:
        rows = self._run_fields(pcap_path)
        stats: dict[str, int] = {}
        for row in rows:
            proto = row.get("_ws.col.Protocol") or "Unknown"
            stats[proto] = stats.get(proto, 0) + 1
        return stats

    def get_top_talkers(self, pcap_path: str, limit: int = 10) -> dict[str, list[dict]]:
        rows = self._run_fields(pcap_path)
        src_counts: dict[str, int] = {}
        dst_counts: dict[str, int] = {}
        for row in rows:
            src = row.get("ip.src") or row.get("ipv6.src") or ""
            dst = row.get("ip.dst") or row.get("ipv6.dst") or ""
            if src:
                src_counts[src] = src_counts.get(src, 0) + 1
            if dst:
                dst_counts[dst] = dst_counts.get(dst, 0) + 1

        def top_n(d: dict[str, int]) -> list[dict]:
            return [
                {"ip": k, "count": v}
                for k, v in sorted(d.items(), key=lambda x: -x[1])[:limit]
            ]

        return {"sources": top_n(src_counts), "destinations": top_n(dst_counts)}

    def search_payloads(self, pcap_path: str, query: str, limit: int = 100) -> list[dict]:
        if not self.available:
            return []
        safe_query = query.replace("\\", "\\\\").replace('"', '\\"')
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", f'frame contains "{safe_query}"',
            "-T", "fields",
            "-e", "frame.number",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
        except Exception:
            return []
        if result.returncode != 0:
            return []

        matches: list[dict] = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            matches.append({
                "frame_number": _safe_int(parts[0]),
                "protocol": parts[1] if len(parts) > 1 else "",
                "info": parts[2] if len(parts) > 2 else "",
            })
            if len(matches) >= limit:
                break
        return matches
