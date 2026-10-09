"""TCP stream analysis and reassembly."""

import subprocess
from typing import Any, Optional


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


class StreamAnalyzer:
    def __init__(self, tshark_path: str = "tshark", timeout: int = 600):
        self.tshark_path = tshark_path
        self.timeout = timeout

    def list_tcp_streams(self, pcap_path: str) -> list[dict[str, Any]]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-T", "fields",
            "-e", "tcp.stream",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "_ws.col.Protocol",
            "-E", "separator=\t",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
        except Exception:
            return []
        if result.returncode != 0:
            return []

        streams: dict[int, dict] = {}
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            sid = _safe_int(parts[0], default=-1)
            if sid < 0:
                continue

            if sid not in streams:
                streams[sid] = {
                    "stream_id": sid,
                    "src": parts[1] if len(parts) > 1 else "",
                    "dst": parts[2] if len(parts) > 2 else "",
                    "src_port": _safe_int(parts[3]) if len(parts) > 3 else 0,
                    "dst_port": _safe_int(parts[4]) if len(parts) > 4 else 0,
                    "packets": 0,
                    "bytes": 0,
                    "first_seen": _safe_float(parts[5]) if len(parts) > 5 else 0.0,
                    "last_seen": _safe_float(parts[5]) if len(parts) > 5 else 0.0,
                    "protocol": parts[7] if len(parts) > 7 else "TCP",
                }

            s = streams[sid]
            s["packets"] += 1
            s["bytes"] += _safe_int(parts[6]) if len(parts) > 6 else 0
            ts = _safe_float(parts[5]) if len(parts) > 5 else 0.0
            if ts > 0 and (s["first_seen"] == 0 or ts < s["first_seen"]):
                s["first_seen"] = ts
            if ts > s["last_seen"]:
                s["last_seen"] = ts

        return sorted(streams.values(), key=lambda x: x["stream_id"])

    def follow_tcp_stream(self, pcap_path: str, stream_id: int) -> dict[str, str]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-q", "-z", f"follow,tcp,ascii,{stream_id}",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
        except Exception:
            return {"combined": "", "client_to_server": "", "server_to_client": ""}

        if result.returncode != 0:
            return {"combined": "", "client_to_server": "", "server_to_client": ""}

        output = result.stdout
        client_to_server: list[str] = []
        server_to_client: list[str] = []
        current_dir: Optional[str] = None

        for line in output.split("\n"):
            if "====" in line:
                # tshark follow output separates directions with ==== markers
                if "→" in line or "->" in line:
                    low = line.lower()
                    if "client" in low:
                        current_dir = "c2s"
                    else:
                        current_dir = "s2c"
                continue
            clean = line.lstrip("\t")
            if current_dir == "c2s":
                client_to_server.append(clean)
            elif current_dir == "s2c":
                server_to_client.append(clean)

        return {
            "stream_id": stream_id,
            "client_to_server": "\n".join(client_to_server),
            "server_to_client": "\n".join(server_to_client),
            "combined": output,
        }

    def search_stream(self, pcap_path: str, stream_id: int, query: str) -> list[dict]:
        content = self.follow_tcp_stream(pcap_path, stream_id)
        matches: list[dict] = []
        for direction, text in [
            ("client_to_server", content["client_to_server"]),
            ("server_to_client", content["server_to_client"]),
        ]:
            if query.lower() in text.lower():
                idx = text.lower().index(query.lower())
                matches.append({
                    "direction": direction,
                    "context": text[max(0, idx - 50): idx + len(query) + 50],
                    "query": query,
                })
        return matches

    def get_stream_count(self, pcap_path: str) -> int:
        return len(self.list_tcp_streams(pcap_path))
