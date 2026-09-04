"""TCP stream analysis and reassembly."""

import subprocess
from typing import Any, Optional


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
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        streams: dict[int, dict] = {}
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            try:
                sid = int(parts[0])
            except ValueError:
                continue

            if sid not in streams:
                streams[sid] = {
                    "stream_id": sid,
                    "src": parts[1],
                    "dst": parts[2],
                    "src_port": int(parts[3]) if parts[3].isdigit() else 0,
                    "dst_port": int(parts[4]) if parts[4].isdigit() else 0,
                    "packets": 0,
                    "bytes": 0,
                    "first_seen": float(parts[5]) if parts[5] else 0,
                    "last_seen": float(parts[5]) if parts[5] else 0,
                    "protocol": parts[7] if len(parts) > 7 else "TCP",
                }
            s = streams[sid]
            s["packets"] += 1
            s["bytes"] += int(parts[6]) if parts[6].isdigit() else 0
            ts = float(parts[5]) if parts[5] else 0
            if ts < s["first_seen"]:
                s["first_seen"] = ts
            if ts > s["last_seen"]:
                s["last_seen"] = ts

        return sorted(streams.values(), key=lambda x: x["stream_id"])

    def follow_tcp_stream(self, pcap_path: str, stream_id: int) -> dict[str, str]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-q", "-z", f"follow,tcp,ascii,{stream_id}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return {"combined": "", "client_to_server": "", "server_to_client": ""}

        output = result.stdout
        client_to_server = []
        server_to_client = []
        current_dir = None

        for line in output.split("\n"):
            if "====" in line and "→" in line or "->" in line:
                if "→" in line or "->" in line:
                    if "client" in line.lower() or "→" in line.split("====")[0].lower():
                        current_dir = "c2s"
                    else:
                        current_dir = "s2c"
                continue
            if line.startswith("\t") or (line and not line.startswith("=")):
                clean = line.lstrip("\t")
                if current_dir == "c2s":
                    client_to_server.append(clean)
                elif current_dir == "s2c":
                    server_to_client.append(clean)

        c2s = "\n".join(client_to_server)
        s2c = "\n".join(server_to_client)
        return {
            "stream_id": stream_id,
            "client_to_server": c2s,
            "server_to_client": s2c,
            "combined": output,
        }

    def search_stream(self, pcap_path: str, stream_id: int, query: str) -> list[dict]:
        content = self.follow_tcp_stream(pcap_path, stream_id)
        matches = []
        for direction, text in [("client_to_server", content["client_to_server"]),
                                 ("server_to_client", content["server_to_client"])]:
            if query.lower() in text.lower():
                idx = text.lower().index(query.lower())
                matches.append({
                    "direction": direction,
                    "context": text[max(0, idx - 50):idx + len(query) + 50],
                    "query": query,
                })
        return matches

    def get_stream_count(self, pcap_path: str) -> int:
        streams = self.list_tcp_streams(pcap_path)
        return len(streams)
