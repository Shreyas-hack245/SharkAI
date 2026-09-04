"""HTTP traffic analysis."""

import re
import subprocess
from typing import Any


class HttpAnalyzer:
    def __init__(self, tshark_path: str = "tshark", timeout: int = 600):
        self.tshark_path = tshark_path
        self.timeout = timeout

    def extract_requests(self, pcap_path: str) -> list[dict[str, Any]]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", "http.request",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "tcp.stream",
            "-e", "http.request.method",
            "-e", "http.request.uri",
            "-e", "http.host",
            "-e", "http.user_agent",
            "-e", "http.content_type",
            "-E", "separator=\t",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        requests = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            requests.append({
                "packet_number": int(parts[0]) if parts[0].isdigit() else 0,
                "stream_id": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                "method": parts[2] if len(parts) > 2 else "",
                "uri": parts[3] if len(parts) > 3 else "",
                "host": parts[4] if len(parts) > 4 else "",
                "user_agent": parts[5] if len(parts) > 5 else "",
                "content_type": parts[6] if len(parts) > 6 else "",
                "post_data": "",
            })
        return requests

    def extract_post_data(self, pcap_path: str) -> list[dict[str, Any]]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", "http.request.method == POST",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "tcp.stream",
            "-e", "http.host",
            "-e", "http.request.uri",
            "-e", "http.file_data",
            "-E", "separator=\t",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        posts = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            posts.append({
                "packet_number": int(parts[0]) if parts[0].isdigit() else 0,
                "stream_id": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                "host": parts[2] if len(parts) > 2 else "",
                "uri": parts[3] if len(parts) > 3 else "",
                "post_data": parts[4] if len(parts) > 4 else "",
            })
        return posts

    def find_credentials(self, pcap_path: str) -> list[dict[str, Any]]:
        findings = []
        cred_patterns = [
            (r"(?i)(password|passwd|pwd)\s*[=:]\s*(\S+)", "password"),
            (r"(?i)(username|user|login)\s*[=:]\s*(\S+)", "username"),
            (r"(?i)(token|api_key|apikey|secret)\s*[=:]\s*(\S+)", "token"),
            (r"(?i)Authorization:\s*Basic\s+(\S+)", "basic_auth"),
            (r"(?i)Authorization:\s*Bearer\s+(\S+)", "bearer_token"),
        ]

        posts = self.extract_post_data(pcap_path)
        for post in posts:
            data = post.get("post_data", "")
            for pattern, cred_type in cred_patterns:
                for match in re.finditer(pattern, data):
                    findings.append({
                        "type": cred_type,
                        "value": match.group(0)[:200],
                        "packet_number": post["packet_number"],
                        "stream_id": post.get("stream_id"),
                        "uri": post.get("uri", ""),
                        "severity": "high",
                        "confidence": 0.9,
                    })

        # Search HTTP headers in streams
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", "http",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "tcp.stream",
            "-e", "http.authorization",
            "-e", "http.cookie",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split("\t")
                auth = parts[2] if len(parts) > 2 else ""
                cookie = parts[3] if len(parts) > 3 else ""
                if auth:
                    findings.append({
                        "type": "authorization_header",
                        "value": auth[:200],
                        "packet_number": int(parts[0]) if parts[0].isdigit() else 0,
                        "stream_id": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                        "severity": "high",
                        "confidence": 0.95,
                    })
                if cookie:
                    findings.append({
                        "type": "cookie",
                        "value": cookie[:200],
                        "packet_number": int(parts[0]) if parts[0].isdigit() else 0,
                        "stream_id": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                        "severity": "medium",
                        "confidence": 0.8,
                    })

        return findings

    def find_suspicious_requests(self, pcap_path: str) -> list[dict[str, Any]]:
        suspicious = []
        requests = self.extract_requests(pcap_path)

        suspicious_ua_patterns = [
            r"(?i)(sqlmap|nikto|nmap|masscan|metasploit|burp|dirbuster|gobuster|hydra)",
            r"(?i)(curl/|python-requests|wget|libwww)",
        ]
        suspicious_uri_patterns = [
            r"(?i)(/admin|/wp-login|/shell|/cmd|/exec|/upload|\.\./|\.\.%2f)",
            r"(?i)(union\s+select|select\s+from|<script|javascript:)",
        ]

        for req in requests:
            reasons = []
            ua = req.get("user_agent", "")
            uri = req.get("uri", "")

            for pattern in suspicious_ua_patterns:
                if re.search(pattern, ua):
                    reasons.append(f"Suspicious user agent: {ua[:80]}")
                    break

            for pattern in suspicious_uri_patterns:
                if re.search(pattern, uri):
                    reasons.append(f"Suspicious URI pattern: {uri[:80]}")
                    break

            if req.get("method") == "POST" and any(
                k in req.get("uri", "").lower() for k in ["login", "auth", "signin"]
            ):
                reasons.append("Authentication POST request")

            if reasons:
                suspicious.append({
                    **req,
                    "reasons": reasons,
                    "severity": "medium",
                    "confidence": 0.75,
                })

        return suspicious

    def get_session_count(self, pcap_path: str) -> int:
        return len(self.extract_requests(pcap_path))
