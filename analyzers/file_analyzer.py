"""File extraction from network captures."""

import hashlib
import re
import subprocess
from typing import Any


class FileAnalyzer:
    MIME_SIGNATURES = {
        b"\x89PNG\r\n\x1a\n": "image/png",
        b"\xff\xd8\xff": "image/jpeg",
        b"GIF87a": "image/gif",
        b"GIF89a": "image/gif",
        b"%PDF": "application/pdf",
        b"PK\x03\x04": "application/zip",
        b"\x7fELF": "application/x-executable",
        b"MZ": "application/x-dosexec",
    }

    def __init__(self, tshark_path: str = "tshark", timeout: int = 600):
        self.tshark_path = tshark_path
        self.timeout = timeout

    def extract_files(self, pcap_path: str) -> list[dict[str, Any]]:
        files = []

        # HTTP objects
        http_files = self._extract_http_objects(pcap_path)
        files.extend(http_files)

        # Files from tshark export
        tshark_files = self._extract_via_tshark(pcap_path)
        for tf in tshark_files:
            if not any(f.get("filename") == tf.get("filename") for f in files):
                files.append(tf)

        return files

    def _extract_http_objects(self, pcap_path: str) -> list[dict[str, Any]]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", "http.response",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "tcp.stream",
            "-e", "http.content_type",
            "-e", "http.content_length",
            "-e", "http.request.uri",
            "-e", "http.response.code",
            "-e", "ip.src",
            "-e", "ip.dst",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        files = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue

            uri = parts[4] if len(parts) > 4 else ""
            filename = uri.split("/")[-1] if uri else "unknown"
            content_type = parts[2] if len(parts) > 2 else ""
            content_length = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0

            if content_length > 0 or content_type:
                files.append({
                    "filename": filename,
                    "protocol": "HTTP",
                    "source": parts[6] if len(parts) > 6 else "",
                    "destination": parts[7] if len(parts) > 7 else "",
                    "size": content_length,
                    "mime": content_type,
                    "stream_id": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                    "packet_number": int(parts[0]) if parts[0].isdigit() else 0,
                    "status_code": int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else None,
                })

        return files

    def _extract_via_tshark(self, pcap_path: str) -> list[dict[str, Any]]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", "http || ftp-data || smb || tftp",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        files = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            files.append({
                "filename": f"extracted_{parts[0] if parts else 'unknown'}",
                "protocol": parts[1] if len(parts) > 1 else "Unknown",
                "size": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                "packet_number": int(parts[0]) if parts[0].isdigit() else 0,
            })
        return files

    @staticmethod
    def compute_hash(data: bytes) -> dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    @staticmethod
    def detect_mime(data: bytes) -> str:
        for sig, mime in FileAnalyzer.MIME_SIGNATURES.items():
            if data.startswith(sig):
                return mime
        return "application/octet-stream"
