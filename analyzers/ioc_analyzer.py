"""IOC extraction from PCAP data."""

import hashlib
import re
import subprocess
from typing import Any


class IocAnalyzer:
    IPV4_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    IPV6_PATTERN = re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    )
    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )
    URL_PATTERN = re.compile(
        r"https?://[^\s<>\"{}|\\^`\[\]]+"
    )
    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    )
    MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
    SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
    SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

    def __init__(self, tshark_path: str = "tshark", timeout: int = 600):
        self.tshark_path = tshark_path
        self.timeout = timeout

    def extract_all(self, pcap_path: str) -> list[dict[str, Any]]:
        iocs: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        def add(ioc_type: str, value: str, source: str, **meta):
            key = (ioc_type, value.lower())
            if key not in seen and value:
                seen.add(key)
                iocs.append({"type": ioc_type, "value": value, "source": source, **meta})

        # IPs from tshark
        for field, ioc_type in [("ip.src", "ipv4"), ("ip.dst", "ipv4"),
                                 ("ipv6.src", "ipv6"), ("ipv6.dst", "ipv6")]:
            cmd = [
                self.tshark_path, "-r", pcap_path,
                "-T", "fields", "-e", field,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    val = line.strip()
                    if val:
                        add(ioc_type, val, f"tshark:{field}")

        # Domains from DNS
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", "dns.qry.name",
            "-T", "fields", "-e", "dns.qry.name",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                val = line.strip()
                if val:
                    add("domain", val, "dns_query")

        # URLs from HTTP
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", "http.request.uri",
            "-T", "fields",
            "-e", "http.host",
            "-e", "http.request.uri",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    url = f"http://{parts[0]}{parts[1]}"
                    add("url", url, "http_request")

        # Search payloads for patterns
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-T", "fields", "-e", "data.text",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                text = line.strip()
                if not text:
                    continue
                for match in self.EMAIL_PATTERN.finditer(text):
                    add("email", match.group(0), "payload")
                for match in self.MD5_PATTERN.finditer(text):
                    add("md5", match.group(0), "payload")
                for match in self.SHA1_PATTERN.finditer(text):
                    add("sha1", match.group(0), "payload")
                for match in self.SHA256_PATTERN.finditer(text):
                    add("sha256", match.group(0), "payload")

        return iocs

    def export_json(self, iocs: list[dict]) -> list[dict]:
        return iocs

    def export_csv(self, iocs: list[dict]) -> str:
        lines = ["type,value,source"]
        for ioc in iocs:
            lines.append(f"{ioc['type']},{ioc['value']},{ioc.get('source', '')}")
        return "\n".join(lines)

    def export_txt(self, iocs: list[dict]) -> str:
        lines = []
        by_type: dict[str, list] = {}
        for ioc in iocs:
            by_type.setdefault(ioc["type"], []).append(ioc["value"])
        for ioc_type, values in sorted(by_type.items()):
            lines.append(f"=== {ioc_type.upper()} ===")
            for v in sorted(set(values)):
                lines.append(v)
            lines.append("")
        return "\n".join(lines)
