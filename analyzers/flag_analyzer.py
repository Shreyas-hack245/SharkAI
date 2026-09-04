"""CTF flag detection with fragmented flag reconstruction."""

import base64
import binascii
import re
import subprocess
from typing import Any, Optional


DEFAULT_PATTERNS = [
    (r"flag\{[^}]+\}", "flag{...}", 0.99),
    (r"FLAG\{[^}]+\}", "FLAG{...}", 0.99),
    (r"CTF\{[^}]+\}", "CTF{...}", 0.99),
    (r"THM\{[^}]+\}", "THM{...}", 0.99),
    (r"picoCTF\{[^}]+\}", "picoCTF{...}", 0.99),
    (r"HTB\{[^}]+\}", "HTB{...}", 0.99),
    (r"cyber\{[^}]+\}", "cyber{...}", 0.95),
]


class FlagAnalyzer:
    def __init__(self, tshark_path: str = "tshark", timeout: int = 600):
        self.tshark_path = tshark_path
        self.timeout = timeout

    def search_flags(
        self,
        pcap_path: str,
        custom_patterns: Optional[list[tuple[str, str, float]]] = None,
    ) -> list[dict[str, Any]]:
        patterns = custom_patterns or DEFAULT_PATTERNS
        findings: list[dict[str, Any]] = []
        seen_flags: set[str] = set()

        # Search packet payloads
        payload_findings = self._search_payloads(pcap_path, patterns)
        for f in payload_findings:
            if f["flag"] not in seen_flags:
                seen_flags.add(f["flag"])
                findings.append(f)

        # Search TCP streams
        stream_findings = self._search_streams(pcap_path, patterns)
        for f in stream_findings:
            if f["flag"] not in seen_flags:
                seen_flags.add(f["flag"])
                findings.append(f)

        # Search HTTP
        http_findings = self._search_http(pcap_path, patterns)
        for f in http_findings:
            if f["flag"] not in seen_flags:
                seen_flags.add(f["flag"])
                findings.append(f)

        # Search DNS
        dns_findings = self._search_dns(pcap_path, patterns)
        for f in dns_findings:
            if f["flag"] not in seen_flags:
                seen_flags.add(f["flag"])
                findings.append(f)

        # Search for fragmented flags
        frag_findings = self._search_fragmented(pcap_path, patterns)
        for f in frag_findings:
            if f["flag"] not in seen_flags:
                seen_flags.add(f["flag"])
                findings.append(f)

        # Try decoding encoded content
        decode_findings = self._search_encoded(pcap_path, patterns)
        for f in decode_findings:
            if f["flag"] not in seen_flags:
                seen_flags.add(f["flag"])
                findings.append(f)

        return sorted(findings, key=lambda x: -x.get("confidence", 0))

    def _match_patterns(
        self, text: str, patterns: list, source: str, **meta
    ) -> list[dict[str, Any]]:
        results = []
        for pattern, name, confidence in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                results.append({
                    "flag": match.group(0),
                    "pattern": name,
                    "protocol": source,
                    "confidence": confidence,
                    "context": text[max(0, match.start() - 30):match.end() + 30],
                    **meta,
                })
        return results

    def _search_payloads(self, pcap_path: str, patterns: list) -> list[dict]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "tcp.stream",
            "-e", "_ws.col.Protocol",
            "-e", "data.text",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        findings = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            text = parts[3] if len(parts) > 3 else ""
            if not text:
                continue
            proto = parts[2] if len(parts) > 2 else "Unknown"
            pkt = int(parts[0]) if parts[0].isdigit() else 0
            stream = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            findings.extend(self._match_patterns(
                text, patterns, proto,
                packet_numbers=[pkt], stream_id=stream,
            ))
        return findings

    def _search_streams(self, pcap_path: str, patterns: list) -> list[dict]:
        cmd = [self.tshark_path, "-r", pcap_path, "-T", "fields", "-e", "tcp.stream"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        stream_ids = set()
        for line in result.stdout.strip().split("\n"):
            if line.strip().isdigit():
                stream_ids.add(int(line.strip()))

        findings = []
        for sid in sorted(stream_ids):
            follow_cmd = [
                self.tshark_path, "-r", pcap_path,
                "-q", "-z", f"follow,tcp,ascii,{sid}",
            ]
            follow_result = subprocess.run(
                follow_cmd, capture_output=True, text=True, timeout=60
            )
            if follow_result.returncode != 0:
                continue
            findings.extend(self._match_patterns(
                follow_result.stdout, patterns, "TCP",
                stream_id=sid,
            ))
        return findings

    def _search_http(self, pcap_path: str, patterns: list) -> list[dict]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", "http",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "tcp.stream",
            "-e", "http.file_data",
            "-e", "http.request.uri",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        findings = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            text = " ".join(p for p in parts[2:] if p)
            pkt = int(parts[0]) if parts[0].isdigit() else 0
            stream = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            findings.extend(self._match_patterns(
                text, patterns, "HTTP",
                packet_numbers=[pkt], stream_id=stream,
            ))
        return findings

    def _search_dns(self, pcap_path: str, patterns: list) -> list[dict]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", "dns",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "dns.qry.name",
            "-e", "dns.txt",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        findings = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            text = " ".join(p for p in parts[1:] if p)
            pkt = int(parts[0]) if parts[0].isdigit() else 0
            findings.extend(self._match_patterns(
                text, patterns, "DNS", packet_numbers=[pkt],
            ))
        return findings

    def _search_fragmented(self, pcap_path: str, patterns: list) -> list[dict]:
        """Detect flags split across consecutive packets."""
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "tcp.stream",
            "-e", "data.text",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        packets_by_stream: dict[int, list[tuple[int, str]]] = {}
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            pkt = int(parts[0]) if parts[0].isdigit() else 0
            stream = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            text = parts[2] if len(parts) > 2 else ""
            if text:
                packets_by_stream.setdefault(stream, []).append((pkt, text))

        findings = []
        flag_starts = [r"flag\{", r"FLAG\{", r"CTF\{", r"THM\{", r"picoCTF\{"]

        for stream_id, packets in packets_by_stream.items():
            combined = ""
            pkt_range = []
            for pkt_num, text in sorted(packets, key=lambda x: x[0]):
                combined += text
                pkt_range.append(pkt_num)

                for start_pat in flag_starts:
                    if re.search(start_pat, combined, re.IGNORECASE):
                        for pattern, name, confidence in patterns:
                            for match in re.finditer(pattern, combined, re.IGNORECASE):
                                findings.append({
                                    "flag": match.group(0),
                                    "pattern": name,
                                    "protocol": "TCP (fragmented)",
                                    "stream_id": stream_id,
                                    "packet_numbers": pkt_range,
                                    "confidence": confidence * 0.95,
                                    "context": "Reconstructed from fragmented packets",
                                })

        return findings

    def _search_encoded(self, pcap_path: str, patterns: list) -> list[dict]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-T", "fields", "-e", "data.text",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        findings = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            decoded_variants = self._try_decode(line.strip())
            for variant, chain in decoded_variants:
                for pattern, name, confidence in patterns:
                    for match in re.finditer(pattern, variant, re.IGNORECASE):
                        findings.append({
                            "flag": match.group(0),
                            "pattern": name,
                            "protocol": "Encoded",
                            "confidence": confidence * 0.9,
                            "decode_chain": chain,
                            "context": f"Found after decoding: {' → '.join(chain)}",
                        })
        return findings

    @staticmethod
    def _try_decode(text: str) -> list[tuple[str, list[str]]]:
        results = []
        chain = ["Original"]

        # Base64
        try:
            if re.match(r"^[A-Za-z0-9+/=]{8,}$", text):
                decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
                if decoded and decoded != text:
                    results.append((decoded, chain + ["Base64"]))
                    # Try hex on decoded
                    try:
                        hex_decoded = binascii.unhexlify(decoded.strip()).decode("utf-8", errors="ignore")
                        if hex_decoded:
                            results.append((hex_decoded, chain + ["Base64", "Hex"]))
                    except Exception:
                        pass
        except Exception:
            pass

        # Hex
        try:
            clean = text.replace(" ", "").replace(":", "")
            if re.match(r"^[0-9a-fA-F]{8,}$", clean):
                decoded = binascii.unhexlify(clean).decode("utf-8", errors="ignore")
                if decoded and decoded != text:
                    results.append((decoded, chain + ["Hex"]))
        except Exception:
            pass

        return results
