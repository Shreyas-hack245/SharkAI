"""DNS traffic analysis."""

import math
import re
import subprocess
from collections import Counter
from typing import Any


class DnsAnalyzer:
    def __init__(self, tshark_path: str = "tshark", timeout: int = 600):
        self.tshark_path = tshark_path
        self.timeout = timeout

    def extract_queries(self, pcap_path: str) -> list[dict[str, Any]]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", "dns.flags.response == 0",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "ip.src",
            "-e", "dns.qry.name",
            "-e", "dns.qry.type",
            "-E", "separator=\t",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        queries = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            queries.append({
                "packet_number": int(parts[0]) if parts[0].isdigit() else 0,
                "client": parts[1] if len(parts) > 1 else "",
                "query_name": parts[2] if len(parts) > 2 else "",
                "query_type": parts[3] if len(parts) > 3 else "",
            })
        return queries

    def extract_responses(self, pcap_path: str) -> list[dict[str, Any]]:
        cmd = [
            self.tshark_path, "-r", pcap_path,
            "-Y", "dns.flags.response == 1",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "dns.qry.name",
            "-e", "dns.a",
            "-e", "dns.resp.type",
            "-e", "dns.flags.rcode",
            "-E", "separator=\t",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if result.returncode != 0:
            return []

        responses = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            rcode = parts[4] if len(parts) > 4 else "0"
            responses.append({
                "packet_number": int(parts[0]) if parts[0].isdigit() else 0,
                "query_name": parts[1] if len(parts) > 1 else "",
                "response_ip": parts[2] if len(parts) > 2 else "",
                "response_type": parts[3] if len(parts) > 3 else "",
                "is_nxdomain": rcode == "3",
            })
        return responses

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def detect_suspicious(self, pcap_path: str) -> list[dict[str, Any]]:
        queries = self.extract_queries(pcap_path)
        findings = []
        domain_counts: Counter = Counter()

        for q in queries:
            name = q.get("query_name", "")
            domain_counts[name] += 1

            reasons = []
            confidence = 0.0

            # Long labels
            labels = name.split(".")
            for label in labels:
                if len(label) > 50:
                    reasons.append(f"Unusually long DNS label ({len(label)} chars)")
                    confidence = max(confidence, 0.7)

            # High entropy subdomain (possible tunneling)
            if labels:
                subdomain = labels[0]
                ent = self._entropy(subdomain)
                if ent > 4.0 and len(subdomain) > 20:
                    reasons.append(f"High-entropy subdomain (entropy={ent:.2f})")
                    confidence = max(confidence, 0.76)

            # Excessive subdomains
            if len(labels) > 6:
                reasons.append(f"Excessive subdomains ({len(labels)} levels)")
                confidence = max(confidence, 0.6)

            if reasons:
                findings.append({
                    **q,
                    "reasons": reasons,
                    "severity": "medium" if confidence < 0.8 else "high",
                    "confidence": confidence,
                })

        # Beacon-like: same client, many unique domains
        client_domains: dict[str, set] = {}
        for q in queries:
            client = q.get("client", "")
            if client:
                client_domains.setdefault(client, set()).add(q.get("query_name", ""))

        for client, domains in client_domains.items():
            if len(domains) > 50:
                findings.append({
                    "client": client,
                    "unique_domains": len(domains),
                    "reasons": [f"Client queried {len(domains)} unique domains"],
                    "severity": "medium",
                    "confidence": 0.65,
                    "category": "beacon_like_dns",
                })

        return findings

    def get_query_count(self, pcap_path: str) -> int:
        return len(self.extract_queries(pcap_path))
