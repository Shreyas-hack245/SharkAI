"""Evidence-first investigation report generation."""

import json
from datetime import datetime, timezone
from io import BytesIO
from typing import Any


class ReportService:
    def build_document(self, capture: Any, summary: dict[str, Any], timeline: list[dict]) -> str:
        findings = summary.get("findings", [])
        lines = [
            "# SharkAI Network Investigation Report",
            "",
            f"**Capture:** {capture.original_name}",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            "",
            "## Executive Summary",
            f"SharkAI analyzed **{capture.packet_count:,}** packets and identified **{len(findings)}** evidence-backed findings.",
            "",
            "## Capture Overview",
            f"- TCP streams: {capture.tcp_streams}",
            f"- HTTP requests: {capture.http_sessions}",
            f"- DNS queries: {capture.dns_queries}",
            f"- Extracted files: {capture.files_count}",
            f"- Indicators: {capture.iocs_count}",
            f"- Flags found: {capture.flags_count}",
            "",
            "## Security Findings",
        ]
        if not findings:
            lines.append("No automated findings were generated. This is not proof that the capture is benign.")
        for finding in findings:
            lines.extend([
                f"### {finding.get('title', 'Finding')}",
                f"- Severity: {finding.get('severity', 'unknown').upper()}",
                f"- Confidence: {float(finding.get('confidence', 0)) * 100:.0f}%",
                f"- Description: {finding.get('description', '')}",
                f"- FACT: {finding.get('fact', 'Not recorded')}",
                f"- INFERENCE: {finding.get('inference', 'Not recorded')}",
                "",
            ])
        lines.extend(["## IOCs", ""])
        for ioc in summary.get("iocs", [])[:200]:
            lines.append(f"- `{ioc.get('type', 'unknown')}`: {ioc.get('value', '')} ({ioc.get('source', '')})")
        lines.extend(["", "## Timeline", ""])
        for event in timeline:
            timestamp = event.get("timestamp")
            time_label = datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp else "Unknown time"
            lines.append(f"- {time_label} — {event.get('description', '')}")
        return "\n".join(lines) + "\n"

    def build_json(self, capture: Any, summary: dict[str, Any], timeline: list[dict]) -> str:
        return json.dumps({
            "report_type": "SharkAI Network Investigation Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "capture": {"name": capture.original_name, "packets": capture.packet_count},
            "summary": summary,
            "timeline": timeline,
        }, indent=2, default=str)

    def build_pdf(self, markdown: str) -> bytes:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

        output = BytesIO()
        document = SimpleDocTemplate(output, pagesize=letter, title="SharkAI Investigation Report")
        styles = getSampleStyleSheet()
        story = []
        for line in markdown.splitlines():
            if line.startswith("# "):
                style = styles["Title"]
            elif line.startswith("## "):
                style = styles["Heading2"]
            elif line.startswith("### "):
                style = styles["Heading3"]
            elif not line:
                story.append(Spacer(1, 8))
                continue
            else:
                style = styles["BodyText"]
            story.append(Paragraph(line.replace("&", "&amp;"), style))
        document.build(story)
        return output.getvalue()


report_service = ReportService()
