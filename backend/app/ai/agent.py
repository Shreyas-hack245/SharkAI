"""AI investigation agent with tool calling."""

import json
from typing import Any, Callable, Optional

from app.ai.provider import get_ai_provider
from app.ai.tools import TOOL_DEFINITIONS, SYSTEM_PROMPT
from app.core.security import validate_display_filter
from app.services.analysis_service import analysis_service


class InvestigationAgent:
    def __init__(self, capture_id: str, pcap_path: str, mode: str = "expert"):
        self.capture_id = capture_id
        self.pcap_path = pcap_path
        self.mode = mode
        self.provider = get_ai_provider()
        self.evidence: list[dict] = []
        self.steps: list[dict] = []

    async def investigate(
        self,
        query: str,
        progress_callback: Optional[Callable] = None,
    ) -> dict[str, Any]:
        intent = self._parse_intent(query)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": query},
        ]

        if progress_callback:
            await progress_callback({"step": "understanding", "intent": intent})

        max_iterations = 8
        for i in range(max_iterations):
            if progress_callback:
                await progress_callback({"step": f"ai_reasoning_{i}", "message": "AI analyzing..."})

            response = await self.provider.chat(messages, tools=TOOL_DEFINITIONS)

            if response.get("error"):
                return await self._fallback_investigation(query, intent, response["error"])

            tool_calls = response.get("tool_calls")
            if not tool_calls:
                content = response.get("content", "")
                return {
                    "response": content,
                    "evidence": self.evidence,
                    "steps": self.steps,
                    "intent": intent,
                    "filter_applied": intent.get("filter"),
                }

            messages.append({
                "role": "assistant",
                "content": response.get("content"),
                "tool_calls": tool_calls,
            })

            for tc in tool_calls:
                fn = tc.get("function", {})
                tool_name = fn.get("name", "")
                try:
                    args = json.loads(fn.get("arguments", "{}"))
                except json.JSONDecodeError:
                    args = {}

                if progress_callback:
                    await progress_callback({
                        "step": "tool_call",
                        "tool": tool_name,
                        "args": args,
                    })

                result = await self._execute_tool(tool_name, args)
                self.steps.append({"tool": tool_name, "args": args, "result_summary": str(result)[:200]})

                if result and not result.get("error"):
                    self.evidence.append({"tool": tool_name, "data": result})

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "content": json.dumps(result, default=str)[:8000],
                })

        final = await self.provider.chat(messages)
        return {
            "response": final.get("content", "Investigation complete. See evidence for details."),
            "evidence": self.evidence,
            "steps": self.steps,
            "intent": intent,
        }

    def _parse_intent(self, query: str) -> dict[str, Any]:
        q = query.lower().strip()
        intent: dict[str, Any] = {"original_query": query}

        if q.startswith("/"):
            parts = q.split(maxsplit=1)
            intent["command"] = parts[0]
            intent["args"] = parts[1] if len(parts) > 1 else ""
            return intent

        if "flag" in q:
            intent["action"] = "search_flags"
        elif "credential" in q or "password" in q or "login" in q:
            intent["action"] = "find_credentials"
            intent["filter"] = "http.request.method == POST"
        elif "post" in q and "http" in q:
            intent["action"] = "filter_http_post"
            intent["filter"] = "http.request.method == POST"
        elif "suspicious" in q:
            intent["action"] = "detect_anomalies"
        elif "dns" in q:
            intent["action"] = "analyze_dns"
        elif "http" in q:
            intent["action"] = "analyze_http"
        elif "stream" in q or "tcp" in q:
            intent["action"] = "list_streams"
        elif "exfil" in q:
            intent["action"] = "detect_anomalies"
        elif "what happened" in q or "summarize" in q or "summary" in q:
            intent["action"] = "full_investigation"
        elif "ioc" in q:
            intent["action"] = "extract_iocs"
        elif "file" in q:
            intent["action"] = "extract_files"
        elif "timeline" in q:
            intent["action"] = "build_timeline"
        else:
            intent["action"] = "general_search"
            intent["query"] = query

        return intent

    async def _execute_tool(self, name: str, args: dict) -> Any:
        try:
            if name == "get_capture_summary":
                summary = analysis_service.get_cached_summary(self.capture_id)
                if summary:
                    return {
                        "protocol_stats": summary.get("protocol_stats"),
                        "findings_count": len(summary.get("findings", [])),
                        "flags_count": len(summary.get("flags", [])),
                        "iocs_count": len(summary.get("iocs", [])),
                    }
                return {"error": "No summary available"}

            elif name == "search_packets" or name == "search_strings":
                results = analysis_service.packet_analyzer.search_payloads(
                    self.pcap_path, args.get("query", ""), args.get("limit", 50)
                )
                return {"matches": results, "count": len(results)}

            elif name == "filter_packets":
                filt = args.get("filter", "")
                valid, err = validate_display_filter(filt)
                if not valid:
                    return {"error": f"Invalid filter: {err}"}
                packets = analysis_service.packet_analyzer.extract_packets(
                    self.pcap_path, filt, args.get("limit", 100)
                )
                return {"packets": packets, "count": len(packets), "filter": filt}

            elif name == "get_packet":
                detail = await analysis_service.get_packet_detail(
                    self.pcap_path, args["frame_number"]
                )
                return detail

            elif name == "list_tcp_streams":
                streams = await analysis_service.list_streams(self.pcap_path)
                return {"streams": streams[:50], "count": len(streams)}

            elif name == "follow_tcp_stream":
                content = await analysis_service.follow_stream(
                    self.pcap_path, args["stream_id"]
                )
                return content

            elif name == "analyze_http":
                summary = analysis_service.get_cached_summary(self.capture_id) or {}
                return {
                    "requests": summary.get("http_requests", [])[:20],
                    "credentials": summary.get("credentials", []),
                }

            elif name == "analyze_dns":
                summary = analysis_service.get_cached_summary(self.capture_id) or {}
                return {
                    "queries": summary.get("dns_queries", [])[:20],
                    "suspicious": summary.get("suspicious_dns", []),
                }

            elif name == "search_flags":
                flags = analysis_service.flag_analyzer.search_flags(self.pcap_path)
                return {"flags": flags, "count": len(flags)}

            elif name == "extract_iocs":
                summary = analysis_service.get_cached_summary(self.capture_id) or {}
                iocs = summary.get("iocs", [])
                if not iocs:
                    iocs = analysis_service.ioc_analyzer.extract_all(self.pcap_path)
                return {"iocs": iocs[:100], "count": len(iocs)}

            elif name == "extract_files":
                summary = analysis_service.get_cached_summary(self.capture_id) or {}
                return {"files": summary.get("files", [])}

            elif name == "decode_base64":
                from analyzers.encoding import decode_base64
                return decode_base64(args.get("text", ""))

            elif name == "decode_hex":
                from analyzers.encoding import decode_hex
                return decode_hex(args.get("text", ""))

            elif name == "build_timeline":
                timeline = analysis_service.build_timeline(self.capture_id)
                return {"events": timeline}

            elif name == "detect_anomalies":
                summary = analysis_service.get_cached_summary(self.capture_id) or {}
                return {"findings": summary.get("findings", [])}

            else:
                return {"error": f"Unknown tool: {name}"}

        except Exception as e:
            return {"error": str(e)}

    async def _fallback_investigation(
        self, query: str, intent: dict, error: str
    ) -> dict[str, Any]:
        """Rule-based investigation when AI is unavailable."""
        action = intent.get("action", "")
        results = []

        if action == "search_flags" or "flag" in query.lower():
            flags = analysis_service.flag_analyzer.search_flags(self.pcap_path)
            results = flags
            response = self._format_flag_response(flags)
        elif action == "find_credentials":
            creds = analysis_service.http_analyzer.find_credentials(self.pcap_path)
            results = creds
            response = self._format_credentials_response(creds)
        elif action == "full_investigation":
            summary = analysis_service.get_cached_summary(self.capture_id) or {}
            findings = summary.get("findings", [])
            results = findings
            response = self._format_investigation_response(summary, findings)
        else:
            matches = analysis_service.packet_analyzer.search_payloads(
                self.pcap_path, query, 20
            )
            results = matches
            response = f"Found {len(matches)} matching packets for '{query}'."

        return {
            "response": response,
            "evidence": [{"tool": "fallback", "data": results}],
            "steps": [{"tool": "fallback", "reason": f"AI unavailable: {error}"}],
            "intent": intent,
        }

    def _format_flag_response(self, flags: list) -> str:
        if not flags:
            return "No flags found in this capture."
        lines = ["## Flag Search Results\n"]
        for f in flags:
            lines.append(f"**{f.get('flag', 'unknown')}**")
            lines.append(f"- Protocol: {f.get('protocol', 'unknown')}")
            lines.append(f"- Confidence: {f.get('confidence', 0)*100:.0f}%")
            if f.get("stream_id") is not None:
                lines.append(f"- TCP Stream: #{f['stream_id']}")
            lines.append("")
        return "\n".join(lines)

    def _format_credentials_response(self, creds: list) -> str:
        if not creds:
            return "No credentials found in plaintext."
        lines = ["## Credential Findings\n"]
        for c in creds:
            lines.append(f"- **{c.get('type', 'unknown')}** in packet {c.get('packet_number')}")
            lines.append(f"  Value: `{c.get('value', '')[:100]}`")
        return "\n".join(lines)

    def _format_investigation_response(self, summary: dict, findings: list) -> str:
        lines = ["## Investigation Summary\n"]
        stats = summary.get("protocol_stats", {})
        lines.append(f"Analyzed capture with {sum(stats.values())} packets.\n")
        lines.append("### Key Findings\n")
        for f in findings[:10]:
            sev = f.get("severity", "info")
            icon = {"high": "🔴", "medium": "🟠", "low": "🟡"}.get(sev, "⚪")
            lines.append(f"{icon} **{f.get('title', '')}** ({f.get('confidence', 0)*100:.0f}%)")
            lines.append(f"  {f.get('description', '')}")
        return "\n".join(lines)
