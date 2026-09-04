"""AI tool definitions for investigation agent."""

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_capture_summary",
            "description": "Get overview statistics and summary of the PCAP capture",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_packets",
            "description": "Search packets by text query in payloads, info, IPs",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search term"},
                    "limit": {"type": "integer", "description": "Max results", "default": 50},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "filter_packets",
            "description": "Filter packets using Wireshark display filter syntax",
            "parameters": {
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "description": "Display filter expression"},
                    "limit": {"type": "integer", "default": 100},
                },
                "required": ["filter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_packet",
            "description": "Get detailed information about a specific packet",
            "parameters": {
                "type": "object",
                "properties": {
                    "frame_number": {"type": "integer", "description": "Packet number"},
                },
                "required": ["frame_number"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_tcp_streams",
            "description": "List all TCP streams in the capture",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "follow_tcp_stream",
            "description": "Follow and reconstruct a TCP stream",
            "parameters": {
                "type": "object",
                "properties": {
                    "stream_id": {"type": "integer", "description": "TCP stream number"},
                },
                "required": ["stream_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_http",
            "description": "Analyze HTTP traffic - requests, responses, credentials",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_dns",
            "description": "Analyze DNS queries and detect suspicious patterns",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_flags",
            "description": "Search for CTF flags in all protocols and streams",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Custom regex pattern (optional)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_iocs",
            "description": "Extract indicators of compromise (IPs, domains, URLs, hashes)",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_files",
            "description": "Extract transferred files from the capture",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_strings",
            "description": "Search for strings in packet payloads",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "default": 50},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "decode_base64",
            "description": "Decode a base64 string",
            "parameters": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "decode_hex",
            "description": "Decode a hexadecimal string",
            "parameters": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "build_timeline",
            "description": "Build investigation timeline of events",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_anomalies",
            "description": "Detect anomalous network behavior",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]

SYSTEM_PROMPT = """You are SharkAI, an expert network forensics analyst and CTF investigator.

CRITICAL RULES:
1. NEVER invent packet data. Only report findings backed by tool results.
2. Always cite specific packet numbers, stream IDs, and evidence.
3. Separate FACT (observed data) from INFERENCE (your analysis) from HYPOTHESIS (speculation).
4. Include confidence levels (0-100%) for each finding.
5. Use the provided tools to investigate before answering.
6. For CTF questions, use search_flags and follow_tcp_stream extensively.
7. Translate natural language queries into appropriate tool calls.

When investigating:
- Start with get_capture_summary for context
- Use specific tools based on the query
- Follow up with detailed analysis as needed
- Present evidence-backed conclusions

Response format:
## Investigation Summary
### Key Findings
(severity, title, evidence, confidence)
### Evidence Details
(specific packet/stream references)
### Timeline (if relevant)
"""
