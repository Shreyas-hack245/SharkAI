import re
import shutil
from pathlib import Path
from typing import Optional, Set

from fastapi import HTTPException, UploadFile

from app.core.config import Settings


ALLOWED_FILTER_FIELDS = {
    "frame", "eth", "ip", "ipv6", "tcp", "udp", "icmp", "dns", "http",
    "tls", "ssl", "ftp", "smtp", "arp", "sctp",
}

# This intentionally supports a useful, auditable subset of display filters.  The
# same expression may be handed to tshark by analysis tools, so accepting arbitrary
# token sequences here would undermine the command allowlist.
SUPPORTED_FILTER_FIELDS = {
    "frame.number", "frame.len",
    "ip.addr", "ip.src", "ip.dst",
    "ipv6.addr", "ipv6.src", "ipv6.dst",
    "tcp.port", "tcp.srcport", "tcp.dstport", "tcp.stream",
    "udp.port", "udp.srcport", "udp.dstport",
    "http.request.method", "http.host", "http.request.uri",
    "dns.qry.name", "dns.qry.type", "dns.flags.rcode",
}

ALLOWED_FILTER_OPERATORS = {"==", "!=", ">", "<", ">=", "<=", "contains", "matches"}

DANGEROUS_PATTERNS = [
    r"[;&|`$]",
    r"\.\./",
    r"\\x00",
    r"\x00",
    r"exec\s*\(",
    r"system\s*\(",
    r"subprocess",
    r"import\s",
    r"__",
]


def validate_extension(filename: str, allowed: list[str]) -> None:
    ext = Path(filename).suffix.lower()
    if ext not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file extension '{ext}'. Allowed: {', '.join(allowed)}",
        )


def validate_upload_size(size: int, max_bytes: int) -> None:
    if size > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {max_bytes // (1024 * 1024)} MB",
        )


def sanitize_path(base: Path, user_path: str) -> Path:
    """Prevent path traversal attacks."""
    resolved = (base / user_path).resolve()
    try:
        resolved.relative_to(base.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid path")
    return resolved


def validate_display_filter(filter_expr: str) -> tuple[bool, Optional[str]]:
    """Validate Wireshark-style display filter expressions."""
    if not filter_expr or not filter_expr.strip():
        return True, None

    expr = filter_expr.strip()

    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, expr, re.IGNORECASE):
            return False, f"Filter contains disallowed pattern: {pattern}"

    if len(expr) > 2000:
        return False, "Filter expression too long"

    # A bare protocol is the most common filter (for example: tcp, http, dns).
    if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*", expr):
        if expr.lower() in ALLOWED_FILTER_FIELDS:
            return True, None
        return False, f"Unsupported protocol '{expr}'"

    token_re = re.compile(
        r'\s*(>=|<=|==|!=|&&|\|\||>|<|contains|matches|\(|\)|'
        r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|'
        r'[A-Za-z][A-Za-z0-9_.:-]*|\d+(?:\.\d+)*)'
    )
    tokens: list[str] = []
    position = 0
    while position < len(expr):
        match = token_re.match(expr, position)
        if not match:
            return False, "Invalid filter syntax"
        tokens.append(match.group(1))
        position = match.end()

    index = 0
    expecting_clause = True
    paren_depth = 0
    while index < len(tokens):
        token = tokens[index]
        if expecting_clause:
            if token == "(":
                paren_depth += 1
                index += 1
                continue
            if token not in SUPPORTED_FILTER_FIELDS:
                return False, f"Unsupported filter field '{token}'"
            if index + 2 >= len(tokens) or tokens[index + 1] not in ALLOWED_FILTER_OPERATORS:
                return False, "Expected a supported comparison operator and value"
            value = tokens[index + 2]
            if value in {"(", ")", "&&", "||"}:
                return False, "Expected a comparison value"
            index += 3
            expecting_clause = False
            continue
        if token in {"&&", "||"}:
            expecting_clause = True
            index += 1
            continue
        if token == ")" and paren_depth:
            paren_depth -= 1
            index += 1
            continue
        return False, "Expected &&, ||, or closing parenthesis"

    if expecting_clause or paren_depth:
        return False, "Incomplete filter expression"
    return True, None


PCAP_MAGIC_NUMBERS = {
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",  # microsecond PCAP
    b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",  # nanosecond PCAP
    b"\x0a\x0d\x0d\x0a",  # PCAPNG section header
}


def validate_capture_file(path: Path) -> None:
    """Reject renamed or empty files before they enter the analysis pipeline."""
    with path.open("rb") as capture_file:
        magic = capture_file.read(4)
    if magic not in PCAP_MAGIC_NUMBERS:
        raise HTTPException(status_code=400, detail="File does not have a valid PCAP or PCAPNG header")


def safe_capture_id(capture_id: str) -> str:
    if not re.match(r"^[a-f0-9-]{36}$", capture_id):
        raise HTTPException(status_code=400, detail="Invalid capture ID")
    return capture_id


async def save_upload_file(
    upload: UploadFile,
    dest: Path,
    settings: Settings,
) -> int:
    validate_extension(upload.filename or "unknown", settings.allowed_ext_list)

    dest.parent.mkdir(parents=True, exist_ok=True)
    size = 0

    with open(dest, "wb") as f:
        while chunk := await upload.read(1024 * 1024):
            size += len(chunk)
            validate_upload_size(size, settings.max_upload_bytes)
            f.write(chunk)

    return size


def cleanup_directory(path: Path) -> None:
    if path.exists() and path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
