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
    if not str(resolved).startswith(str(base.resolve())):
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

    # Allow simple protocol names
    if re.match(r"^[a-zA-Z][a-zA-Z0-9_.]*$", expr):
        return True, None

    # Validate compound expressions
    tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9_.]*|==|!=|>=|<=|>|<|&&|\|\||contains|matches|\(|\)|\"[^\"]*\"|'[^']*'|\d+\.?\d*", expr)
    if not tokens:
        return False, "Invalid filter syntax"

    return True, None


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
