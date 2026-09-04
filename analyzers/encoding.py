"""Encoding and decoding utilities."""

import base64
import binascii
import gzip
import re
import urllib.parse
import zlib
from typing import Any


def decode_base64(text: str) -> dict[str, Any]:
    try:
        cleaned = text.strip()
        decoded_bytes = base64.b64decode(cleaned, validate=True)
        try:
            decoded_str = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            decoded_str = decoded_bytes.decode("latin-1")
        return {"success": True, "result": decoded_str, "encoding": "base64"}
    except Exception as e:
        return {"success": False, "error": str(e), "encoding": "base64"}


def decode_base32(text: str) -> dict[str, Any]:
    try:
        decoded_bytes = base64.b32decode(text.strip().upper())
        decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
        return {"success": True, "result": decoded_str, "encoding": "base32"}
    except Exception as e:
        return {"success": False, "error": str(e), "encoding": "base32"}


def decode_hex(text: str) -> dict[str, Any]:
    try:
        cleaned = text.replace(" ", "").replace(":", "").replace("\\x", "")
        decoded_bytes = binascii.unhexlify(cleaned)
        try:
            decoded_str = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            decoded_str = decoded_bytes.decode("latin-1")
        return {"success": True, "result": decoded_str, "encoding": "hex"}
    except Exception as e:
        return {"success": False, "error": str(e), "encoding": "hex"}


def decode_url(text: str) -> dict[str, Any]:
    try:
        decoded = urllib.parse.unquote(text)
        return {"success": True, "result": decoded, "encoding": "url"}
    except Exception as e:
        return {"success": False, "error": str(e), "encoding": "url"}


def try_decompress(data: bytes) -> dict[str, Any]:
    for name, func in [("gzip", gzip.decompress), ("zlib", zlib.decompress)]:
        try:
            result = func(data)
            return {"success": True, "result": result.decode("utf-8", errors="ignore"), "encoding": name}
        except Exception:
            continue
    return {"success": False, "error": "No compression detected"}


def auto_decode(text: str, max_depth: int = 5) -> dict[str, Any]:
    """Attempt multiple decoding strategies, building a decode chain."""
    chain = ["Original"]
    current = text
    results = []

    decoders = [
        ("Base64", decode_base64, lambda s: re.match(r"^[A-Za-z0-9+/=]{4,}$", s)),
        ("Hex", decode_hex, lambda s: re.match(r"^[0-9a-fA-F\s:]{4,}$", s)),
        ("URL", decode_url, lambda s: "%" in s),
        ("Base32", decode_base32, lambda s: re.match(r"^[A-Z2-7=]{8,}$", s.upper())),
    ]

    for depth in range(max_depth):
        decoded_any = False
        for name, decoder, check in decoders:
            if check(current):
                result = decoder(current)
                if result.get("success") and result["result"] != current:
                    chain.append(name)
                    current = result["result"]
                    results.append({"chain": list(chain), "result": current})
                    decoded_any = True
                    break
        if not decoded_any:
            break

    return {
        "original": text,
        "final": current,
        "chain": chain,
        "steps": results,
    }
