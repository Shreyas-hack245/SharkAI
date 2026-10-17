"""Configuration: optional config.toml, overlaid by SHARKAI_* environment variables.

Precedence (lowest to highest): built-in defaults -> config.toml -> .env file -> real environment.
The AI API key is only ever read from here; it is never accepted from HTTP requests.
"""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

PREFIX_RE = re.compile(r"^[A-Za-z0-9_]{1,24}$")
PROVIDERS = ("none", "openai", "ollama")
DEFAULT_BASE_URLS = {"openai": "https://api.openai.com/v1", "ollama": "http://127.0.0.1:11434"}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class AISettings:
    provider: str = "none"          # none | openai (any OpenAI-compatible server) | ollama
    base_url: str = ""
    model: str = ""
    api_key: str = ""
    timeout: float = 60.0
    temperature: float = 0.2
    max_evidence_chars: int = 16000
    redact_secrets: bool = True     # mask credentials in the evidence sent to the model

    @property
    def enabled(self) -> bool:
        return self.provider in ("openai", "ollama") and bool(self.model) and bool(self.base_url)


@dataclass(frozen=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8000
    data_dir: Path = Path("data")
    max_upload_mb: int = 100
    max_packets: int = 500_000
    max_stream_mb: int = 32
    flag_prefixes: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "[::1]", "::1")
    ai: AISettings = field(default_factory=AISettings)

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def max_stream_bytes(self) -> int:
        return self.max_stream_mb * 1024 * 1024


def _load_dotenv(path: Path, env: dict[str, str]) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        env.setdefault(key.strip(), value)


def _bool(v: object) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _prefixes(raw: object) -> tuple[str, ...]:
    items = raw.split(",") if isinstance(raw, str) else list(raw or [])
    out = []
    for item in items:
        item = str(item).strip()
        if not item:
            continue
        if not PREFIX_RE.match(item):
            raise ConfigError(f"invalid flag prefix {item!r}: use 1-24 letters, digits or underscores")
        out.append(item)
    return tuple(dict.fromkeys(out))


def load_settings(env: Mapping[str, str] | None = None, config_path: str | Path | None = None,
                  dotenv_path: str | Path | None = ".env") -> Settings:
    real_env = dict(os.environ if env is None else env)
    if dotenv_path is not None:
        _load_dotenv(Path(dotenv_path), real_env)

    cfg: dict = {}
    path = Path(config_path or real_env.get("SHARKAI_CONFIG", "config.toml"))
    if path.is_file():
        with path.open("rb") as fh:
            cfg = tomllib.load(fh)

    server, limits = cfg.get("server", {}), cfg.get("limits", {})
    analysis, ai = cfg.get("analysis", {}), cfg.get("ai", {})

    def pick(env_key: str, section: dict, key: str, default):
        return real_env.get(env_key, section.get(key, default))

    provider = str(pick("SHARKAI_AI_PROVIDER", ai, "provider", "none")).lower()
    if provider not in PROVIDERS:
        raise ConfigError(f"ai.provider must be one of {', '.join(PROVIDERS)}")
    base_url = str(pick("SHARKAI_AI_BASE_URL", ai, "base_url", "")).strip().rstrip("/")
    if provider != "none" and not base_url:
        base_url = DEFAULT_BASE_URLS[provider]
    if base_url and not re.match(r"^https?://", base_url):
        raise ConfigError("ai.base_url must start with http:// or https://")

    try:
        ai_settings = AISettings(
            provider=provider,
            base_url=base_url,
            model=str(pick("SHARKAI_AI_MODEL", ai, "model", "")).strip(),
            api_key=str(pick("SHARKAI_AI_API_KEY", ai, "api_key", "")).strip(),
            timeout=float(pick("SHARKAI_AI_TIMEOUT", ai, "timeout", 60)),
            temperature=float(pick("SHARKAI_AI_TEMPERATURE", ai, "temperature", 0.2)),
            max_evidence_chars=int(pick("SHARKAI_AI_MAX_EVIDENCE_CHARS", ai, "max_evidence_chars", 16000)),
            redact_secrets=_bool(pick("SHARKAI_AI_REDACT_SECRETS", ai, "redact_secrets", True)),
        )
        hosts = pick("SHARKAI_ALLOWED_HOSTS", server, "allowed_hosts", None)
        allowed = tuple(h.strip() for h in hosts.split(",") if h.strip()) if isinstance(hosts, str) \
            else tuple(hosts or Settings.allowed_hosts)
        return Settings(
            host=str(pick("SHARKAI_HOST", server, "host", "127.0.0.1")),
            port=int(pick("SHARKAI_PORT", server, "port", 8000)),
            data_dir=Path(pick("SHARKAI_DATA_DIR", server, "data_dir", "data")),
            max_upload_mb=int(pick("SHARKAI_MAX_UPLOAD_MB", limits, "max_upload_mb", 100)),
            max_packets=int(pick("SHARKAI_MAX_PACKETS", limits, "max_packets", 500_000)),
            max_stream_mb=int(pick("SHARKAI_MAX_STREAM_MB", limits, "max_stream_mb", 32)),
            flag_prefixes=_prefixes(pick("SHARKAI_FLAG_PREFIXES", analysis, "flag_prefixes", "")),
            allowed_hosts=allowed,
            ai=ai_settings,
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"invalid configuration value: {exc}") from exc
