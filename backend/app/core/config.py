from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True

    database_url: str = "sqlite+aiosqlite:///./data/sharkai.db"

    max_upload_size_mb: int = 500
    max_pcap_size_mb: int = 500

    tshark_path: str = "tshark"
    analysis_timeout_seconds: int = 600
    temp_dir: str = "./data/temp"

    ai_provider: str = "ollama"
    ai_model: str = "llama3.2"
    ai_base_url: str = "http://localhost:11434/v1"
    ai_api_key: str = ""
    ai_max_tokens: int = 4096
    ai_temperature: float = 0.2

    allowed_extensions: str = ".pcap,.pcapng,.cap"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    @property
    def allowed_ext_list(self) -> List[str]:
        return [e.strip().lower() for e in self.allowed_extensions.split(",")]

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    @property
    def data_dir(self) -> Path:
        return Path("./data")

    @property
    def captures_dir(self) -> Path:
        return self.data_dir / "captures"


@lru_cache
def get_settings() -> Settings:
    return Settings()
