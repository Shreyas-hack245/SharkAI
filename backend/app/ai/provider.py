"""Provider-independent AI layer."""

import json
from abc import ABC, abstractmethod
from typing import Any, Optional

import httpx

from app.core.config import get_settings


class AIProvider(ABC):
    @abstractmethod
    async def chat(
        self,
        messages: list[dict[str, str]],
        tools: Optional[list[dict]] = None,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        ...


class OpenAICompatibleProvider(AIProvider):
    def __init__(self, base_url: str, api_key: str, model: str, max_tokens: int = 4096):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens

    async def chat(
        self,
        messages: list[dict[str, str]],
        tools: Optional[list[dict]] = None,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            if response.status_code != 200:
                return {
                    "error": f"AI API error ({response.status_code}): {response.text[:500]}",
                    "content": None,
                }
            data = response.json()
            choice = data.get("choices", [{}])[0]
            message = choice.get("message", {})
            return {
                "content": message.get("content"),
                "tool_calls": message.get("tool_calls"),
                "finish_reason": choice.get("finish_reason"),
            }


class OllamaProvider(OpenAICompatibleProvider):
    """Ollama uses OpenAI-compatible API."""
    pass


def get_ai_provider() -> AIProvider:
    settings = get_settings()
    if settings.ai_provider in ("openai", "ollama", "custom"):
        return OpenAICompatibleProvider(
            base_url=settings.ai_base_url,
            api_key=settings.ai_api_key,
            model=settings.ai_model,
            max_tokens=settings.ai_max_tokens,
        )
    raise ValueError(f"Unknown AI provider: {settings.ai_provider}")
