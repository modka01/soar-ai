"""Anthropic client wrapper used by the agent, triage and summarisation paths.

Isolating the SDK here keeps the model contract in one place: JSON-mode
prompting, token accounting, timeouts, and a clear failure when no API key is
configured (the platform never silently fabricates AI output).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from anthropic import (
    APIConnectionError,
    APIStatusError,
    AsyncAnthropic,
)
from anthropic import (
    RateLimitError as AnthropicRateLimitError,
)
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.errors import IntegrationError
from app.core.logging import get_logger

logger = get_logger(__name__)

_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


@dataclass(slots=True)
class LLMResponse:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    stop_reason: str | None = None
    model: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def as_json(self) -> dict[str, Any]:
        """Parse the response as JSON, tolerating prose around the object.

        Models occasionally wrap JSON in commentary or a fenced block; rather
        than failing the whole agent turn we extract the outermost object.
        """
        candidate = self.text.strip()
        if candidate.startswith("```"):
            candidate = re.sub(r"^```(?:json)?\s*|\s*```$", "", candidate, flags=re.MULTILINE)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            match = _JSON_BLOCK.search(candidate)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
        logger.warning("llm_response_not_json", preview=self.text[:200])
        return {"message": self.text, "tool_calls": [], "final_answer": ""}


class LLMClient:
    """Thin async wrapper around the Anthropic Messages API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.api_key = api_key or settings.anthropic_api_key
        self.model = model or settings.anthropic_model
        self.timeout = timeout or settings.anthropic_timeout_seconds
        self._client: AsyncAnthropic | None = None

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    @property
    def client(self) -> AsyncAnthropic:
        if not self.configured:
            raise IntegrationError(
                "Anthropic API key is not configured. Set SOAR_ANTHROPIC_API_KEY.",
                details={"integration": "anthropic"},
            )
        if self._client is None:
            self._client = AsyncAnthropic(api_key=self.api_key, timeout=self.timeout)
        return self._client

    @retry(
        retry=retry_if_exception_type((APIConnectionError, AnthropicRateLimitError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def complete(
        self,
        messages: list[dict[str, Any]],
        *,
        system: str,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResponse:
        """Single completion. Retries connection errors and rate limits."""
        try:
            message = await self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens or settings.anthropic_max_tokens,
                temperature=(
                    temperature if temperature is not None else settings.anthropic_temperature
                ),
                system=system,
                messages=messages,  # type: ignore[arg-type]
            )
        except AnthropicRateLimitError:
            raise
        except APIStatusError as exc:
            logger.error("anthropic_api_error", status=exc.status_code, body=str(exc)[:300])
            raise IntegrationError(
                f"Anthropic API error (HTTP {exc.status_code}).",
                details={"integration": "anthropic", "status": exc.status_code},
            ) from exc
        except APIConnectionError:
            raise

        text = "".join(
            block.text for block in message.content if getattr(block, "type", "") == "text"
        )
        return LLMResponse(
            text=text,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
            stop_reason=message.stop_reason,
            model=message.model,
        )

    async def complete_json(
        self,
        messages: list[dict[str, Any]],
        *,
        system: str,
        max_tokens: int | None = None,
    ) -> tuple[dict[str, Any], LLMResponse]:
        """Completion that must yield a JSON object; returns ``(parsed, raw)``."""
        response = await self.complete(messages, system=system, max_tokens=max_tokens)
        return response.as_json(), response

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.close()


_default_client: LLMClient | None = None


def get_llm_client() -> LLMClient:
    global _default_client
    if _default_client is None:
        _default_client = LLMClient()
    return _default_client
