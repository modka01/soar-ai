"""Shared HTTP client for outbound security-tool integrations.

Every integration inherits retry-with-backoff, timeouts, structured logging
and a uniform "not configured" behaviour so a missing credential degrades to
a clear error instead of a stack trace.
"""

from __future__ import annotations

from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import settings
from app.core.errors import IntegrationError
from app.core.logging import get_logger

logger = get_logger(__name__)

RETRYABLE = (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError)


class BaseIntegration:
    """Base class for an outbound integration.

    Subclasses set :attr:`slug` and :attr:`base_url` and implement
    :meth:`is_configured`.
    """

    slug: str = "base"
    display_name: str = "Integration"
    category: str = "generic"

    def __init__(self, base_url: str | None = None, timeout: float | None = None) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.timeout = timeout or settings.integration_timeout_seconds
        self._client: httpx.AsyncClient | None = None

    # ── lifecycle ────────────────────────────────────────────────────

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(self.timeout),
                headers=self.default_headers(),
                follow_redirects=False,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> BaseIntegration:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    # ── contract ─────────────────────────────────────────────────────

    def default_headers(self) -> dict[str, str]:
        return {"user-agent": "QuantNexa-SOAR/1.0", "accept": "application/json"}

    def is_configured(self) -> bool:
        """True when credentials for this integration are present."""
        return bool(self.base_url)

    def require_configured(self) -> None:
        if not self.is_configured():
            raise IntegrationError(
                f"{self.display_name} is not configured. Add its credentials in Settings.",
                details={"integration": self.slug},
            )

    # ── request helper ───────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(RETRYABLE),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
        reraise=True,
    )
    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        expect_json: bool = True,
    ) -> Any:
        self.require_configured()
        try:
            response = await self.client.request(
                method, path, json=json, params=params, headers=headers
            )
        except RETRYABLE as exc:
            logger.warning("integration_transport_error", integration=self.slug, error=str(exc))
            raise
        except httpx.HTTPError as exc:
            raise IntegrationError(
                f"{self.display_name} request failed: {exc}", details={"integration": self.slug}
            ) from exc

        if response.status_code >= 400:
            logger.warning(
                "integration_http_error",
                integration=self.slug,
                status=response.status_code,
                path=path,
            )
            raise IntegrationError(
                f"{self.display_name} returned HTTP {response.status_code}.",
                details={
                    "integration": self.slug,
                    "status": response.status_code,
                    "body": response.text[:500],
                },
            )

        if not expect_json:
            return response.text
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise IntegrationError(
                f"{self.display_name} returned a non-JSON response.",
                details={"integration": self.slug},
            ) from exc

    async def health_check(self) -> dict[str, Any]:
        """Probe used by the integration-health dashboard."""
        if not self.is_configured():
            return {"slug": self.slug, "health": "unknown", "detail": "not configured"}
        import time

        started = time.perf_counter()
        try:
            await self.ping()
        except Exception as exc:
            return {"slug": self.slug, "health": "offline", "detail": str(exc)[:200]}
        latency = (time.perf_counter() - started) * 1000
        health = "healthy" if latency < 2000 else "degraded"
        return {"slug": self.slug, "health": health, "latency_ms": round(latency, 1)}

    async def ping(self) -> None:
        """Cheapest call that proves the credentials work. Override per tool."""
        await self.request("GET", "/", expect_json=False)
