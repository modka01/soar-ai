"""Cross-cutting HTTP middleware: correlation IDs, access logs, security headers, rate limiting."""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings
from app.core.logging import get_logger, request_id_ctx
from app.core.metrics import http_duration, http_requests

logger = get_logger(__name__)

RequestHandler = Callable[[Request], Awaitable[Response]]


def _route_template(request: Request) -> str:
    """The matched route pattern, not the concrete path.

    Labelling metrics with raw paths would create one time series per incident
    id and blow up cardinality; the template keeps it bounded.
    """
    route = request.scope.get("route")
    return getattr(route, "path", None) or request.url.path


#: Paths excluded from access logging and rate limiting — probes and scrape targets.
_QUIET_PATHS = frozenset({"/health/live", "/health/ready", "/metrics"})


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request id, propagates it to logs, and echoes it to the client."""

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        token = request_id_ctx.set(request_id)
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.perf_counter() - started) * 1000
            logger.exception(
                "request_failed",
                method=request.method,
                path=request.url.path,
                duration_ms=round(duration_ms, 2),
            )
            raise
        finally:
            request_id_ctx.reset(token)

        duration_ms = (time.perf_counter() - started) * 1000
        response.headers["x-request-id"] = request_id
        response.headers["server-timing"] = f"app;dur={duration_ms:.1f}"

        route = _route_template(request)
        http_requests.labels(
            method=request.method, path=route, status=str(response.status_code)
        ).inc()
        http_duration.labels(method=request.method, path=route).observe(duration_ms / 1000)

        if request.url.path not in _QUIET_PATHS:
            logger.info(
                "request_completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
                client=request.client.host if request.client else None,
            )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Applies the response hardening headers expected of a security product."""

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        response = await call_next(request)
        response.headers.setdefault("x-content-type-options", "nosniff")
        response.headers.setdefault("x-frame-options", "DENY")
        response.headers.setdefault("referrer-policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "permissions-policy", "geolocation=(), microphone=(), camera=()"
        )
        response.headers.setdefault("cross-origin-opener-policy", "same-origin")
        if settings.is_production:
            response.headers.setdefault(
                "strict-transport-security", "max-age=63072000; includeSubDomains; preload"
            )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window limiter keyed by API key, bearer subject, or client IP.

    Backed by Redis when available so the limit holds across replicas; falls
    back to a per-process window when Redis is unreachable, which fails open
    rather than rejecting legitimate SOC traffic during a Redis outage.
    """

    def __init__(self, app: FastAPI, limit_per_minute: int | None = None) -> None:
        super().__init__(app)
        self.limit = limit_per_minute or settings.rate_limit_per_minute
        self._local: dict[str, tuple[int, float]] = {}

    def _identity(self, request: Request) -> str:
        api_key = request.headers.get("x-api-key")
        if api_key:
            return f"key:{api_key[:12]}"
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            return f"tok:{auth[7:27]}"
        forwarded = request.headers.get("x-forwarded-for", "")
        client = forwarded.split(",")[0].strip() or (
            request.client.host if request.client else "anonymous"
        )
        return f"ip:{client}"

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        if request.url.path in _QUIET_PATHS:
            return await call_next(request)

        window = int(time.time() // 60)
        key = f"ratelimit:{self._identity(request)}:{window}"
        count = await self._increment(request, key)

        if count > self.limit:
            logger.warning("rate_limit_exceeded", key=key, count=count, limit=self.limit)
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "rate_limited",
                        "message": "Too many requests. Slow down and retry shortly.",
                        "details": {"limit_per_minute": self.limit},
                        "request_id": request_id_ctx.get(),
                    }
                },
                headers={"retry-after": "60"},
            )

        response = await call_next(request)
        response.headers["x-ratelimit-limit"] = str(self.limit)
        response.headers["x-ratelimit-remaining"] = str(max(0, self.limit - count))
        return response

    async def _increment(self, request: Request, key: str) -> int:
        redis = getattr(request.app.state, "redis", None)
        if redis is not None:
            try:
                async with redis.pipeline(transaction=True) as pipe:
                    pipe.incr(key)
                    pipe.expire(key, 120)
                    result = await pipe.execute()
                return int(result[0])
            except Exception as exc:  # pragma: no cover - Redis outage path
                logger.warning("rate_limit_redis_unavailable", error=str(exc))
        now = time.time()
        self._local = {k: v for k, v in self._local.items() if now - v[1] < 120}
        count, first_seen = self._local.get(key, (0, now))
        count += 1
        self._local[key] = (count, first_seen)
        return count


def register_middleware(app: FastAPI) -> None:
    """Order matters — the last registered middleware runs outermost."""
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)
