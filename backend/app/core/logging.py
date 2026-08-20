"""Structured logging with request correlation.

Every log line carries the ``request_id`` of the in-flight HTTP request so a
single incident can be traced end-to-end across API, agent and worker logs.
"""

from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from typing import Any

import structlog

from app.core.config import settings

request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
actor_ctx: ContextVar[str | None] = ContextVar("actor", default=None)


def _inject_context(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    request_id = request_id_ctx.get()
    if request_id:
        event_dict["request_id"] = request_id
    actor = actor_ctx.get()
    if actor:
        event_dict["actor"] = actor
    return event_dict


_REDACT_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "access_key",
    "secret_key",
    "client_secret",
}


def _redact(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Never let a credential reach the log sink."""
    for key in list(event_dict):
        if any(marker in key.lower() for marker in _REDACT_KEYS):
            event_dict[key] = "***redacted***"
    return event_dict


def configure_logging() -> None:
    """Install structlog + stdlib logging. Idempotent."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        _inject_context,
        _redact,
    ]

    if settings.log_format == "json":
        renderer: Any = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[*shared_processors, structlog.processors.format_exc_info, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level, force=True)
    for noisy in ("uvicorn.access", "botocore", "aiobotocore", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(max(level, logging.WARNING))


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[return-value]
