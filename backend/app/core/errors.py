"""Typed application errors and the handlers that render them.

All API errors share one JSON envelope so the frontend can render them
uniformly::

    {"error": {"code": "not_found", "message": "...", "details": {...},
               "request_id": "..."}}
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger, request_id_ctx

logger = get_logger(__name__)

# Starlette renamed the 422 constant in newer releases; resolve it once here.
HTTP_422 = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)


class SoarError(Exception):
    """Base class for every error the platform raises deliberately."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    code: str = "internal_error"
    message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
        code: str | None = None,
    ) -> None:
        self.message = message or self.message
        self.details = details or {}
        if code:
            self.code = code
        super().__init__(self.message)


class NotFoundError(SoarError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"
    message = "The requested resource does not exist."


class ConflictError(SoarError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"
    message = "The request conflicts with the current state."


class ValidationError(SoarError):
    status_code = HTTP_422
    code = "validation_error"
    message = "The request payload is invalid."


class AuthenticationError(SoarError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unauthenticated"
    message = "Authentication is required."


class ForbiddenError(SoarError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"
    message = "You do not have permission to perform this action."


class RateLimitError(SoarError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"
    message = "Too many requests."


class IntegrationError(SoarError):
    """A downstream security tool failed or is not configured."""

    status_code = status.HTTP_502_BAD_GATEWAY
    code = "integration_error"
    message = "A downstream integration failed."


class ApprovalRequiredError(SoarError):
    """A containment action needs a human decision before it can run."""

    status_code = status.HTTP_409_CONFLICT
    code = "approval_required"
    message = "This action requires human approval."


def _envelope(code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
            "request_id": request_id_ctx.get(),
        }
    }


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(SoarError)
    async def _soar_error(_: Request, exc: SoarError) -> JSONResponse:
        if exc.status_code >= 500:
            logger.error("soar_error", code=exc.code, message=exc.message, details=exc.details)
        else:
            logger.info("soar_error", code=exc.code, message=exc.message)
        return JSONResponse(
            status_code=exc.status_code, content=_envelope(exc.code, exc.message, exc.details)
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {401: "unauthenticated", 403: "forbidden", 404: "not_found"}.get(
            exc.status_code, "http_error"
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(code, str(exc.detail)),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=HTTP_422,
            content=_envelope(
                "validation_error",
                "The request payload is invalid.",
                {"errors": _serialisable_errors(exc)},
            ),
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_exception", error=str(exc))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_envelope("internal_error", "An unexpected error occurred."),
        )


def _serialisable_errors(exc: RequestValidationError) -> list[dict[str, Any]]:
    """Strip non-JSON-serialisable ``ctx`` values pydantic sometimes attaches."""
    out: list[dict[str, Any]] = []
    for err in exc.errors():
        item = {k: v for k, v in err.items() if k != "ctx"}
        item["loc"] = [str(part) for part in err.get("loc", ())]
        out.append(item)
    return out
