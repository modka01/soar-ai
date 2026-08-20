"""Liveness, readiness and Prometheus metrics.

These endpoints are deliberately unauthenticated: kubelet probes and the
metrics scraper cannot present a bearer token. They expose no security data.
"""

from __future__ import annotations

from fastapi import APIRouter, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app import __version__
from app.api.deps import DbSession
from app.core.config import settings
from app.services.health import HealthService

router = APIRouter(tags=["health"], include_in_schema=False)


@router.get("/health/live", summary="Liveness probe")
async def live() -> dict:
    """Process is up. Never touches a dependency — a slow database must not
    trigger a pod restart loop."""
    return {"status": "alive", "version": __version__, "environment": settings.environment}


@router.get("/health/ready", summary="Readiness probe")
async def ready(db: DbSession, response: Response) -> dict:
    """Ready to serve traffic: the database must be reachable."""
    database_ok = await HealthService(db).database_ready()
    if not database_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if database_ok else "not_ready",
        "checks": {"database": "ok" if database_ok else "unreachable"},
        "version": __version__,
    }


@router.get("/metrics", summary="Prometheus metrics")
async def metrics() -> Response:
    if not settings.metrics_enabled:
        return Response(status_code=status.HTTP_404_NOT_FOUND)
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
