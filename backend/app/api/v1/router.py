"""v1 API surface."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    agent,
    alerts,
    auth,
    aws,
    dashboard,
    incidents,
    mcp,
    playbooks,
    rag,
    sigma,
    threats,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(agent.router)
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(mcp.router)
api_router.include_router(rag.router)
api_router.include_router(sigma.router)
api_router.include_router(aws.router)
api_router.include_router(playbooks.router)
api_router.include_router(threats.router)

__all__ = ["api_router"]
