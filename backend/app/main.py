"""FastAPI application factory and lifespan."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.api.v1 import health
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import register_middleware
from app.db.session import dispose_engine

logger = get_logger(__name__)

DESCRIPTION = """
**QuantNexa SOAR·AI Platform** — agentic security orchestration, automation and response.

* **Agent Console** — an autonomous loop with RAG grounding, MCP tools and human approval gates
* **Alerts & Incidents** — ingestion, deduplication, AI risk scoring and case correlation
* **RAG Knowledge** — MITRE ATT&CK, CVE, IR playbooks and detection engineering context
* **MCP Tools** — ten audited capabilities spanning SIEM, EDR, firewall, cloud and ticketing
* **Sigma Builder** — AI rule generation with Splunk / Elastic / Sentinel / QRadar conversion
* **AWS Security** — GuardDuty, Security Hub, IAM and S3 posture with guarded remediation
* **Playbooks** — multi-step response executed through n8n

Authenticate with a bearer token (`POST /api/v1/auth/login`) or an `X-API-Key` header.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    logger.info(
        "application_starting",
        version=__version__,
        environment=settings.environment,
        destructive_actions=settings.allow_destructive_actions,
    )

    app.state.redis = None
    if settings.redis_url:
        try:
            client = aioredis.from_url(settings.redis_url, decode_responses=True)
            await client.ping()
            app.state.redis = client
            logger.info("redis_connected")
        except Exception as exc:
            # Redis backs rate limiting and cross-replica streaming; both degrade
            # gracefully, so an outage must not stop the platform from booting.
            logger.warning("redis_unavailable", error=str(exc))

    yield

    if app.state.redis is not None:
        await app.state.redis.aclose()
    await dispose_engine()
    logger.info("application_stopped")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        description=DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None if settings.is_production else "/redoc",
        openapi_url=None if settings.is_production else "/openapi.json",
        contact={"name": "QuantNexa Technologies", "url": "https://quantnexa.com"},
        license_info={"name": "Proprietary"},
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["authorization", "content-type", "x-api-key", "x-request-id", "x-signature"],
        expose_headers=["x-request-id", "x-ratelimit-remaining"],
        max_age=600,
    )
    if settings.trusted_hosts and settings.trusted_hosts != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
    # SSE must not be buffered by compression, so only larger JSON bodies are gzipped.
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    register_middleware(app)
    register_exception_handlers(app)

    app.include_router(health.router)
    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/", include_in_schema=False)
    async def root() -> dict:
        return {
            "name": settings.app_name,
            "version": __version__,
            "environment": settings.environment,
            "docs": None if settings.is_production else "/docs",
            "api": settings.api_v1_prefix,
        }

    return app


app = create_app()
