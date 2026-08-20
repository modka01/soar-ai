"""Integration health probing and platform readiness checks."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.models import HealthState, Integration
from app.integrations.aws import AWSSecurityClient
from app.integrations.edr import CrowdStrikeClient
from app.integrations.firewall import PaloAltoClient
from app.integrations.llm import get_llm_client
from app.integrations.n8n import N8NClient
from app.integrations.siem import ElasticClient, SplunkClient
from app.integrations.ticketing import JiraClient
from app.integrations.tip import AbuseIPDBClient, MISPClient, OTXClient, VirusTotalClient
from app.integrations.vuln import TenableClient

logger = get_logger(__name__)

#: Every integration the health dashboard tracks.
INTEGRATION_CLASSES = [
    SplunkClient,
    ElasticClient,
    CrowdStrikeClient,
    PaloAltoClient,
    VirusTotalClient,
    AbuseIPDBClient,
    OTXClient,
    MISPClient,
    JiraClient,
    N8NClient,
    TenableClient,
]


class HealthService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def probe_all(self) -> list[dict[str, Any]]:
        """Probe every integration concurrently and persist the outcome."""
        clients = [cls() for cls in INTEGRATION_CLASSES]

        async def probe(client) -> dict[str, Any]:
            try:
                result = await client.health_check()
                result.setdefault("name", client.display_name)
                result.setdefault("category", client.category)
                return result
            finally:
                await client.aclose()

        results = await asyncio.gather(
            *(probe(client) for client in clients), return_exceptions=True
        )

        outcomes: list[dict[str, Any]] = []
        for client, result in zip(clients, results, strict=True):
            if isinstance(result, BaseException):
                result = {
                    "slug": client.slug,
                    "name": client.display_name,
                    "category": client.category,
                    "health": HealthState.OFFLINE.value,
                    "detail": str(result)[:200],
                }
            outcomes.append(result)
            await self._persist(result)

        # AWS and Anthropic do not use the BaseIntegration HTTP client.
        aws = await AWSSecurityClient().health_check()
        aws.update({"name": "AWS Security", "category": "cloud"})
        outcomes.append(aws)
        await self._persist(aws)

        llm = get_llm_client()
        anthropic = {
            "slug": "anthropic",
            "name": "Claude API",
            "category": "ai",
            "health": (HealthState.HEALTHY.value if llm.configured else HealthState.UNKNOWN.value),
            "detail": "configured" if llm.configured else "no API key set",
        }
        outcomes.append(anthropic)
        await self._persist(anthropic)

        await self.db.flush()
        return outcomes

    async def _persist(self, result: dict[str, Any]) -> None:
        slug = result.get("slug")
        if not slug:
            return
        integration = await self.db.scalar(select(Integration).where(Integration.slug == slug))
        if integration is None:
            integration = Integration(
                slug=slug,
                name=result.get("name", slug),
                category=result.get("category", "generic"),
            )
            self.db.add(integration)
        integration.health = result.get("health", HealthState.UNKNOWN.value)
        integration.latency_ms = result.get("latency_ms")
        integration.last_error = result.get("detail") if result.get("health") == "offline" else None
        integration.last_checked_at = datetime.now(UTC)

    async def summary(self) -> dict[str, Any]:
        integrations = list((await self.db.scalars(select(Integration))).all())
        counts = {state.value: 0 for state in HealthState}
        for integration in integrations:
            counts[integration.health] = counts.get(integration.health, 0) + 1
        return {
            "total": len(integrations),
            "healthy": counts.get(HealthState.HEALTHY.value, 0),
            "degraded": counts.get(HealthState.DEGRADED.value, 0),
            "offline": counts.get(HealthState.OFFLINE.value, 0),
            "unknown": counts.get(HealthState.UNKNOWN.value, 0),
            "integrations": [
                {
                    "slug": i.slug,
                    "name": i.name,
                    "category": i.category,
                    "health": i.health,
                    "latency_ms": i.latency_ms,
                    "last_checked_at": i.last_checked_at,
                    "last_error": i.last_error,
                }
                for i in sorted(integrations, key=lambda x: (x.category, x.name))
            ],
        }

    async def database_ready(self) -> bool:
        try:
            await self.db.execute(text("SELECT 1"))
        except Exception as exc:
            logger.warning("database_not_ready", error=str(exc))
            return False
        return True
