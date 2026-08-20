"""Threat-intelligence indicator cache and enrichment fan-out."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.base import ensure_utc
from app.db.models import ThreatIndicator
from app.services.mcp import classify_indicator, get_registry

logger = get_logger(__name__)

#: How long a verdict stays authoritative before it is re-enriched.
CACHE_TTL = timedelta(hours=12)


class ThreatIntelService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.registry = get_registry()

    async def enrich(
        self, value: str, *, indicator_type: str | None = None, force: bool = False
    ) -> ThreatIndicator:
        """Return a cached verdict, or re-enrich when stale or forced."""
        value = value.strip().replace("[.]", ".")
        indicator_type = indicator_type or classify_indicator(value)

        existing = await self.db.scalar(
            select(ThreatIndicator).where(
                ThreatIndicator.value == value,
                ThreatIndicator.indicator_type == indicator_type,
            )
        )
        now = datetime.now(UTC)
        if existing and not force and (ensure_utc(existing.expires_at) or now) > now:
            return existing

        result, _ = await self.registry.execute(
            self.db,
            "enrich_ioc",
            {"ioc": value, "ioc_type": indicator_type},
            invoked_by="threat-intel-service",
        )
        payload = result.to_dict()

        indicator = existing or ThreatIndicator(
            value=value, indicator_type=indicator_type, first_seen=now
        )
        indicator.verdict = str(payload.get("verdict", "unknown"))
        indicator.confidence = int(payload.get("confidence", 0))
        indicator.enrichment = payload.get("sources", {})
        indicator.sources = sorted(payload.get("sources", {}).keys())
        indicator.last_seen = now
        indicator.expires_at = now + CACHE_TTL

        otx = (payload.get("sources") or {}).get("otx") or {}
        if otx.get("threat_actors"):
            indicator.threat_actors = list(otx["threat_actors"])

        if existing is None:
            self.db.add(indicator)
        await self.db.flush()
        logger.info(
            "indicator_enriched",
            value=value,
            verdict=indicator.verdict,
            confidence=indicator.confidence,
        )
        return indicator

    async def record(
        self,
        *,
        value: str,
        indicator_type: str | None = None,
        description: str | None = None,
        verdict: str = "unknown",
        confidence: int = 0,
        threat_actors: list[str] | None = None,
        sources: list[str] | None = None,
    ) -> ThreatIndicator:
        """Insert or refresh an indicator without calling out to providers."""
        value = value.strip()
        indicator_type = indicator_type or classify_indicator(value)
        now = datetime.now(UTC)

        indicator = await self.db.scalar(
            select(ThreatIndicator).where(
                ThreatIndicator.value == value,
                ThreatIndicator.indicator_type == indicator_type,
            )
        )
        if indicator is None:
            indicator = ThreatIndicator(value=value, indicator_type=indicator_type, first_seen=now)
            self.db.add(indicator)

        indicator.description = description or indicator.description
        indicator.verdict = verdict
        indicator.confidence = confidence
        indicator.threat_actors = threat_actors or indicator.threat_actors
        indicator.sources = sources or indicator.sources
        indicator.last_seen = now
        await self.db.flush()
        return indicator

    async def feed(
        self, *, limit: int = 50, min_confidence: int = 0, indicator_type: str | None = None
    ) -> list[ThreatIndicator]:
        statement = (
            select(ThreatIndicator)
            .where(ThreatIndicator.confidence >= min_confidence)
            .order_by(ThreatIndicator.last_seen.desc().nullslast())
            .limit(limit)
        )
        if indicator_type:
            statement = statement.where(ThreatIndicator.indicator_type == indicator_type)
        return list((await self.db.scalars(statement)).all())

    async def stats(self) -> dict[str, Any]:
        by_verdict = {
            verdict: int(count)
            for verdict, count in (
                await self.db.execute(
                    select(ThreatIndicator.verdict, func.count()).group_by(ThreatIndicator.verdict)
                )
            ).all()
        }
        by_type = {
            kind: int(count)
            for kind, count in (
                await self.db.execute(
                    select(ThreatIndicator.indicator_type, func.count()).group_by(
                        ThreatIndicator.indicator_type
                    )
                )
            ).all()
        }
        actors = (
            (
                await self.db.execute(
                    select(ThreatIndicator.threat_actors).where(
                        ThreatIndicator.verdict == "malicious"
                    )
                )
            )
            .scalars()
            .all()
        )
        actor_counts: dict[str, int] = {}
        for entry in actors:
            for actor in entry or []:
                actor_counts[actor] = actor_counts.get(actor, 0) + 1

        return {
            "total": sum(by_verdict.values()),
            "by_verdict": by_verdict,
            "by_type": by_type,
            "top_actors": sorted(
                ({"actor": a, "count": c} for a, c in actor_counts.items()),
                key=lambda x: x["count"],
                reverse=True,
            )[:10],
        }
