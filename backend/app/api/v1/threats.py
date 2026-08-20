"""Threat intelligence feed and IOC enrichment."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import CurrentPrincipal, DbSession, Principal, require_permission
from app.db.models import ThreatIndicator
from app.schemas.security import EnrichRequest, ThreatIndicatorOut
from app.services.audit import AuditService
from app.services.threat_intel import ThreatIntelService

router = APIRouter(prefix="/threats", tags=["threat-intel"])


@router.get("/feed", response_model=list[ThreatIndicatorOut], summary="Latest indicators")
async def feed(
    db: DbSession,
    principal: CurrentPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    min_confidence: Annotated[int, Query(ge=0, le=100)] = 0,
    indicator_type: Annotated[str | None, Query()] = None,
) -> list[ThreatIndicator]:
    return await ThreatIntelService(db).feed(
        limit=limit, min_confidence=min_confidence, indicator_type=indicator_type
    )


@router.get("/stats", summary="Indicator statistics and top actors")
async def stats(db: DbSession, principal: CurrentPrincipal) -> dict:
    return await ThreatIntelService(db).stats()


@router.post("/enrich", response_model=ThreatIndicatorOut, summary="Enrich an indicator")
async def enrich(
    payload: EnrichRequest,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("read"))],
) -> ThreatIndicator:
    indicator = await ThreatIntelService(db).enrich(
        payload.value, indicator_type=payload.indicator_type, force=payload.force
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="ioc_enrich",
        resource_type="indicator",
        resource_id=payload.value,
        detail={"verdict": indicator.verdict, "confidence": indicator.confidence},
    )
    return indicator
