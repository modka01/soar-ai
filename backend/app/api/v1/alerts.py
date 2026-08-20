"""Alert queue and ingestion webhook."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Request, status

from app.api.deps import CurrentPrincipal, DbSession, PaginationDep, Principal, require_permission
from app.core.config import settings
from app.core.errors import AuthenticationError
from app.core.logging import get_logger
from app.core.security import verify_signature
from app.db.models import Alert
from app.schemas.common import Message, Page
from app.schemas.security import (
    AlertIngest,
    AlertOut,
    AlertStatusUpdate,
    BulkTriageRequest,
)
from app.services.alerts import AlertService
from app.services.audit import AuditService
from app.services.incidents import IncidentService
from app.services.notifications import get_notification_service

logger = get_logger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=Page[AlertOut], summary="List alerts")
async def list_alerts(
    db: DbSession,
    page: PaginationDep,
    principal: CurrentPrincipal,
    severity: Annotated[str | None, Query()] = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    source: Annotated[str | None, Query()] = None,
    search: Annotated[str | None, Query()] = None,
) -> Page[AlertOut]:
    rows, total = await AlertService(db).list(
        severity=severity,
        status=status_filter,
        source=source,
        search=search,
        limit=page.limit,
        offset=page.offset,
    )
    return Page(
        items=[AlertOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/distribution", summary="Severity distribution and automation rate")
async def distribution(
    db: DbSession,
    principal: CurrentPrincipal,
    hours: Annotated[int, Query(ge=1, le=720)] = 24,
) -> dict:
    return await AlertService(db).severity_distribution(hours=hours)


@router.get("/{alert_id}", response_model=AlertOut, summary="Get an alert")
async def get_alert(alert_id: str, db: DbSession, principal: CurrentPrincipal) -> Alert:
    return await AlertService(db).get(alert_id)


@router.post(
    "/ingest",
    response_model=AlertOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest an alert from a detection source",
)
async def ingest_alert(
    payload: AlertIngest,
    request: Request,
    db: DbSession,
    x_signature: Annotated[str | None, Header(alias="x-signature")] = None,
) -> Alert:
    """Webhook for SIEM/EDR/cloud detections.

    Authenticated by HMAC signature rather than a bearer token, so detection
    sources can post without holding a user credential. In production an
    unsigned request is rejected outright.
    """
    body = await request.body()
    if (settings.is_production or x_signature) and not verify_signature(body, x_signature or ""):
        logger.warning("alert_ingest_bad_signature", source=payload.source)
        raise AuthenticationError("Webhook signature is missing or invalid.")

    service = AlertService(db)
    alert, created = await service.ingest(
        title=payload.title,
        severity=payload.severity.value,
        source=payload.source,
        description=payload.description,
        asset=payload.asset,
        asset_type=payload.asset_type,
        source_event_id=payload.source_event_id,
        detected_at=payload.detected_at,
        indicators=payload.indicators,
        mitre_techniques=payload.mitre_techniques,
        raw_event=payload.raw_event,
    )

    if created and payload.severity.value in {"critical", "high"}:
        incident = await IncidentService(db).correlate_alert(alert, created_by="ingest")
        await get_notification_service().notify(
            title=f"{payload.severity.value.upper()}: {alert.title}",
            message=alert.description or alert.title,
            severity=payload.severity.value,
            detail={
                "asset": alert.asset or "unknown",
                "source": alert.source,
                "incident": incident.reference,
            },
        )

    await AuditService(db).record(
        actor=payload.source,
        actor_type="system",
        action="alert_ingest",
        resource_type="alert",
        resource_id=alert.reference,
        detail={"deduplicated": not created},
    )
    return alert


@router.post("/{alert_id}/triage", response_model=AlertOut, summary="AI-triage one alert")
async def triage_alert(
    alert_id: str,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("alert:triage"))],
) -> Alert:
    alert = await AlertService(db).triage(alert_id, actor=principal.display_name)
    await AuditService(db).record(
        actor=principal.display_name,
        action="alert_triage",
        resource_type="alert",
        resource_id=alert.reference,
        detail={"risk_score": alert.risk_score},
    )
    return alert


@router.post(
    "/triage/bulk", response_model=list[AlertOut], summary="AI-triage the open alert queue"
)
async def bulk_triage(
    payload: BulkTriageRequest,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("alert:triage"))],
) -> list[Alert]:
    alerts = await AlertService(db).bulk_triage(limit=payload.limit, actor=principal.display_name)
    await AuditService(db).record(
        actor=principal.display_name,
        action="alert_bulk_triage",
        detail={"count": len(alerts)},
    )
    return alerts


@router.patch("/{alert_id}/status", response_model=AlertOut, summary="Update alert status")
async def update_status(
    alert_id: str,
    payload: AlertStatusUpdate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("alert:triage"))],
) -> Alert:
    alert = await AlertService(db).update_status(
        alert_id, payload.status.value, actor=principal.display_name
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="alert_status_update",
        resource_type="alert",
        resource_id=alert.reference,
        detail={"status": payload.status.value},
    )
    return alert


@router.post(
    "/{alert_id}/escalate", response_model=Message, summary="Escalate an alert into an incident"
)
async def escalate(
    alert_id: str,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("incident:write"))],
) -> Message:
    alert = await AlertService(db).get(alert_id)
    incident = await IncidentService(db).correlate_alert(alert, created_by=principal.display_name)
    await AuditService(db).record(
        actor=principal.display_name,
        action="alert_escalate",
        resource_type="alert",
        resource_id=alert.reference,
        detail={"incident": incident.reference},
    )
    return Message(
        message=f"Alert {alert.reference} escalated to incident {incident.reference}.",
        detail={"incident_id": incident.id, "incident_reference": incident.reference},
    )
