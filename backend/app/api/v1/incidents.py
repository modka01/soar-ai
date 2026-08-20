"""Incident cases: queue, detail, timeline and AI summary."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import CurrentPrincipal, DbSession, PaginationDep, Principal, require_permission
from app.db.models import Incident
from app.schemas.common import Page
from app.schemas.security import (
    IncidentCreate,
    IncidentDetail,
    IncidentEventCreate,
    IncidentEventOut,
    IncidentOut,
    IncidentStatusUpdate,
)
from app.services.audit import AuditService
from app.services.incidents import IncidentService

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=Page[IncidentOut], summary="List incidents")
async def list_incidents(
    db: DbSession,
    page: PaginationDep,
    principal: CurrentPrincipal,
    severity: Annotated[str | None, Query()] = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    owner: Annotated[str | None, Query()] = None,
) -> Page[IncidentOut]:
    rows, total = await IncidentService(db).list(
        severity=severity,
        status=status_filter,
        owner=owner,
        limit=page.limit,
        offset=page.offset,
    )
    return Page(
        items=[IncidentOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/metrics", summary="Incident metrics (open counts, MTTR)")
async def metrics(
    db: DbSession,
    principal: CurrentPrincipal,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> dict:
    return await IncidentService(db).metrics(days=days)


@router.get("/{incident_id}", response_model=IncidentDetail, summary="Get an incident")
async def get_incident(
    incident_id: str, db: DbSession, principal: CurrentPrincipal
) -> IncidentDetail:
    incident = await IncidentService(db).get(incident_id)
    detail = IncidentDetail.model_validate(incident)
    detail.mttr_minutes = incident.mttr_minutes
    return detail


@router.post(
    "",
    response_model=IncidentOut,
    status_code=status.HTTP_201_CREATED,
    summary="Open an incident",
)
async def create_incident(
    payload: IncidentCreate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("incident:write"))],
) -> Incident:
    incident = await IncidentService(db).create(
        title=payload.title,
        severity=payload.severity.value,
        description=payload.description,
        asset=payload.asset,
        owner=payload.owner or principal.display_name,
        alert_ids=payload.alert_ids,
        created_by=principal.display_name,
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="incident_create",
        resource_type="incident",
        resource_id=incident.reference,
    )
    return incident


@router.patch("/{incident_id}/status", response_model=IncidentOut, summary="Change incident status")
async def update_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("incident:write"))],
) -> Incident:
    incident = await IncidentService(db).update_status(
        incident_id, payload.status.value, actor=principal.display_name
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="incident_status_update",
        resource_type="incident",
        resource_id=incident.reference,
        detail={"status": payload.status.value},
    )
    return incident


@router.post(
    "/{incident_id}/events",
    response_model=IncidentEventOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add a timeline entry",
)
async def add_event(
    incident_id: str,
    payload: IncidentEventCreate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("incident:write"))],
):
    service = IncidentService(db)
    await service.get(incident_id)  # 404 before writing an orphan event
    return await service.add_event(
        incident_id,
        message=payload.message,
        actor=principal.display_name,
        kind=payload.kind,
        severity=payload.severity.value if payload.severity else None,
        detail=payload.detail,
    )


@router.post(
    "/{incident_id}/summary", response_model=IncidentDetail, summary="Generate the AI summary"
)
async def generate_summary(
    incident_id: str,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("incident:write"))],
) -> IncidentDetail:
    incident = await IncidentService(db).generate_summary(incident_id)
    await AuditService(db).record(
        actor=principal.display_name,
        action="incident_ai_summary",
        resource_type="incident",
        resource_id=incident.reference,
    )
    detail = IncidentDetail.model_validate(incident)
    detail.mttr_minutes = incident.mttr_minutes
    return detail
