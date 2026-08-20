"""Dashboard aggregation and platform settings."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.deps import CurrentPrincipal, DbSession, PaginationDep, Principal, require_permission
from app.db.models import Alert, AlertStatus, Incident, IncidentStatus, Severity
from app.schemas.common import Message, Page
from app.schemas.operations import AuditLogOut, DashboardMetrics, IntegrationOut, SettingsUpdate
from app.services.alerts import AlertService
from app.services.audit import AuditService
from app.services.health import HealthService
from app.services.incidents import IncidentService
from app.services.mcp import get_registry
from app.services.settings_service import NAMESPACES, SettingsService

router = APIRouter(tags=["platform"])


@router.get("/dashboard", response_model=DashboardMetrics, summary="Dashboard rollup")
async def dashboard(
    db: DbSession,
    principal: CurrentPrincipal,
    hours: Annotated[int, Query(ge=1, le=168)] = 24,
) -> DashboardMetrics:
    """Everything the Dashboard module needs, in a single round trip."""
    since = datetime.now(UTC) - timedelta(hours=hours)

    critical_alerts = int(
        await db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.severity == Severity.CRITICAL.value,
                Alert.status.notin_([AlertStatus.CLOSED.value, AlertStatus.FALSE_POSITIVE.value]),
            )
        )
        or 0
    )
    open_incidents = int(
        await db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.status.notin_([IncidentStatus.CLOSED.value]))
        )
        or 0
    )
    auto_resolved = int(
        await db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.detected_at >= since, Alert.status == AlertStatus.AUTOMATED.value)
        )
        or 0
    )

    incident_metrics = await IncidentService(db).metrics(days=30)
    recent = list(
        (await db.scalars(select(Alert).order_by(Alert.detected_at.desc()).limit(10))).all()
    )

    return DashboardMetrics(
        critical_alerts=critical_alerts,
        open_incidents=open_incidents,
        auto_resolved=auto_resolved,
        mttr_minutes=incident_metrics.get("mttr_minutes"),
        alert_distribution=await AlertService(db).severity_distribution(hours=hours),
        incident_metrics=incident_metrics,
        integration_health=await HealthService(db).summary(),
        tool_usage=await get_registry().usage_stats(db),
        recent_alerts=[
            {
                "id": alert.id,
                "reference": alert.reference,
                "title": alert.title,
                "severity": alert.severity,
                "status": alert.status,
                "source": alert.source,
                "asset": alert.asset,
                "risk_score": alert.risk_score,
                "detected_at": alert.detected_at,
            }
            for alert in recent
        ],
    )


@router.get("/integrations", response_model=list[IntegrationOut], summary="Integration health")
async def integrations(db: DbSession, principal: CurrentPrincipal) -> list[dict]:
    summary = await HealthService(db).summary()
    return summary["integrations"]


@router.post("/integrations/probe", summary="Probe every integration now")
async def probe_integrations(
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("read"))],
) -> dict:
    results = await HealthService(db).probe_all()
    return {"probed": len(results), "results": results}


# ── settings ─────────────────────────────────────────────────────────


@router.get("/settings", summary="All platform settings (secrets masked)")
async def get_settings_all(db: DbSession, principal: CurrentPrincipal) -> dict:
    return {"namespaces": NAMESPACES, "settings": await SettingsService(db).get_all()}


@router.get("/settings/{namespace}", summary="One settings namespace")
async def get_namespace(namespace: str, db: DbSession, principal: CurrentPrincipal) -> dict:
    return await SettingsService(db).get_namespace(namespace)


@router.put("/settings/{namespace}", summary="Update a settings namespace")
async def update_namespace(
    namespace: str,
    payload: SettingsUpdate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("settings:write"))],
) -> dict:
    values = await SettingsService(db).set_namespace(
        namespace, payload.values, updated_by=principal.display_name
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="settings_update",
        resource_type="settings",
        resource_id=namespace,
        detail={"keys": sorted(payload.values)},
    )
    return values


@router.get("/settings-export", summary="Export the full configuration (secrets redacted)")
async def export_settings(
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("settings:write"))],
) -> dict:
    await AuditService(db).record(actor=principal.display_name, action="settings_export")
    return await SettingsService(db).export()


# ── audit ────────────────────────────────────────────────────────────


@router.get("/audit", response_model=Page[AuditLogOut], summary="Audit log")
async def audit_log(
    db: DbSession,
    page: PaginationDep,
    principal: Annotated[Principal, Depends(require_permission("audit:read"))],
    actor: Annotated[str | None, Query()] = None,
    action: Annotated[str | None, Query()] = None,
    outcome: Annotated[str | None, Query()] = None,
    search: Annotated[str | None, Query()] = None,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> Page[AuditLogOut]:
    rows, total = await AuditService(db).list(
        actor=actor,
        action=action,
        outcome=outcome,
        search=search,
        since=datetime.now(UTC) - timedelta(days=days),
        limit=page.limit,
        offset=page.offset,
    )
    return Page(
        items=[AuditLogOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post("/seed", response_model=Message, summary="Seed baseline content")
async def seed(
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("settings:write"))],
) -> Message:
    from app.services.seed import seed_all

    result = await seed_all(db)
    return Message(message="Baseline content seeded.", detail=result)
