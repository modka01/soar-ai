"""Playbooks and n8n workflow orchestration."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Request, status
from sqlalchemy import func, select

from app.api.deps import CurrentPrincipal, DbSession, PaginationDep, Principal, require_permission
from app.core.config import settings
from app.core.errors import AuthenticationError, IntegrationError
from app.core.security import verify_signature
from app.db.models import Playbook, PlaybookRun, WorkflowRun
from app.integrations.n8n import N8NClient
from app.schemas.common import Message, Page
from app.schemas.operations import (
    PlaybookOut,
    PlaybookRunOut,
    PlaybookRunRequest,
    WorkflowOut,
    WorkflowRunOut,
)
from app.services.audit import AuditService
from app.services.playbooks import PlaybookService

router = APIRouter(tags=["playbooks"])


@router.get("/playbooks", response_model=list[PlaybookOut], summary="List playbooks")
async def list_playbooks(
    db: DbSession,
    principal: CurrentPrincipal,
    enabled_only: Annotated[bool, Query()] = False,
) -> list[Playbook]:
    return await PlaybookService(db).list(enabled_only=enabled_only)


@router.get("/playbooks/stats", summary="Per-playbook run statistics")
async def playbook_stats(db: DbSession, principal: CurrentPrincipal) -> list[dict]:
    return await PlaybookService(db).stats()


@router.get("/playbooks/{playbook_id}", response_model=PlaybookOut, summary="Get a playbook")
async def get_playbook(playbook_id: str, db: DbSession, principal: CurrentPrincipal) -> Playbook:
    return await PlaybookService(db).get(playbook_id)


@router.post(
    "/playbooks/{playbook_id}/run",
    response_model=PlaybookRunOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Execute a playbook",
)
async def run_playbook(
    playbook_id: str,
    payload: PlaybookRunRequest,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("playbook:run"))],
) -> PlaybookRun:
    run = await PlaybookService(db).run(
        playbook_id,
        triggered_by=principal.display_name,
        incident_id=payload.incident_id,
        alert_id=payload.alert_id,
        parameters=payload.parameters,
        dry_run=payload.dry_run,
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="playbook_run",
        resource_type="playbook",
        resource_id=playbook_id,
        detail={"run_id": run.id, "dry_run": run.dry_run},
    )
    return run


@router.get("/playbook-runs", response_model=Page[PlaybookRunOut], summary="Playbook run history")
async def list_runs(
    db: DbSession,
    page: PaginationDep,
    principal: CurrentPrincipal,
    playbook_id: Annotated[str | None, Query()] = None,
) -> Page[PlaybookRunOut]:
    rows, total = await PlaybookService(db).list_runs(
        playbook_id=playbook_id, limit=page.limit, offset=page.offset
    )
    return Page(
        items=[PlaybookRunOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/playbook-runs/{run_id}", response_model=PlaybookRunOut, summary="Get a run")
async def get_run(run_id: str, db: DbSession, principal: CurrentPrincipal) -> PlaybookRun:
    return await PlaybookService(db).get_run(run_id)


# ── n8n workflows ────────────────────────────────────────────────────


@router.get("/workflows", response_model=list[WorkflowOut], summary="List n8n workflows")
async def list_workflows(
    principal: CurrentPrincipal, active_only: Annotated[bool, Query()] = False
) -> list[dict]:
    client = N8NClient()
    if not client.is_configured():
        raise IntegrationError(
            "n8n is not configured. Set SOAR_N8N_URL and SOAR_N8N_API_KEY.",
            details={"integration": "n8n"},
        )
    async with client:
        return await client.list_workflows(active_only=active_only)


@router.get("/workflows/{workflow_id}", summary="Get one workflow's node graph")
async def get_workflow(workflow_id: str, principal: CurrentPrincipal) -> dict:
    client = N8NClient()
    async with client:
        return await client.get_workflow(workflow_id)


@router.get(
    "/workflow-runs", response_model=Page[WorkflowRunOut], summary="Workflow execution history"
)
async def list_workflow_runs(
    db: DbSession, page: PaginationDep, principal: CurrentPrincipal
) -> Page[WorkflowRunOut]:
    total = int(await db.scalar(select(func.count()).select_from(WorkflowRun)) or 0)
    rows = list(
        (
            await db.scalars(
                select(WorkflowRun)
                .order_by(WorkflowRun.created_at.desc())
                .limit(page.limit)
                .offset(page.offset)
            )
        ).all()
    )
    return Page(
        items=[WorkflowRunOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post("/n8n/callback", response_model=Message, summary="n8n progress callback")
async def n8n_callback(
    request: Request,
    db: DbSession,
    x_signature: Annotated[str | None, Header(alias="x-signature")] = None,
) -> Message:
    """Receives step-by-step progress from a running n8n workflow.

    Signed with the same HMAC secret as alert ingestion — this endpoint can
    change incident state, so an unsigned call is rejected in production.
    """
    body = await request.body()
    if (settings.is_production or x_signature) and not verify_signature(body, x_signature or ""):
        raise AuthenticationError("Webhook signature is missing or invalid.")

    payload = await request.json()
    service = PlaybookService(db)

    if payload.get("run_id"):
        run = await service.record_callback(payload)
        return Message(message="Playbook run updated.", detail={"run_id": run.id if run else None})

    execution = await service.record_workflow_execution(payload)
    return Message(message="Workflow execution recorded.", detail={"id": execution.id})
