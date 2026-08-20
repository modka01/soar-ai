"""Sigma rule builder: generate, validate, convert, deploy."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import CurrentPrincipal, DbSession, PaginationDep, Principal, require_permission
from app.db.models import SigmaRule
from app.schemas.common import Page
from app.schemas.detection import (
    RuleDeploymentOut,
    SigmaConvertRequest,
    SigmaDeployRequest,
    SigmaGenerateRequest,
    SigmaRuleOut,
    SigmaRuleUpdate,
    SigmaStatusUpdate,
    SigmaValidateRequest,
)
from app.services.audit import AuditService
from app.services.sigma import SUPPORTED_BACKENDS, SigmaService, convert_rule

router = APIRouter(prefix="/sigma", tags=["sigma"])


@router.get("/rules", response_model=Page[SigmaRuleOut], summary="List Sigma rules")
async def list_rules(
    db: DbSession,
    page: PaginationDep,
    principal: CurrentPrincipal,
    search: Annotated[str | None, Query()] = None,
    tactic: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
) -> Page[SigmaRuleOut]:
    rows, total = await SigmaService(db).list(
        search=search,
        tactic=tactic,
        severity=severity,
        status=status_filter,
        limit=page.limit,
        offset=page.offset,
    )
    return Page(
        items=[SigmaRuleOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/backends", summary="Supported SIEM conversion backends")
async def backends(principal: CurrentPrincipal) -> dict:
    return {"backends": list(SUPPORTED_BACKENDS)}


@router.get("/rules/{rule_id}", response_model=SigmaRuleOut, summary="Get a rule")
async def get_rule(rule_id: str, db: DbSession, principal: CurrentPrincipal) -> SigmaRule:
    return await SigmaService(db).get(rule_id)


@router.post(
    "/generate",
    response_model=SigmaRuleOut,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a Sigma rule",
)
async def generate(
    payload: SigmaGenerateRequest,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("sigma:write"))],
) -> SigmaRule:
    """Generate a rule with the LLM (or the deterministic template) and save it as a draft."""
    service = SigmaService(db)
    if payload.use_ai:
        draft = await service.generate_with_ai(
            scenario=payload.scenario,
            tactic=payload.tactic,
            log_source=payload.log_source,
            severity=payload.severity.value,
            author=principal.display_name,
        )
    else:
        draft = await SigmaService.generate_rule_yaml(
            scenario=payload.scenario,
            tactic=payload.tactic,
            log_source=payload.log_source,
            severity=payload.severity.value,
            author=principal.display_name,
        )

    rule = await service.save(
        draft, author=principal.display_name, source_incident_id=payload.source_incident_id
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="sigma_generate",
        resource_type="sigma_rule",
        resource_id=rule.reference,
        detail={"ai": payload.use_ai, "tactic": payload.tactic},
    )
    return rule


@router.post("/validate", summary="Validate Sigma YAML")
async def validate(payload: SigmaValidateRequest, principal: CurrentPrincipal) -> dict:
    document = SigmaService.validate(payload.yaml_body)
    return {
        "valid": True,
        "title": document.get("title"),
        "level": document.get("level"),
        "logsource": document.get("logsource"),
        "tags": document.get("tags", []),
    }


@router.post("/convert", summary="Convert Sigma YAML to a SIEM query")
async def convert(payload: SigmaConvertRequest, principal: CurrentPrincipal) -> dict:
    document = SigmaService.validate(payload.yaml_body)
    return {"backend": payload.backend, "query": convert_rule(document, payload.backend)}


@router.put("/rules/{rule_id}", response_model=SigmaRuleOut, summary="Update a rule's YAML")
async def update_rule(
    rule_id: str,
    payload: SigmaRuleUpdate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("sigma:write"))],
) -> SigmaRule:
    rule = await SigmaService(db).update_yaml(
        rule_id, payload.yaml_body, actor=principal.display_name
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="sigma_update",
        resource_type="sigma_rule",
        resource_id=rule.reference,
        detail={"version": rule.version},
    )
    return rule


@router.patch("/rules/{rule_id}/status", response_model=SigmaRuleOut, summary="Change rule status")
async def update_status(
    rule_id: str,
    payload: SigmaStatusUpdate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("sigma:write"))],
) -> SigmaRule:
    service = SigmaService(db)
    rule = await service.get(rule_id)
    rule.status = payload.status.value
    await db.flush()
    return rule


@router.post(
    "/rules/{rule_id}/deploy",
    response_model=list[RuleDeploymentOut],
    summary="Deploy a rule to SIEM backends",
)
async def deploy(
    rule_id: str,
    payload: SigmaDeployRequest,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("sigma:deploy"))],
):
    deployments = await SigmaService(db).deploy(
        rule_id, payload.backends, deployed_by=principal.display_name
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="sigma_deploy",
        resource_type="sigma_rule",
        resource_id=rule_id,
        detail={"backends": payload.backends},
    )
    return deployments
