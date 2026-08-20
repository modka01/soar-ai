"""AWS cloud security posture and remediation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.deps import CurrentPrincipal, DbSession, PaginationDep, Principal, require_permission
from app.core.config import settings
from app.db.models import CloudFinding
from app.integrations.aws import AWSSecurityClient
from app.schemas.common import Message, Page
from app.schemas.operations import CloudFindingOut, RemediateRequest
from app.services.audit import AuditService
from app.services.mcp import get_registry

router = APIRouter(prefix="/aws", tags=["aws"])


@router.get("/overview", summary="AWS security service posture tiles")
async def overview(
    principal: CurrentPrincipal, region: Annotated[str | None, Query()] = None
) -> dict:
    client = AWSSecurityClient(region=region)
    return {
        "account_id": settings.aws_account_id,
        "region": client.region,
        "services": await client.service_inventory(),
    }


@router.get("/findings", response_model=Page[CloudFindingOut], summary="Cloud findings")
async def list_findings(
    db: DbSession,
    page: PaginationDep,
    principal: CurrentPrincipal,
    service: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    status_filter: Annotated[str | None, Query(alias="status")] = "active",
) -> Page[CloudFindingOut]:
    statement = select(CloudFinding).order_by(CloudFinding.created_at.desc())
    count_statement = select(func.count()).select_from(CloudFinding)

    for column, value in (
        (CloudFinding.service, service),
        (CloudFinding.severity, severity),
        (CloudFinding.status, status_filter),
    ):
        if value:
            statement = statement.where(column == value)
            count_statement = count_statement.where(column == value)

    total = int(await db.scalar(count_statement) or 0)
    rows = list((await db.scalars(statement.limit(page.limit).offset(page.offset))).all())
    return Page(
        items=[CloudFindingOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post("/sync", response_model=Message, summary="Pull the latest findings from AWS")
async def sync(
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("read"))],
    region: Annotated[str | None, Query()] = None,
) -> Message:
    """Fetch GuardDuty findings and upsert them by their AWS finding id."""
    client = AWSSecurityClient(region=region)
    findings = await client.guardduty_findings(limit=100)

    created = 0
    for finding in findings:
        existing = await db.scalar(
            select(CloudFinding).where(CloudFinding.external_id == finding["external_id"])
        )
        if existing is not None:
            existing.severity = finding["severity"]
            existing.raw = finding
            continue
        db.add(
            CloudFinding(
                provider="aws",
                service=finding["service"],
                finding_type=finding["finding_type"],
                title=finding["title"] or finding["finding_type"],
                description=finding["description"],
                severity=finding["severity"],
                account_id=finding.get("account_id"),
                region=finding.get("region"),
                resource_id=str(finding.get("resource_id") or ""),
                resource_type=finding.get("resource_type"),
                external_id=finding["external_id"],
                raw=finding,
            )
        )
        created += 1

    await db.flush()
    await AuditService(db).record(
        actor=principal.display_name,
        action="aws_sync",
        detail={"fetched": len(findings), "created": created},
    )
    return Message(
        message=f"Synced {len(findings)} finding(s); {created} new.",
        detail={"fetched": len(findings), "created": created},
    )


@router.get("/iam-risks", summary="IAM risk analysis")
async def iam_risks(
    principal: CurrentPrincipal, region: Annotated[str | None, Query()] = None
) -> dict:
    risks = await AWSSecurityClient(region=region).iam_risk_analysis()
    return {
        "total": len(risks),
        "critical": sum(1 for r in risks if r["severity"] == "critical"),
        "risks": risks,
    }


@router.get("/public-buckets", summary="Publicly accessible S3 buckets")
async def public_buckets(
    principal: CurrentPrincipal, region: Annotated[str | None, Query()] = None
) -> dict:
    buckets = await AWSSecurityClient(region=region).public_s3_buckets()
    return {"total": len(buckets), "buckets": buckets}


@router.post("/remediate", summary="Apply an AWS remediation")
async def remediate(
    payload: RemediateRequest,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("containment:execute"))],
) -> dict:
    """Runs through the MCP registry so it is dry-run gated and fully audited."""
    result, record = await get_registry().execute(
        db,
        "aws_remediate",
        {
            "action": payload.action,
            "resource_id": payload.resource_id,
            "region": payload.region or settings.aws_region,
            "reason": payload.reason,
        },
        invoked_by=principal.display_name,
        reason=payload.reason,
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="aws_remediate",
        resource_type="aws_resource",
        resource_id=payload.resource_id,
        outcome="success" if result.ok else "failure",
        detail={"action": payload.action, "dry_run": result.dry_run},
    )

    finding = await db.scalar(
        select(CloudFinding).where(CloudFinding.resource_id == payload.resource_id)
    )
    if finding is not None and result.ok and not result.dry_run:
        finding.status = "remediated"
        finding.remediated_at = datetime.now(UTC)
        finding.remediation = f"{payload.action} by {principal.display_name}"

    return {"execution_id": record.id, **result.to_dict()}
