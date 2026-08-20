"""MCP tool registry: catalogue, invocation and execution history."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import CurrentPrincipal, DbSession, PaginationDep, Principal, require_permission
from app.core.errors import ApprovalRequiredError
from app.db.models import ToolExecution
from app.schemas.agent import ToolExecutionOut, ToolInvokeRequest, ToolSchemaOut
from app.schemas.common import Page
from app.services.audit import AuditService
from app.services.mcp import get_registry

router = APIRouter(prefix="/mcp", tags=["mcp"])


@router.get("/tools", response_model=list[ToolSchemaOut], summary="List registered MCP tools")
async def list_tools(db: DbSession, principal: CurrentPrincipal) -> list[ToolSchemaOut]:
    """Tool catalogue enriched with each tool's live usage statistics."""
    registry = get_registry()
    stats = {row["tool_name"]: row for row in await registry.usage_stats(db)}
    last_used = await registry.last_used(db)

    tools: list[ToolSchemaOut] = []
    for described in registry.describe_all():
        usage = stats.get(described["name"], {})
        tools.append(
            ToolSchemaOut(
                **{k: v for k, v in described.items() if k != "schema"},
                schema=described["schema"],
                calls=usage.get("calls", 0),
                success_rate=usage.get("success_rate", 0.0),
                avg_duration_ms=usage.get("avg_duration_ms", 0.0),
                last_used_at=last_used.get(described["name"]),
            )
        )
    return tools


@router.get("/tools/{tool_name}", response_model=ToolSchemaOut, summary="Get one tool's schema")
async def get_tool(tool_name: str, db: DbSession, principal: CurrentPrincipal) -> ToolSchemaOut:
    registry = get_registry()
    described = registry.get(tool_name).describe()
    return ToolSchemaOut(
        **{k: v for k, v in described.items() if k != "schema"}, schema=described["schema"]
    )


@router.post(
    "/tools/{tool_name}/invoke",
    response_model=ToolExecutionOut,
    summary="Invoke a tool directly",
)
async def invoke_tool(
    tool_name: str,
    payload: ToolInvokeRequest,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("agent:run"))],
) -> ToolExecution:
    """Manual invocation, used by the MCP module's "Test" action.

    A destructive tool cannot be fired manually without the containment
    permission — it must go through the approval flow instead.
    """
    registry = get_registry()
    tool = registry.get(tool_name)

    if (
        tool.risk.requires_approval
        and not payload.dry_run
        and not principal.has("containment:execute")
    ):
        raise ApprovalRequiredError(
            f"'{tool_name}' is a {tool.risk.value}-risk action. Run it through the agent so it "
            "passes an approval gate, or re-invoke with dry_run=true.",
            details={"tool": tool_name, "risk": tool.risk.value},
        )

    _, record = await registry.execute(
        db,
        tool_name,
        payload.params,
        invoked_by=principal.display_name,
        incident_id=payload.incident_id,
        reason=payload.reason or "Manual invocation",
        force_dry_run=payload.dry_run,
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="tool_invoke",
        resource_type="tool",
        resource_id=tool_name,
        outcome="success" if record.status != "failed" else "failure",
        detail={"dry_run": record.dry_run, "duration_ms": record.duration_ms},
    )
    return record


@router.get("/executions", response_model=Page[ToolExecutionOut], summary="Tool execution history")
async def execution_history(
    db: DbSession,
    page: PaginationDep,
    principal: CurrentPrincipal,
    tool_name: Annotated[str | None, Query()] = None,
    session_id: Annotated[str | None, Query()] = None,
) -> Page[ToolExecutionOut]:
    rows, total = await get_registry().history(
        db, limit=page.limit, offset=page.offset, tool_name=tool_name, session_id=session_id
    )
    return Page(
        items=[ToolExecutionOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/stats", summary="Per-tool usage statistics")
async def tool_stats(db: DbSession, principal: CurrentPrincipal) -> list[dict]:
    return await get_registry().usage_stats(db)
