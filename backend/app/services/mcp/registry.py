"""Tool registry: lookup, safety gating, execution and audit persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.db.models import ExecutionStatus, ToolExecution
from app.services.mcp.base import MCPTool, ToolResult
from app.services.mcp.tools import ALL_TOOLS

logger = get_logger(__name__)


class ToolRegistry:
    """Owns the tool catalogue and every invocation's audit trail."""

    def __init__(self, tools: list[MCPTool] | None = None) -> None:
        self._tools: dict[str, MCPTool] = {t.name: t for t in (tools or ALL_TOOLS)}

    # ── catalogue ────────────────────────────────────────────────────

    def get(self, name: str) -> MCPTool:
        tool = self._tools.get(name)
        if tool is None:
            raise NotFoundError(
                f"Tool '{name}' is not registered.",
                details={"available": sorted(self._tools)},
            )
        return tool

    def has(self, name: str) -> bool:
        return name in self._tools

    def all(self) -> list[MCPTool]:
        return list(self._tools.values())

    def describe_all(self) -> list[dict[str, Any]]:
        return [tool.describe() for tool in self._tools.values()]

    def anthropic_schemas(self) -> list[dict[str, Any]]:
        return [tool.json_schema() for tool in self._tools.values()]

    def names(self) -> list[str]:
        return list(self._tools)

    # ── safety gating ────────────────────────────────────────────────

    def requires_approval(self, name: str) -> bool:
        """True when a human must sign off before this tool runs."""
        if not settings.require_approval_for_containment:
            return False
        return self.get(name).risk.requires_approval

    def is_dry_run(self, name: str, *, force_dry_run: bool = False) -> bool:
        """Mutating tools run as dry runs unless destructive actions are enabled."""
        if force_dry_run:
            return True
        tool = self.get(name)
        return tool.mutating and not settings.allow_destructive_actions

    # ── execution ────────────────────────────────────────────────────

    async def execute(
        self,
        db: AsyncSession,
        name: str,
        params: dict[str, Any] | None = None,
        *,
        invoked_by: str = "agent",
        session_id: str | None = None,
        incident_id: str | None = None,
        approval_id: str | None = None,
        reason: str | None = None,
        force_dry_run: bool = False,
    ) -> tuple[ToolResult, ToolExecution]:
        """Run a tool and persist the execution record in the same transaction."""
        tool = self.get(name)
        dry_run = self.is_dry_run(name, force_dry_run=force_dry_run)

        record = ToolExecution(
            tool_name=name,
            session_id=session_id,
            incident_id=incident_id,
            invoked_by=invoked_by,
            reason=reason,
            params=_redact_params(params or {}),
            status=ExecutionStatus.RUNNING.value,
            dry_run=dry_run,
            approval_id=approval_id,
        )
        db.add(record)
        await db.flush()

        logger.info(
            "tool_execution_started",
            tool=name,
            invoked_by=invoked_by,
            dry_run=dry_run,
            session_id=session_id,
        )

        result = await tool.execute(params or {}, dry_run=dry_run)

        record.result = _truncate(result.to_dict())
        record.duration_ms = result.duration_ms
        record.error = result.error
        if not result.ok:
            record.status = ExecutionStatus.FAILED.value
        elif result.dry_run:
            record.status = ExecutionStatus.DRY_RUN.value
        else:
            record.status = ExecutionStatus.SUCCESS.value
        await db.flush()

        logger.info(
            "tool_execution_finished",
            tool=name,
            status=record.status,
            duration_ms=result.duration_ms,
        )
        return result, record

    # ── history ──────────────────────────────────────────────────────

    async def history(
        self,
        db: AsyncSession,
        *,
        limit: int = 50,
        offset: int = 0,
        tool_name: str | None = None,
        session_id: str | None = None,
    ) -> tuple[list[ToolExecution], int]:
        statement = select(ToolExecution).order_by(ToolExecution.created_at.desc())
        count_statement = select(func.count()).select_from(ToolExecution)
        if tool_name:
            statement = statement.where(ToolExecution.tool_name == tool_name)
            count_statement = count_statement.where(ToolExecution.tool_name == tool_name)
        if session_id:
            statement = statement.where(ToolExecution.session_id == session_id)
            count_statement = count_statement.where(ToolExecution.session_id == session_id)

        total = int(await db.scalar(count_statement) or 0)
        rows = list((await db.scalars(statement.limit(limit).offset(offset))).all())
        return rows, total

    async def usage_stats(self, db: AsyncSession) -> list[dict[str, Any]]:
        """Per-tool call counts, success rate and mean latency."""
        rows = (
            await db.execute(
                select(
                    ToolExecution.tool_name,
                    func.count().label("calls"),
                    func.avg(ToolExecution.duration_ms).label("avg_ms"),
                    func.sum(
                        case((ToolExecution.status == ExecutionStatus.FAILED.value, 1), else_=0)
                    ).label("failures"),
                ).group_by(ToolExecution.tool_name)
            )
        ).all()

        stats = []
        for tool_name, calls, avg_ms, failures in rows:
            calls = int(calls or 0)
            failures = int(failures or 0)
            stats.append(
                {
                    "tool_name": tool_name,
                    "calls": calls,
                    "failures": failures,
                    "success_rate": round((calls - failures) / calls * 100, 1) if calls else 0.0,
                    "avg_duration_ms": round(float(avg_ms or 0), 1),
                }
            )
        return sorted(stats, key=lambda s: s["calls"], reverse=True)

    async def last_used(self, db: AsyncSession) -> dict[str, datetime]:
        rows = (
            await db.execute(
                select(ToolExecution.tool_name, func.max(ToolExecution.created_at)).group_by(
                    ToolExecution.tool_name
                )
            )
        ).all()
        return {name: ts for name, ts in rows if ts is not None}


_SECRET_KEYS = {"password", "token", "api_key", "secret", "credential", "authorization"}


def _redact_params(params: dict[str, Any]) -> dict[str, Any]:
    """Tool parameters land in the audit log — strip anything credential-shaped."""
    return {
        key: ("***redacted***" if any(s in key.lower() for s in _SECRET_KEYS) else value)
        for key, value in params.items()
    }


def _truncate(payload: dict[str, Any], *, max_chars: int = 20_000) -> dict[str, Any]:
    """Guard the database against a SIEM query returning tens of megabytes."""
    import json

    encoded = json.dumps(payload, default=str)
    if len(encoded) <= max_chars:
        return payload
    return {
        "truncated": True,
        "original_size_bytes": len(encoded),
        "preview": encoded[:max_chars],
    }


_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry


def utcnow() -> datetime:
    return datetime.now(UTC)
