"""Append-only audit trail."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger, request_id_ctx
from app.db.models import AuditLog

logger = get_logger(__name__)


class AuditService:
    """Records privileged actions. Entries are never updated or deleted."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def record(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        outcome: str = "success",
        actor_type: str = "user",
        source_ip: str | None = None,
        user_agent: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            actor=actor,
            actor_type=actor_type,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            source_ip=source_ip,
            user_agent=user_agent,
            request_id=request_id_ctx.get(),
            detail=detail or {},
        )
        self.db.add(entry)
        await self.db.flush()
        logger.info("audit", actor=actor, action=action, resource=resource_id, outcome=outcome)
        return entry

    async def list(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        since: datetime | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[AuditLog], int]:
        statement = select(AuditLog).order_by(AuditLog.created_at.desc())
        count_statement = select(func.count()).select_from(AuditLog)

        conditions = []
        if actor:
            conditions.append(AuditLog.actor == actor)
        if action:
            conditions.append(AuditLog.action == action)
        if outcome:
            conditions.append(AuditLog.outcome == outcome)
        if since:
            conditions.append(AuditLog.created_at >= since)
        if search:
            pattern = f"%{search.lower()}%"
            conditions.append(
                func.lower(AuditLog.action).like(pattern)
                | func.lower(AuditLog.actor).like(pattern)
                | func.lower(func.coalesce(AuditLog.resource_id, "")).like(pattern)
            )
        for condition in conditions:
            statement = statement.where(condition)
            count_statement = count_statement.where(condition)

        total = int(await self.db.scalar(count_statement) or 0)
        rows = list((await self.db.scalars(statement.limit(limit).offset(offset))).all())
        return rows, total
