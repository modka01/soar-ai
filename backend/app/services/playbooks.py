"""Playbook execution through n8n, with step tracking and incident timeline writes."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.db.models import ExecutionStatus, Playbook, PlaybookRun, WorkflowRun
from app.integrations.n8n import N8NClient
from app.services.incidents import IncidentService

logger = get_logger(__name__)


class PlaybookService:
    def __init__(self, db: AsyncSession, n8n: N8NClient | None = None) -> None:
        self.db = db
        self.n8n = n8n or N8NClient()

    # ── catalogue ────────────────────────────────────────────────────

    async def list(self, *, enabled_only: bool = False) -> list[Playbook]:
        statement = select(Playbook).order_by(Playbook.name)
        if enabled_only:
            statement = statement.where(Playbook.enabled.is_(True))
        return list((await self.db.scalars(statement)).all())

    async def get(self, playbook_id: str) -> Playbook:
        playbook = await self.db.get(Playbook, playbook_id)
        if playbook is None:
            playbook = await self.db.scalar(select(Playbook).where(Playbook.slug == playbook_id))
        if playbook is None:
            raise NotFoundError(f"Playbook {playbook_id} does not exist.")
        return playbook

    # ── execution ────────────────────────────────────────────────────

    async def run(
        self,
        playbook_id: str,
        *,
        triggered_by: str,
        incident_id: str | None = None,
        alert_id: str | None = None,
        parameters: dict[str, Any] | None = None,
        dry_run: bool | None = None,
    ) -> PlaybookRun:
        """Start a playbook run.

        When n8n is unreachable or destructive actions are disabled, the run
        executes as a dry run: every step is recorded with its intent, so the
        analyst sees exactly what the playbook would have done.
        """
        playbook = await self.get(playbook_id)
        if not playbook.enabled:
            raise ConflictError(f"Playbook '{playbook.name}' is disabled.")

        effective_dry_run = (
            dry_run if dry_run is not None else not settings.allow_destructive_actions
        )

        run = PlaybookRun(
            playbook_id=playbook.id,
            incident_id=incident_id,
            alert_id=alert_id,
            triggered_by=triggered_by,
            total_steps=playbook.step_count,
            status=ExecutionStatus.RUNNING.value,
            dry_run=effective_dry_run,
            started_at=datetime.now(UTC),
        )
        self.db.add(run)
        await self.db.flush()

        if incident_id:
            await IncidentService(self.db).add_event(
                incident_id,
                message=f"Playbook '{playbook.name}' started"
                + (" (dry run)" if effective_dry_run else "."),
                actor=triggered_by,
                kind="playbook",
                detail={"run_id": run.id, "playbook": playbook.slug},
            )

        if effective_dry_run or not self.n8n.is_configured():
            await self._simulate(run, playbook)
        else:
            await self._dispatch(run, playbook, parameters or {})

        await self.db.flush()
        logger.info(
            "playbook_run",
            playbook=playbook.slug,
            run_id=run.id,
            status=run.status,
            dry_run=effective_dry_run,
        )
        return run

    async def _dispatch(
        self, run: PlaybookRun, playbook: Playbook, parameters: dict[str, Any]
    ) -> None:
        """Hand execution to n8n; the callback webhook reports progress back."""
        try:
            async with self.n8n:
                result = await self.n8n.trigger_workflow(
                    playbook.n8n_workflow_id or playbook.slug,
                    payload={
                        "run_id": run.id,
                        "playbook": playbook.slug,
                        "incident_id": run.incident_id,
                        "alert_id": run.alert_id,
                        **parameters,
                    },
                )
            run.n8n_execution_id = result.get("execution_id")
            run.step_results = [
                {
                    "index": 0,
                    "name": "Dispatched to n8n",
                    "status": ExecutionStatus.SUCCESS.value,
                    "at": datetime.now(UTC).isoformat(),
                    "detail": result,
                }
            ]
            run.current_step = 1
        except Exception as exc:
            run.status = ExecutionStatus.FAILED.value
            run.error = str(exc)[:1000]
            run.finished_at = datetime.now(UTC)
            logger.warning("playbook_dispatch_failed", playbook=playbook.slug, error=str(exc))

    async def _simulate(self, run: PlaybookRun, playbook: Playbook) -> None:
        """Record each declared step as a dry-run result without side effects."""
        now = datetime.now(UTC)
        run.step_results = [
            {
                "index": index,
                "name": step.get("name", f"Step {index + 1}"),
                "kind": step.get("kind", "action"),
                "status": ExecutionStatus.DRY_RUN.value,
                "at": now.isoformat(),
                "detail": {
                    "would_do": step.get("description", ""),
                    "tool": step.get("tool"),
                },
            }
            for index, step in enumerate(playbook.steps)
        ]
        run.current_step = playbook.step_count
        run.status = ExecutionStatus.DRY_RUN.value
        run.finished_at = now

    # ── callbacks from n8n ───────────────────────────────────────────

    async def record_callback(self, payload: dict[str, Any]) -> PlaybookRun | None:
        """Apply a progress update posted by an n8n workflow."""
        run_id = payload.get("run_id")
        if not run_id:
            return None
        run = await self.db.get(PlaybookRun, run_id)
        if run is None:
            logger.warning("playbook_callback_unknown_run", run_id=run_id)
            return None

        step = payload.get("step") or {}
        if step:
            results = list(run.step_results)
            results.append(
                {
                    "index": len(results),
                    "name": step.get("name", "n8n step"),
                    "status": step.get("status", ExecutionStatus.SUCCESS.value),
                    "at": datetime.now(UTC).isoformat(),
                    "detail": step.get("detail", {}),
                }
            )
            run.step_results = results
            run.current_step = len(results)

        status = payload.get("status")
        if status in {"success", "failed", "completed"}:
            run.status = (
                ExecutionStatus.SUCCESS.value
                if status in {"success", "completed"}
                else ExecutionStatus.FAILED.value
            )
            run.error = payload.get("error")
            run.finished_at = datetime.now(UTC)

            if run.incident_id:
                await IncidentService(self.db).add_event(
                    run.incident_id,
                    message=f"Playbook run finished with status '{run.status}'.",
                    actor="n8n",
                    kind="playbook",
                    detail={"run_id": run.id},
                )

        await self.db.flush()
        return run

    async def record_workflow_execution(self, payload: dict[str, Any]) -> WorkflowRun:
        """Store an n8n execution summary for the Workflows module."""
        execution = WorkflowRun(
            workflow_id=str(payload.get("workflow_id", "")),
            workflow_name=str(payload.get("workflow_name", "")),
            execution_id=str(payload.get("execution_id", "")),
            status=str(payload.get("status", "unknown")),
            trigger_source=payload.get("trigger_source"),
            duration_ms=int(payload.get("duration_ms", 0)),
            node_results=list(payload.get("node_results", [])),
            error=payload.get("error"),
        )
        self.db.add(execution)
        await self.db.flush()
        return execution

    # ── history and stats ────────────────────────────────────────────

    async def get_run(self, run_id: str) -> PlaybookRun:
        run = await self.db.get(PlaybookRun, run_id)
        if run is None:
            raise NotFoundError(f"Playbook run {run_id} does not exist.")
        return run

    async def list_runs(
        self, *, playbook_id: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[PlaybookRun], int]:
        statement = select(PlaybookRun).order_by(PlaybookRun.created_at.desc())
        count_statement = select(func.count()).select_from(PlaybookRun)
        if playbook_id:
            statement = statement.where(PlaybookRun.playbook_id == playbook_id)
            count_statement = count_statement.where(PlaybookRun.playbook_id == playbook_id)

        total = int(await self.db.scalar(count_statement) or 0)
        rows = list((await self.db.scalars(statement.limit(limit).offset(offset))).all())
        return rows, total

    async def stats(self) -> list[dict[str, Any]]:
        """Per-playbook run counts and success rate for the Playbooks module."""
        rows = (
            await self.db.execute(
                select(
                    Playbook.slug,
                    Playbook.name,
                    func.count(PlaybookRun.id),
                    func.sum(
                        case((PlaybookRun.status == ExecutionStatus.SUCCESS.value, 1), else_=0)
                    ),
                )
                .join(PlaybookRun, PlaybookRun.playbook_id == Playbook.id, isouter=True)
                .group_by(Playbook.slug, Playbook.name)
            )
        ).all()

        stats = []
        for slug, name, runs, successes in rows:
            runs = int(runs or 0)
            successes = int(successes or 0)
            stats.append(
                {
                    "slug": slug,
                    "name": name,
                    "runs": runs,
                    "successes": successes,
                    "success_rate": round(successes / runs * 100, 1) if runs else 0.0,
                }
            )
        return stats
