"""Background maintenance loop.

Runs as its own deployment so periodic work — health probing, approval
expiry, cloud sync, retention — never competes with request handling. All
tasks are idempotent, so a duplicated tick is harmless.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select

from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.db.session import dispose_engine, session_scope

logger = get_logger(__name__)


@dataclass(slots=True)
class ScheduledTask:
    name: str
    interval_seconds: int
    run: Callable[[], Awaitable[None]]
    last_run: datetime | None = None

    def is_due(self, now: datetime) -> bool:
        if self.last_run is None:
            return True
        return (now - self.last_run).total_seconds() >= self.interval_seconds


async def probe_integrations() -> None:
    from app.core.metrics import integration_health
    from app.services.health import HealthService

    async with session_scope() as db:
        results = await HealthService(db).probe_all()

    scores = {"healthy": 1.0, "degraded": 0.5, "offline": 0.0, "unknown": 0.0}
    for result in results:
        integration_health.labels(integration=result.get("slug", "unknown")).set(
            scores.get(result.get("health", "unknown"), 0.0)
        )
    logger.info("integrations_probed", count=len(results))


async def expire_approvals() -> None:
    from app.core.metrics import approvals_pending
    from app.db.models import ApprovalRequest, ApprovalStatus
    from app.services.agent import AgentOrchestrator

    async with session_scope() as db:
        expired = await AgentOrchestrator(db).expire_stale_approvals()
        pending = len(
            (
                await db.scalars(
                    select(ApprovalRequest).where(
                        ApprovalRequest.status == ApprovalStatus.PENDING.value
                    )
                )
            ).all()
        )
    approvals_pending.set(pending)
    if expired:
        logger.warning("approvals_expired", count=expired, still_pending=pending)


async def sync_cloud_findings() -> None:
    """Pull GuardDuty findings so the cloud view is fresh without a manual sync."""
    from app.db.models import CloudFinding
    from app.integrations.aws import AWSSecurityClient

    client = AWSSecurityClient()
    try:
        findings = await client.guardduty_findings(limit=100)
    except Exception as exc:
        logger.info("cloud_sync_skipped", reason=str(exc)[:200])
        return

    async with session_scope() as db:
        created = 0
        for finding in findings:
            exists = await db.scalar(
                select(CloudFinding).where(CloudFinding.external_id == finding["external_id"])
            )
            if exists is not None:
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
    logger.info("cloud_findings_synced", fetched=len(findings), created=created)


async def enforce_retention() -> None:
    """Delete data past its retention window.

    Audit logs are never touched here — they are the compliance record and are
    archived out of band rather than deleted by a background job.
    """
    from app.db.models import AgentSession, ToolExecution, WorkflowRun

    now = datetime.now(UTC)
    windows = (
        (ToolExecution, timedelta(days=180)),
        (AgentSession, timedelta(days=180)),
        (WorkflowRun, timedelta(days=90)),
    )
    async with session_scope() as db:
        for model, window in windows:
            cutoff = now - window
            result = await db.execute(delete(model).where(model.created_at < cutoff))
            if result.rowcount:
                logger.info("retention_pruned", model=model.__name__, rows=result.rowcount)


TASKS: list[ScheduledTask] = [
    ScheduledTask("probe_integrations", 300, probe_integrations),
    ScheduledTask("expire_approvals", 60, expire_approvals),
    ScheduledTask("sync_cloud_findings", 900, sync_cloud_findings),
    ScheduledTask("enforce_retention", 86_400, enforce_retention),
]

TICK_SECONDS = 15


async def run_scheduler(tasks: list[ScheduledTask] | None = None) -> None:
    """Tick every few seconds and run whatever is due.

    A task that raises is logged and retried on its next interval — one broken
    integration must not stop retention or approval expiry from running.
    """
    configure_logging()
    tasks = tasks or TASKS
    stopping = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        # Not every platform supports signal handlers on the loop; on those the
        # container still stops, just without the graceful drain.
        with contextlib.suppress(NotImplementedError, AttributeError):
            loop.add_signal_handler(sig, stopping.set)

    logger.info("scheduler_started", tasks=[task.name for task in tasks])

    try:
        while not stopping.is_set():
            now = datetime.now(UTC)
            for task in tasks:
                if not task.is_due(now):
                    continue
                task.last_run = now
                try:
                    await task.run()
                except Exception as exc:
                    logger.exception("scheduled_task_failed", task=task.name, error=str(exc))
            try:
                await asyncio.wait_for(stopping.wait(), timeout=TICK_SECONDS)
            except TimeoutError:
                continue
    finally:
        await dispose_engine()
        logger.info("scheduler_stopped")


def main() -> None:
    logger.info("scheduler_booting", environment=settings.environment)
    asyncio.run(run_scheduler())


if __name__ == "__main__":
    main()
