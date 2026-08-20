"""Incident case management: correlation, timeline, AI summary, metrics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.db.models import Alert, Incident, IncidentEvent, IncidentStatus, Severity
from app.integrations.llm import LLMClient, get_llm_client
from app.services.rag import RAGService

logger = get_logger(__name__)

#: Alerts on the same asset within this window are correlated into one case.
CORRELATION_WINDOW = timedelta(hours=4)

SUMMARY_PROMPT = """You are writing the executive summary of a security incident for QuantNexa \
Technologies. Be precise and factual — no speculation beyond the evidence given. Reply with a \
single JSON object:

{
  "summary": "3-5 sentences: what happened, blast radius, current containment state",
  "attack_narrative": "the chain of events in order",
  "recommended_actions": ["prioritised next steps for the responder"],
  "mitre_techniques": ["T1234"],
  "severity_assessment": "critical|high|medium|low"
}
"""


class IncidentService:
    def __init__(self, db: AsyncSession, llm: LLMClient | None = None) -> None:
        self.db = db
        self.llm = llm or get_llm_client()

    # ── creation and correlation ─────────────────────────────────────

    async def create(
        self,
        *,
        title: str,
        severity: str,
        description: str | None = None,
        asset: str | None = None,
        owner: str | None = None,
        detected_at: datetime | None = None,
        alert_ids: list[str] | None = None,
        created_by: str = "system",
    ) -> Incident:
        incident = Incident(
            reference=await self._next_reference(),
            title=title[:500],
            description=description,
            severity=Severity(severity).value,
            asset=asset,
            owner=owner,
            detected_at=detected_at or datetime.now(UTC),
        )
        self.db.add(incident)
        await self.db.flush()

        if alert_ids:
            await self.attach_alerts(incident.id, alert_ids)

        await self.add_event(
            incident.id,
            message=f"Incident {incident.reference} opened.",
            actor=created_by,
            kind="created",
        )
        logger.info("incident_created", incident=incident.reference, severity=incident.severity)
        return incident

    async def _next_reference(self) -> str:
        count = int(await self.db.scalar(select(func.count()).select_from(Incident)) or 0)
        return f"INC-{40 + count + 1:03d}"

    async def correlate_alert(self, alert: Alert, *, created_by: str = "correlation") -> Incident:
        """Attach an alert to an open case on the same asset, or open a new one.

        Correlating by asset within a short window is deliberately simple and
        predictable — an analyst can always re-parent a case manually, whereas a
        clever heuristic that merges unrelated activity is hard to unpick.
        """
        if alert.asset:
            existing = await self.db.scalar(
                select(Incident)
                .where(
                    Incident.asset == alert.asset,
                    Incident.status.notin_([IncidentStatus.CLOSED.value]),
                    Incident.detected_at >= datetime.now(UTC) - CORRELATION_WINDOW,
                )
                .order_by(Incident.detected_at.desc())
                .limit(1)
            )
            if existing is not None:
                alert.incident_id = existing.id
                if Severity(alert.severity).rank > Severity(existing.severity).rank:
                    existing.severity = alert.severity
                await self.add_event(
                    existing.id,
                    message=f"Alert {alert.reference} correlated: {alert.title}",
                    actor=created_by,
                    kind="alert_linked",
                    severity=alert.severity,
                )
                await self.db.flush()
                return existing

        incident = await self.create(
            title=alert.title,
            severity=alert.severity,
            description=alert.description,
            asset=alert.asset,
            detected_at=alert.detected_at,
            alert_ids=[alert.id],
            created_by=created_by,
        )
        return incident

    async def attach_alerts(self, incident_id: str, alert_ids: list[str]) -> Incident:
        incident = await self.get(incident_id)
        for alert_id in alert_ids:
            alert = await self.db.get(Alert, alert_id)
            if alert is None:
                continue
            alert.incident_id = incident.id
            if Severity(alert.severity).rank > Severity(incident.severity).rank:
                incident.severity = alert.severity
        await self.db.flush()
        return incident

    # ── timeline ─────────────────────────────────────────────────────

    async def add_event(
        self,
        incident_id: str,
        *,
        message: str,
        actor: str = "system",
        kind: str = "note",
        tool_name: str | None = None,
        severity: str | None = None,
        detail: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> IncidentEvent:
        event = IncidentEvent(
            incident_id=incident_id,
            occurred_at=occurred_at or datetime.now(UTC),
            kind=kind,
            actor=actor,
            message=message,
            tool_name=tool_name,
            severity=severity,
            detail=detail or {},
        )
        self.db.add(event)
        await self.db.flush()
        return event

    # ── AI summary ───────────────────────────────────────────────────

    async def generate_summary(self, incident_id: str) -> Incident:
        incident = await self.get(incident_id)

        rag = RAGService(self.db)
        context_results = await rag.retrieve(
            f"{incident.title} {incident.description or ''}", top_k=4
        )
        context = RAGService.build_context(context_results)

        timeline = [
            {"at": event.occurred_at.isoformat(), "actor": event.actor, "what": event.message}
            for event in incident.events
        ]
        payload = {
            "reference": incident.reference,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "asset": incident.asset,
            "description": incident.description,
            "indicators": incident.indicators,
            "mitre_techniques": incident.mitre_techniques,
            "alerts": [
                {"reference": a.reference, "title": a.title, "severity": a.severity}
                for a in incident.alerts
            ],
            "timeline": timeline,
        }
        system = SUMMARY_PROMPT + (f"\n\nKnowledge base context:\n{context}" if context else "")

        result, _ = await self.llm.complete_json(
            [{"role": "user", "content": f"Summarise this incident:\n{payload}"}],
            system=system,
            max_tokens=1500,
        )

        incident.ai_summary = str(result.get("summary", ""))[:8000]
        if result.get("mitre_techniques"):
            incident.mitre_techniques = list(result["mitre_techniques"])
        await self.add_event(
            incident.id,
            message="AI analyst generated an incident summary.",
            actor="ai-agent",
            kind="ai_summary",
            detail={
                "attack_narrative": result.get("attack_narrative"),
                "recommended_actions": result.get("recommended_actions", []),
                "severity_assessment": result.get("severity_assessment"),
            },
        )
        await self.db.flush()
        return incident

    # ── queries and state ────────────────────────────────────────────

    async def get(self, incident_id: str) -> Incident:
        incident = await self.db.get(Incident, incident_id)
        if incident is None:
            incident = await self.db.scalar(
                select(Incident).where(Incident.reference == incident_id)
            )
        if incident is None:
            raise NotFoundError(f"Incident {incident_id} does not exist.")
        return incident

    async def list(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        owner: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Incident], int]:
        statement = select(Incident)
        count_statement = select(func.count()).select_from(Incident)

        conditions = []
        if severity:
            conditions.append(Incident.severity == severity.lower())
        if status:
            conditions.append(Incident.status == status.lower())
        if owner:
            conditions.append(Incident.owner == owner)
        for condition in conditions:
            statement = statement.where(condition)
            count_statement = count_statement.where(condition)

        total = int(await self.db.scalar(count_statement) or 0)
        rows = list(
            (
                await self.db.scalars(
                    statement.order_by(Incident.detected_at.desc()).limit(limit).offset(offset)
                )
            ).all()
        )
        return rows, total

    async def update_status(self, incident_id: str, status: str, *, actor: str) -> Incident:
        incident = await self.get(incident_id)
        previous = incident.status
        incident.status = IncidentStatus(status).value

        now = datetime.now(UTC)
        if incident.status == IncidentStatus.CONTAINED.value and not incident.contained_at:
            incident.contained_at = now
        if incident.status == IncidentStatus.CLOSED.value:
            incident.closed_at = now

        await self.add_event(
            incident.id,
            message=f"Status changed {previous} → {incident.status}.",
            actor=actor,
            kind="status_change",
        )
        await self.db.flush()
        return incident

    async def metrics(self, *, days: int = 30) -> dict[str, Any]:
        """Dashboard metrics: open counts, MTTR, automation."""
        since = datetime.now(UTC) - timedelta(days=days)

        open_count = int(
            await self.db.scalar(
                select(func.count())
                .select_from(Incident)
                .where(Incident.status.notin_([IncidentStatus.CLOSED.value]))
            )
            or 0
        )
        critical_open = int(
            await self.db.scalar(
                select(func.count())
                .select_from(Incident)
                .where(
                    Incident.status.notin_([IncidentStatus.CLOSED.value]),
                    Incident.severity == Severity.CRITICAL.value,
                )
            )
            or 0
        )

        closed = list(
            (
                await self.db.scalars(
                    select(Incident).where(
                        Incident.closed_at.isnot(None), Incident.detected_at >= since
                    )
                )
            ).all()
        )
        mttrs = [i.mttr_minutes for i in closed if i.mttr_minutes is not None]

        return {
            "window_days": days,
            "open_incidents": open_count,
            "critical_open": critical_open,
            "resolved": len(closed),
            "mttr_minutes": round(sum(mttrs) / len(mttrs), 1) if mttrs else None,
            "mttr_p90_minutes": (
                round(sorted(mttrs)[int(len(mttrs) * 0.9)], 1) if len(mttrs) >= 10 else None
            ),
        }
