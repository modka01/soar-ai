"""Alert ingestion, deduplication, AI risk scoring and triage."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.db.base import ensure_utc
from app.db.models import Alert, AlertStatus, Severity
from app.integrations.llm import LLMClient, get_llm_client
from app.services.rag import RAGService

logger = get_logger(__name__)

#: Window in which an identical alert is folded into the existing row.
DEDUP_WINDOW = timedelta(minutes=15)

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

#: Base risk contributed by the reported severity, before signal adjustments.
_SEVERITY_BASE = {"critical": 80, "high": 60, "medium": 35, "low": 15, "info": 5}

TRIAGE_PROMPT = """You are a Tier-2 SOC analyst triaging a security alert for QuantNexa \
Technologies. Assess it against the knowledge base context provided and reply with a single \
JSON object:

{
  "risk_score": 0-100,
  "verdict": "true_positive" | "false_positive" | "needs_investigation",
  "confidence": 0.0-1.0,
  "summary": "two or three sentences an analyst can act on",
  "mitre_techniques": ["T1234"],
  "recommended_actions": ["..."],
  "auto_close": false
}

Set auto_close true only when the alert is unambiguously benign and closing it risks nothing.
"""


def compute_dedup_key(source: str, title: str, asset: str | None) -> str:
    """Stable fingerprint for near-identical detections from the same source.

    Digits are collapsed in the *title* only, so "847 failed logons" and "912
    failed logons" fold into one alert. The asset is matched verbatim — folding
    ``host-01`` into ``host-02``, or two neighbouring IPs, would hide a second
    compromised machine behind the first one's alert.
    """
    normalised_title = re.sub(r"\d+", "#", title.lower())
    fingerprint = f"{source.lower()}|{normalised_title}|{(asset or '').lower()}"
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:32]


def heuristic_risk_score(
    *,
    severity: str,
    source: str,
    indicators: list[Any],
    mitre_techniques: list[Any],
    asset: str | None,
) -> int:
    """Deterministic baseline score, used when the LLM is unavailable.

    Keeping a non-AI path means the queue still prioritises correctly during an
    Anthropic outage rather than every alert collapsing to the same score.
    """
    score = _SEVERITY_BASE.get(severity, 20)
    if indicators:
        score += min(10, len(indicators) * 3)
    if mitre_techniques:
        score += min(10, len(mitre_techniques) * 4)
    if source.lower() in {"crowdstrike", "guardduty", "aws guardduty"}:
        # Endpoint and cloud-native detections carry a lower false-positive rate.
        score += 5
    if asset and any(marker in asset.lower() for marker in ("dc-", "domain", "prod", "finance")):
        score += 8
    return max(0, min(100, score))


class AlertService:
    """Ingests, deduplicates, scores and queries alerts."""

    def __init__(self, db: AsyncSession, llm: LLMClient | None = None) -> None:
        self.db = db
        self.llm = llm or get_llm_client()

    # ── ingestion ────────────────────────────────────────────────────

    async def ingest(
        self,
        *,
        title: str,
        severity: str,
        source: str,
        description: str | None = None,
        asset: str | None = None,
        asset_type: str | None = None,
        source_event_id: str | None = None,
        detected_at: datetime | None = None,
        indicators: list[Any] | None = None,
        mitre_techniques: list[Any] | None = None,
        raw_event: dict[str, Any] | None = None,
    ) -> tuple[Alert, bool]:
        """Create an alert, or fold it into a recent duplicate.

        Returns ``(alert, created)`` — ``created`` is False when the alert was
        deduplicated into an existing row.
        """
        severity = Severity(severity).value
        detected_at = detected_at or datetime.now(UTC)
        dedup_key = compute_dedup_key(source, title, asset)

        existing = await self.db.scalar(
            select(Alert)
            .where(
                Alert.dedup_key == dedup_key,
                Alert.created_at >= datetime.now(UTC) - DEDUP_WINDOW,
                Alert.status.notin_([AlertStatus.CLOSED.value, AlertStatus.FALSE_POSITIVE.value]),
            )
            .order_by(Alert.created_at.desc())
            .limit(1)
        )
        if existing is not None:
            existing.duplicate_count += 1
            existing.detected_at = max(ensure_utc(existing.detected_at), detected_at)
            await self.db.flush()
            logger.info(
                "alert_deduplicated", alert=existing.reference, duplicates=existing.duplicate_count
            )
            return existing, False

        techniques = list(mitre_techniques or [])
        if not techniques:
            techniques = sorted(set(_TECHNIQUE_RE.findall(f"{title} {description or ''}")))

        alert = Alert(
            reference=await self._next_reference(),
            title=title[:500],
            description=description,
            severity=severity,
            source=source,
            source_event_id=source_event_id,
            asset=asset,
            asset_type=asset_type,
            detected_at=detected_at,
            indicators=list(indicators or []),
            mitre_techniques=techniques,
            raw_event=raw_event or {},
            dedup_key=dedup_key,
            risk_score=heuristic_risk_score(
                severity=severity,
                source=source,
                indicators=list(indicators or []),
                mitre_techniques=techniques,
                asset=asset,
            ),
        )
        self.db.add(alert)
        await self.db.flush()
        logger.info(
            "alert_ingested", alert=alert.reference, severity=severity, risk=alert.risk_score
        )
        return alert, True

    async def _next_reference(self) -> str:
        count = int(await self.db.scalar(select(func.count()).select_from(Alert)) or 0)
        return f"ALT-{1000 + count + 1}"

    # ── triage ───────────────────────────────────────────────────────

    async def triage(self, alert_id: str, *, actor: str = "ai-agent") -> Alert:
        """Score and summarise an alert with the LLM, grounded in RAG context."""
        alert = await self.get(alert_id)

        rag = RAGService(self.db)
        context_results = await rag.retrieve(f"{alert.title} {alert.description or ''}", top_k=4)
        context = RAGService.build_context(context_results)

        payload = {
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "source": alert.source,
            "asset": alert.asset,
            "indicators": alert.indicators,
            "mitre_techniques": alert.mitre_techniques,
            "duplicate_count": alert.duplicate_count,
        }
        system = TRIAGE_PROMPT + (f"\n\nKnowledge base context:\n{context}" if context else "")

        try:
            verdict, _ = await self.llm.complete_json(
                [{"role": "user", "content": f"Triage this alert:\n{payload}"}],
                system=system,
                max_tokens=1000,
            )
        except Exception as exc:
            # Falling back to the heuristic keeps triage functional in an outage.
            logger.warning("alert_triage_llm_failed", alert=alert.reference, error=str(exc))
            alert.ai_summary = (
                f"AI triage unavailable; heuristic score applied. Reason: {str(exc)[:200]}"
            )
            await self.db.flush()
            return alert

        alert.risk_score = int(verdict.get("risk_score", alert.risk_score))
        alert.confidence = float(verdict.get("confidence", 0.0))
        alert.ai_summary = str(verdict.get("summary", ""))[:4000]
        alert.ai_triaged = True
        if verdict.get("mitre_techniques"):
            alert.mitre_techniques = list(verdict["mitre_techniques"])

        if verdict.get("auto_close") and verdict.get("verdict") == "false_positive":
            alert.status = AlertStatus.FALSE_POSITIVE.value
            alert.closed_at = datetime.now(UTC)
        elif alert.status == AlertStatus.OPEN.value:
            alert.status = AlertStatus.INVESTIGATING.value

        await self.db.flush()
        logger.info(
            "alert_triaged",
            alert=alert.reference,
            risk=alert.risk_score,
            verdict=verdict.get("verdict"),
            actor=actor,
        )
        return alert

    async def bulk_triage(self, *, limit: int = 25, actor: str = "ai-agent") -> list[Alert]:
        """Triage the highest-risk untriaged open alerts."""
        candidates = list(
            (
                await self.db.scalars(
                    select(Alert)
                    .where(
                        Alert.ai_triaged.is_(False),
                        Alert.status.in_([AlertStatus.OPEN.value, AlertStatus.INVESTIGATING.value]),
                    )
                    .order_by(Alert.risk_score.desc(), Alert.detected_at.desc())
                    .limit(limit)
                )
            ).all()
        )
        return [await self.triage(alert.id, actor=actor) for alert in candidates]

    # ── queries ──────────────────────────────────────────────────────

    async def get(self, alert_id: str) -> Alert:
        alert = await self.db.get(Alert, alert_id)
        if alert is None:
            alert = await self.db.scalar(select(Alert).where(Alert.reference == alert_id))
        if alert is None:
            raise NotFoundError(f"Alert {alert_id} does not exist.")
        return alert

    async def list(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Alert], int]:
        statement = select(Alert)
        count_statement = select(func.count()).select_from(Alert)

        conditions = []
        if severity:
            conditions.append(Alert.severity == severity.lower())
        if status:
            conditions.append(Alert.status == status.lower())
        if source:
            conditions.append(Alert.source == source)
        if search:
            conditions.append(func.lower(Alert.title).like(f"%{search.lower()}%"))
        for condition in conditions:
            statement = statement.where(condition)
            count_statement = count_statement.where(condition)

        total = int(await self.db.scalar(count_statement) or 0)
        rows = list(
            (
                await self.db.scalars(
                    statement.order_by(Alert.risk_score.desc(), Alert.detected_at.desc())
                    .limit(limit)
                    .offset(offset)
                )
            ).all()
        )
        return rows, total

    async def update_status(self, alert_id: str, status: str, *, actor: str) -> Alert:
        alert = await self.get(alert_id)
        alert.status = AlertStatus(status).value
        if alert.status in {AlertStatus.CLOSED.value, AlertStatus.FALSE_POSITIVE.value}:
            alert.closed_at = datetime.now(UTC)
        alert.assignee = actor
        await self.db.flush()
        return alert

    async def severity_distribution(self, *, hours: int = 24) -> dict[str, Any]:
        """Counts by severity plus the automation rate, for the dashboard."""
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = (
            await self.db.execute(
                select(Alert.severity, func.count())
                .where(Alert.detected_at >= since)
                .group_by(Alert.severity)
            )
        ).all()
        counts = {severity: int(count) for severity, count in rows}
        total = sum(counts.values())

        automated = int(
            await self.db.scalar(
                select(func.count())
                .select_from(Alert)
                .where(
                    Alert.detected_at >= since,
                    Alert.status.in_(
                        [AlertStatus.AUTOMATED.value, AlertStatus.FALSE_POSITIVE.value]
                    ),
                )
            )
            or 0
        )
        return {
            "window_hours": hours,
            "total": total,
            "counts": {level.value: counts.get(level.value, 0) for level in Severity},
            "automated": automated,
            "automation_rate": round(automated / total * 100, 1) if total else 0.0,
        }
