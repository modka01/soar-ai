"""Playbooks, workflow runs, threat intel, cloud findings, integration health, settings."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONBType, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.models.enums import ExecutionStatus, HealthState


class Playbook(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A named response procedure, executed step-by-step through n8n."""

    __tablename__ = "playbooks"

    slug: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    icon: Mapped[str] = mapped_column(String(16), nullable=False, default="▶")
    estimated_seconds: Mapped[int] = mapped_column(Integer, default=120, nullable=False)
    n8n_workflow_id: Mapped[str | None] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    steps: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)

    runs: Mapped[list[PlaybookRun]] = relationship(
        back_populates="playbook", cascade="all, delete-orphan"
    )

    @property
    def step_count(self) -> int:
        return len(self.steps)


class PlaybookRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "playbook_runs"
    __table_args__ = (Index("ix_playbook_runs_status_created", "status", "created_at"),)

    playbook_id: Mapped[str] = mapped_column(
        ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ExecutionStatus.PENDING.value, index=True
    )
    triggered_by: Mapped[str] = mapped_column(String(200), nullable=False)
    current_step: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_steps: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    step_results: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    n8n_execution_id: Mapped[str | None] = mapped_column(String(120))
    error: Mapped[str | None] = mapped_column(Text)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    playbook: Mapped[Playbook] = relationship(back_populates="runs")

    @property
    def progress_percent(self) -> int:
        if not self.total_steps:
            return 0
        return min(100, round(self.current_step / self.total_steps * 100))


class WorkflowRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An n8n execution observed through the callback webhook."""

    __tablename__ = "workflow_runs"

    workflow_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    workflow_name: Mapped[str] = mapped_column(String(200), nullable=False)
    execution_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    trigger_source: Mapped[str | None] = mapped_column(String(120))
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    node_results: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)


class ThreatIndicator(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An IOC with its latest enrichment verdict, cached to avoid re-querying."""

    __tablename__ = "threat_indicators"
    __table_args__ = (
        Index("ix_threat_indicators_value_type", "value", "indicator_type", unique=True),
    )

    value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(String(24), nullable=False, default="unknown", index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    threat_actors: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    mitre_techniques: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    sources: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    enrichment: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CloudFinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A finding from an AWS security service (GuardDuty, Config, Macie, IAM…)."""

    __tablename__ = "cloud_findings"
    __table_args__ = (Index("ix_cloud_findings_service_severity", "service", "severity"),)

    provider: Mapped[str] = mapped_column(String(24), nullable=False, default="aws")
    service: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(String(300), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    account_id: Mapped[str | None] = mapped_column(String(32), index=True)
    region: Mapped[str | None] = mapped_column(String(32), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(500))
    resource_type: Mapped[str | None] = mapped_column(String(120))
    external_id: Mapped[str] = mapped_column(String(500), unique=True, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active", index=True)
    remediation: Mapped[str | None] = mapped_column(Text)
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict, nullable=False)


class Integration(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Registered downstream tool plus its most recent health probe."""

    __tablename__ = "integrations"

    slug: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    health: Mapped[str] = mapped_column(
        String(16), nullable=False, default=HealthState.UNKNOWN.value, index=True
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    latency_ms: Mapped[float | None] = mapped_column(Float)
    last_error: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict, nullable=False)


class Setting(Base, TimestampMixin):
    """Namespaced platform configuration, editable from the Settings module.

    Secret values are stored under a separate secret store; this table only
    holds their reference, never the plaintext.
    """

    __tablename__ = "settings"

    namespace: Mapped[str] = mapped_column(String(60), primary_key=True)
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict, nullable=False)
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(200))
