"""Alerts, incidents and the incident timeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONBType, TimestampMixin, UUIDPrimaryKeyMixin, ensure_utc
from app.db.models.enums import AlertStatus, IncidentStatus, Severity


class Alert(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A normalised detection from any upstream source (SIEM, EDR, cloud)."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_severity_status", "severity", "status"),
        Index("ix_alerts_dedup", "dedup_key", "created_at"),
    )

    reference: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=AlertStatus.OPEN.value, index=True
    )
    source: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    source_event_id: Mapped[str | None] = mapped_column(String(200))
    asset: Mapped[str | None] = mapped_column(String(255), index=True)
    asset_type: Mapped[str | None] = mapped_column(String(40))
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    ai_triaged: Mapped[bool] = mapped_column(default=False, nullable=False)
    ai_summary: Mapped[str | None] = mapped_column(Text)
    mitre_techniques: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    indicators: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict, nullable=False)
    dedup_key: Mapped[str | None] = mapped_column(String(64), index=True)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    assignee: Mapped[str | None] = mapped_column(String(200))

    incident: Mapped[Incident | None] = relationship(back_populates="alerts")

    @property
    def severity_enum(self) -> Severity:
        return Severity(self.severity)


class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A case correlating one or more alerts, with a full response timeline."""

    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_severity_status", "severity", "status"),)

    reference: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=IncidentStatus.OPEN.value, index=True
    )
    asset: Mapped[str | None] = mapped_column(String(255), index=True)
    owner: Mapped[str | None] = mapped_column(String(200), index=True)
    ai_summary: Mapped[str | None] = mapped_column(Text)
    mitre_techniques: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    indicators: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    tags: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    external_ticket_id: Mapped[str | None] = mapped_column(String(120))
    external_ticket_url: Mapped[str | None] = mapped_column(String(500))

    alerts: Mapped[list[Alert]] = relationship(back_populates="incident", lazy="selectin")
    events: Mapped[list[IncidentEvent]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="IncidentEvent.occurred_at",
    )

    @property
    def mttr_minutes(self) -> float | None:
        """Mean time to resolve, in minutes — ``None`` while the case is open."""
        if not self.closed_at:
            return None
        closed = ensure_utc(self.closed_at)
        detected = ensure_utc(self.detected_at)
        if closed is None or detected is None:
            return None
        return (closed - detected).total_seconds() / 60


class IncidentEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One entry on an incident's response timeline."""

    __tablename__ = "incident_events"

    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False, default="note")
    actor: Mapped[str] = mapped_column(String(200), nullable=False, default="system")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str | None] = mapped_column(String(80))
    severity: Mapped[str | None] = mapped_column(String(16))
    detail: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="events")
