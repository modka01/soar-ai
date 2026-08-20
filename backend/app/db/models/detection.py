"""Sigma detection rules and their deployment records."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONBType, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.models.enums import RuleStatus


class SigmaRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "sigma_rules"
    __table_args__ = (Index("ix_sigma_rules_tactic_severity", "tactic", "severity"),)

    reference: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    rule_uuid: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    tactic: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    log_source: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=RuleStatus.DRAFT.value, index=True
    )
    yaml_body: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_techniques: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    false_positives: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    author: Mapped[str] = mapped_column(String(200), nullable=False)
    ai_generated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source_incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL")
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    deployments: Mapped[list[RuleDeployment]] = relationship(
        back_populates="rule", cascade="all, delete-orphan", lazy="selectin"
    )


class RuleDeployment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Tracks a rule pushed to one SIEM backend, with the converted query."""

    __tablename__ = "rule_deployments"

    rule_id: Mapped[str] = mapped_column(
        ForeignKey("sigma_rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    backend: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    converted_query: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    deployed_by: Mapped[str] = mapped_column(String(200), nullable=False)
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    external_id: Mapped[str | None] = mapped_column(String(200))
    error: Mapped[str | None] = mapped_column(Text)

    rule: Mapped[SigmaRule] = relationship(back_populates="deployments")
