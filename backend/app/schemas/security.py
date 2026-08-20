"""Alert, incident and threat-intel schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.db.models.enums import AlertStatus, IncidentStatus, Severity
from app.schemas.common import ORMModel


class AlertIngest(BaseModel):
    """Payload accepted by the alert ingestion webhook."""

    title: str = Field(min_length=1, max_length=500)
    severity: Severity
    source: str = Field(min_length=1, max_length=80)
    description: str | None = None
    asset: str | None = Field(default=None, max_length=255)
    asset_type: str | None = None
    source_event_id: str | None = None
    detected_at: datetime | None = None
    indicators: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    raw_event: dict[str, Any] = Field(default_factory=dict)


class AlertOut(ORMModel):
    id: str
    reference: str
    title: str
    description: str | None
    severity: str
    status: str
    source: str
    asset: str | None
    risk_score: int
    confidence: float
    ai_triaged: bool
    ai_summary: str | None
    mitre_techniques: list[Any]
    indicators: list[Any]
    duplicate_count: int
    detected_at: datetime
    closed_at: datetime | None
    incident_id: str | None
    assignee: str | None
    created_at: datetime


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class BulkTriageRequest(BaseModel):
    limit: int = Field(default=25, ge=1, le=100)


class IncidentEventOut(ORMModel):
    id: str
    occurred_at: datetime
    kind: str
    actor: str
    message: str
    tool_name: str | None
    severity: str | None
    detail: dict[str, Any]


class IncidentOut(ORMModel):
    id: str
    reference: str
    title: str
    description: str | None
    severity: str
    status: str
    asset: str | None
    owner: str | None
    ai_summary: str | None
    mitre_techniques: list[Any]
    indicators: list[Any]
    tags: list[Any]
    detected_at: datetime
    contained_at: datetime | None
    closed_at: datetime | None
    external_ticket_id: str | None
    external_ticket_url: str | None
    created_at: datetime


class IncidentDetail(IncidentOut):
    events: list[IncidentEventOut] = Field(default_factory=list)
    alerts: list[AlertOut] = Field(default_factory=list)
    mttr_minutes: float | None = None


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    severity: Severity
    description: str | None = None
    asset: str | None = None
    owner: str | None = None
    alert_ids: list[str] = Field(default_factory=list)


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus


class IncidentEventCreate(BaseModel):
    message: str = Field(min_length=1)
    kind: str = "note"
    severity: Severity | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class ThreatIndicatorOut(ORMModel):
    id: str
    value: str
    indicator_type: str
    description: str | None
    verdict: str
    confidence: int
    threat_actors: list[Any]
    mitre_techniques: list[Any]
    sources: list[Any]
    first_seen: datetime | None
    last_seen: datetime | None


class EnrichRequest(BaseModel):
    value: str = Field(min_length=1, max_length=500)
    indicator_type: str | None = None
    force: bool = False
