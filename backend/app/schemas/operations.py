"""Playbook, workflow, cloud and settings schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class PlaybookOut(ORMModel):
    id: str
    slug: str
    name: str
    description: str
    severity: str
    icon: str
    estimated_seconds: int
    enabled: bool
    requires_approval: bool
    steps: list[Any]


class PlaybookRunRequest(BaseModel):
    incident_id: str | None = None
    alert_id: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool | None = Field(
        default=None, description="Override the platform's destructive-action setting"
    )


class PlaybookRunOut(ORMModel):
    id: str
    playbook_id: str
    incident_id: str | None
    alert_id: str | None
    status: str
    triggered_by: str
    current_step: int
    total_steps: int
    step_results: list[Any]
    n8n_execution_id: str | None
    error: str | None
    dry_run: bool
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class WorkflowOut(BaseModel):
    id: str
    name: str
    active: bool
    tags: list[str] = Field(default_factory=list)
    updated_at: str | None = None
    nodes: list[dict[str, Any]] = Field(default_factory=list)


class WorkflowRunOut(ORMModel):
    id: str
    workflow_id: str
    workflow_name: str
    execution_id: str
    status: str
    trigger_source: str | None
    duration_ms: int
    error: str | None
    created_at: datetime


class CloudFindingOut(ORMModel):
    id: str
    provider: str
    service: str
    finding_type: str
    title: str
    description: str | None
    severity: str
    account_id: str | None
    region: str | None
    resource_id: str | None
    resource_type: str | None
    status: str
    remediation: str | None
    remediated_at: datetime | None
    created_at: datetime


class RemediateRequest(BaseModel):
    action: str = Field(
        description="block_sg | revoke_iam | block_s3 | snapshot_ec2 | disable_access_key"
    )
    resource_id: str = Field(min_length=1)
    region: str | None = None
    reason: str = Field(default="SOAR remediation", max_length=500)


class IntegrationOut(BaseModel):
    slug: str
    name: str
    category: str
    health: str
    latency_ms: float | None = None
    last_checked_at: datetime | None = None
    last_error: str | None = None


class SettingsUpdate(BaseModel):
    values: dict[str, Any]


class AuditLogOut(ORMModel):
    id: str
    actor: str
    actor_type: str
    action: str
    resource_type: str | None
    resource_id: str | None
    outcome: str
    source_ip: str | None
    request_id: str | None
    detail: dict[str, Any]
    created_at: datetime


class DashboardMetrics(BaseModel):
    """Everything the Dashboard module renders in one round trip."""

    critical_alerts: int
    open_incidents: int
    auto_resolved: int
    mttr_minutes: float | None
    alert_distribution: dict[str, Any]
    incident_metrics: dict[str, Any]
    integration_health: dict[str, Any]
    tool_usage: list[dict[str, Any]]
    recent_alerts: list[dict[str, Any]]
