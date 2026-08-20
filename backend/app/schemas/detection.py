"""Sigma rule schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.db.models.enums import RuleStatus, Severity
from app.schemas.common import ORMModel


class SigmaGenerateRequest(BaseModel):
    scenario: str = Field(min_length=5, max_length=4000)
    tactic: str = Field(default="Lateral Movement", max_length=80)
    log_source: str = Field(default="Windows EventLog", max_length=80)
    severity: Severity = Severity.HIGH
    use_ai: bool = Field(default=True, description="Use the LLM to author the detection logic")
    source_incident_id: str | None = None
    save: bool = Field(default=True, description="Persist the generated rule as a draft")


class SigmaRuleOut(ORMModel):
    id: str
    reference: str
    rule_uuid: str
    name: str
    description: str | None
    tactic: str
    log_source: str
    severity: str
    status: str
    yaml_body: str
    mitre_techniques: list[Any]
    false_positives: list[Any]
    author: str
    ai_generated: bool
    version: int
    created_at: datetime


class SigmaRuleUpdate(BaseModel):
    yaml_body: str = Field(min_length=10)


class SigmaStatusUpdate(BaseModel):
    status: RuleStatus


class SigmaDeployRequest(BaseModel):
    backends: list[str] = Field(min_length=1, description="splunk | elastic | sentinel | qradar")


class RuleDeploymentOut(ORMModel):
    id: str
    backend: str
    converted_query: str
    status: str
    deployed_by: str
    deployed_at: datetime | None
    error: str | None


class SigmaValidateRequest(BaseModel):
    yaml_body: str = Field(min_length=10)


class SigmaConvertRequest(BaseModel):
    yaml_body: str = Field(min_length=10)
    backend: str = Field(default="splunk")
