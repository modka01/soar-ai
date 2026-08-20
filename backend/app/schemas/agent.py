"""Agent, approval and MCP tool schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class AgentTaskCreate(BaseModel):
    task: str = Field(min_length=1, max_length=8000, description="What the agent should do")
    incident_id: str | None = None
    max_iterations: int | None = Field(default=None, ge=1, le=20)
    stream: bool = Field(default=True, description="Stream progress over SSE")


class AgentMessageOut(ORMModel):
    id: str
    sequence: int
    role: str
    content: str
    is_final: bool
    citations: list[Any]
    meta: dict[str, Any]
    created_at: datetime


class AgentSessionOut(ORMModel):
    id: str
    task: str
    status: str
    created_by: str
    model: str
    iterations: int
    max_iterations: int
    plan: list[Any]
    plan_cursor: int
    final_answer: str | None
    error: str | None
    input_tokens: int
    output_tokens: int
    incident_id: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class AgentSessionDetail(AgentSessionOut):
    messages: list[AgentMessageOut] = Field(default_factory=list)


class ApprovalOut(ORMModel):
    id: str
    session_id: str | None
    status: str
    reason: str
    requested_actions: list[Any]
    risk_score: float
    decided_by: str | None
    decided_at: datetime | None
    decision_note: str | None
    expires_at: datetime
    created_at: datetime


class ApprovalDecision(BaseModel):
    approved: bool
    note: str | None = Field(default=None, max_length=2000)


class ToolSchemaOut(BaseModel):
    name: str
    label: str
    description: str
    category: str
    risk: str
    icon: str
    mutating: bool
    requires_approval: bool
    schema_: dict[str, Any] = Field(alias="schema")
    calls: int = 0
    success_rate: float = 0.0
    avg_duration_ms: float = 0.0
    last_used_at: datetime | None = None

    model_config = {"populate_by_name": True}


class ToolInvokeRequest(BaseModel):
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None
    incident_id: str | None = None
    dry_run: bool = Field(default=False, description="Force a dry run regardless of settings")


class ToolExecutionOut(ORMModel):
    id: str
    tool_name: str
    session_id: str | None
    incident_id: str | None
    invoked_by: str
    reason: str | None
    params: dict[str, Any]
    result: dict[str, Any]
    status: str
    error: str | None
    duration_ms: int
    dry_run: bool
    created_at: datetime
