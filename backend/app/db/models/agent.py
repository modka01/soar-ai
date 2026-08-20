"""Agent sessions, transcript messages, tool executions and approval gates."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONBType, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.models.enums import AgentSessionStatus, ApprovalStatus, ExecutionStatus


class AgentSession(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One operator task handed to the agentic loop."""

    __tablename__ = "agent_sessions"
    __table_args__ = (Index("ix_agent_sessions_status_created", "status", "created_at"),)

    task: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=AgentSessionStatus.PENDING.value, index=True
    )
    created_by: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(80), nullable=False)
    iterations: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_iterations: Mapped[int] = mapped_column(Integer, default=6, nullable=False)
    plan: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    plan_cursor: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    final_answer: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    rag_chunk_ids: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    messages: Mapped[list[AgentMessage]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="AgentMessage.sequence",
    )
    approvals: Mapped[list[ApprovalRequest]] = relationship(
        back_populates="session", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            AgentSessionStatus.COMPLETED.value,
            AgentSessionStatus.FAILED.value,
            AgentSessionStatus.STOPPED.value,
        }


class AgentMessage(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A single entry in the agent transcript, replayable by the UI."""

    __tablename__ = "agent_messages"
    __table_args__ = (Index("ix_agent_messages_session_seq", "session_id", "sequence"),)

    session_id: Mapped[str] = mapped_column(
        ForeignKey("agent_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    role: Mapped[str] = mapped_column(String(24), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_final: Mapped[bool] = mapped_column(default=False, nullable=False)
    citations: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    meta: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict, nullable=False)

    session: Mapped[AgentSession] = relationship(back_populates="messages")


class ToolExecution(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Audit record for every MCP tool invocation, agent-driven or manual."""

    __tablename__ = "tool_executions"
    __table_args__ = (Index("ix_tool_executions_tool_created", "tool_name", "created_at"),)

    tool_name: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_sessions.id", ondelete="CASCADE"), index=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    invoked_by: Mapped[str] = mapped_column(String(200), nullable=False, default="agent")
    reason: Mapped[str | None] = mapped_column(Text)
    params: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict, nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ExecutionStatus.PENDING.value, index=True
    )
    error: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    dry_run: Mapped[bool] = mapped_column(default=False, nullable=False)
    approval_id: Mapped[str | None] = mapped_column(
        ForeignKey("approval_requests.id", ondelete="SET NULL")
    )


class ApprovalRequest(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A human-in-the-loop gate in front of a destructive containment action."""

    __tablename__ = "approval_requests"

    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_sessions.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ApprovalStatus.PENDING.value, index=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_actions: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    decided_by: Mapped[str | None] = mapped_column(String(200))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    session: Mapped[AgentSession | None] = relationship(back_populates="approvals")
