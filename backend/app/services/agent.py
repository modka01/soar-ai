"""The agentic loop: analyse → plan → call tools → observe → act.

The loop is *resumable*. Each iteration is persisted (messages, plan cursor,
tool executions), so a session interrupted by a pod restart or an approval
gate can be continued rather than restarted. Events are published to the event
bus so any replica can stream them to the operator's browser over SSE.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.db.base import ensure_utc
from app.db.models import (
    AgentMessage,
    AgentSession,
    AgentSessionStatus,
    ApprovalRequest,
    ApprovalStatus,
    MessageRole,
)
from app.integrations.llm import LLMClient, get_llm_client
from app.services.events import EventBus, get_event_bus
from app.services.mcp import ToolRegistry, get_registry
from app.services.rag import RAGService, RetrievalResult

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are the autonomous security operations agent for QuantNexa Technologies' \
SOAR·AI platform. You run an agentic loop: analyse the task, plan, call tools, observe results, \
reason, and act.

Available MCP tools: {tool_names}

You MUST reply with a single valid JSON object and nothing else:
{{
  "thought": "your private reasoning about the current state",
  "plan": ["ordered", "steps", "for the whole task"],
  "tool_calls": [{{"tool": "tool_name", "params": {{}}, "reason": "why this call"}}],
  "message": "a short status update for the human operator",
  "needs_approval": false,
  "approval_reason": "",
  "final_answer": ""
}}

Operating rules:
- Enrich an indicator before you act on it. Never block or isolate on an unverified IOC.
- Set needs_approval=true for any containment action: isolate_host, block_ip, \
aws_remediate with revoke_iam, and run_playbook for destructive playbooks.
- Create a ticket for every Critical or High finding so a human can follow up.
- Prefer the least disruptive action that resolves the risk.
- Cite the knowledge-base context you relied on inside "message" when it changed your decision.
- Set "final_answer" only when the whole task is complete. Include what you did, \
what you found, and what a human should do next.
- If a tool reports it is not configured, say so plainly rather than guessing at the result.
"""


@dataclass(slots=True)
class AgentEvent:
    """One streamed unit of agent progress."""

    type: str
    data: dict[str, Any]

    def sse(self) -> str:
        return f"event: {self.type}\ndata: {json.dumps(self.data, default=str)}\n\n"


class AgentOrchestrator:
    """Drives one agent session to completion."""

    def __init__(
        self,
        db: AsyncSession,
        *,
        registry: ToolRegistry | None = None,
        llm: LLMClient | None = None,
        bus: EventBus | None = None,
    ) -> None:
        self.db = db
        self.registry = registry or get_registry()
        self.llm = llm or get_llm_client()
        self.bus = bus or get_event_bus()

    # ── session lifecycle ────────────────────────────────────────────

    async def create_session(
        self,
        task: str,
        *,
        created_by: str,
        incident_id: str | None = None,
        max_iterations: int | None = None,
    ) -> AgentSession:
        session = AgentSession(
            task=task,
            created_by=created_by,
            incident_id=incident_id,
            model=self.llm.model,
            max_iterations=max_iterations or settings.agent_max_iterations,
            status=AgentSessionStatus.PENDING.value,
        )
        self.db.add(session)
        await self.db.flush()
        await self._append_message(session, MessageRole.USER, task)
        logger.info("agent_session_created", session_id=session.id, created_by=created_by)
        return session

    async def get_session(self, session_id: str) -> AgentSession:
        session = await self.db.get(AgentSession, session_id)
        if session is None:
            raise NotFoundError(f"Agent session {session_id} does not exist.")
        return session

    async def stop_session(self, session_id: str, *, stopped_by: str) -> AgentSession:
        session = await self.get_session(session_id)
        if session.is_terminal:
            return session
        session.status = AgentSessionStatus.STOPPED.value
        session.finished_at = datetime.now(UTC)
        await self._append_message(session, MessageRole.SYSTEM, f"Agent stopped by {stopped_by}.")
        await self.db.flush()
        await self.bus.publish(session.id, AgentEvent("stopped", {"by": stopped_by}))
        logger.info("agent_session_stopped", session_id=session_id, by=stopped_by)
        return session

    # ── main loop ────────────────────────────────────────────────────

    async def run(self, session_id: str) -> AsyncIterator[AgentEvent]:
        """Execute the loop, yielding events as they happen.

        The caller streams these to the operator. Every event is also published
        to the bus so a second viewer (or a reconnecting one) sees the same feed.
        """
        session = await self.get_session(session_id)
        if session.is_terminal:
            raise ConflictError(f"Agent session {session_id} has already finished.")

        session.status = AgentSessionStatus.THINKING.value
        session.started_at = session.started_at or datetime.now(UTC)
        await self.db.flush()

        rag_results = await self._retrieve_context(session)
        yield await self._emit(
            session, AgentEvent("context", {"chunks": [r.to_dict() for r in rag_results]})
        )

        system_prompt = self._build_system_prompt(rag_results)
        transcript = await self._load_transcript(session)

        try:
            while session.iterations < session.max_iterations:
                session.iterations += 1
                session.status = AgentSessionStatus.THINKING.value
                await self.db.flush()
                yield await self._emit(
                    session, AgentEvent("iteration", {"iteration": session.iterations})
                )

                response, usage = await self.llm.complete_json(
                    transcript, system=system_prompt, max_tokens=settings.anthropic_max_tokens
                )
                session.input_tokens += usage.input_tokens
                session.output_tokens += usage.output_tokens

                async for event in self._handle_response(session, response, rag_results):
                    yield event

                transcript.append({"role": "assistant", "content": json.dumps(response)})

                if session.status == AgentSessionStatus.AWAITING_APPROVAL.value:
                    # The loop parks here; deciding the approval resumes it.
                    await self.db.flush()
                    return

                tool_calls = response.get("tool_calls") or []
                if tool_calls:
                    observations = await self._execute_tools(session, tool_calls)
                    async for event in self._emit_tool_events(session, observations):
                        yield event
                    transcript.append(
                        {"role": "user", "content": self._format_observations(observations)}
                    )

                if response.get("final_answer"):
                    await self._finish(session, response["final_answer"], rag_results)
                    yield await self._emit(
                        session,
                        AgentEvent(
                            "final",
                            {
                                "answer": response["final_answer"],
                                "iterations": session.iterations,
                                "tokens": {
                                    "input": session.input_tokens,
                                    "output": session.output_tokens,
                                },
                            },
                        ),
                    )
                    return

                if not tool_calls:
                    # No tools left to run and no final answer — treat the last
                    # message as the conclusion rather than looping pointlessly.
                    await self._finish(
                        session, response.get("message", ""), rag_results, implicit=True
                    )
                    yield await self._emit(
                        session, AgentEvent("final", {"answer": response.get("message", "")})
                    )
                    return

            await self._finish(
                session,
                f"Reached the {session.max_iterations}-iteration limit without a conclusion. "
                "Review the transcript and re-task with a narrower objective.",
                rag_results,
                implicit=True,
            )
            yield await self._emit(
                session, AgentEvent("exhausted", {"iterations": session.iterations})
            )

        except Exception as exc:
            logger.exception("agent_run_failed", session_id=session.id)
            session.status = AgentSessionStatus.FAILED.value
            session.error = str(exc)[:2000]
            session.finished_at = datetime.now(UTC)
            await self._append_message(session, MessageRole.ERROR, f"Agent error: {exc}")
            await self.db.flush()
            yield await self._emit(session, AgentEvent("error", {"message": str(exc)[:500]}))

    # ── response handling ────────────────────────────────────────────

    async def _handle_response(
        self,
        session: AgentSession,
        response: dict[str, Any],
        rag_results: list[RetrievalResult],
    ) -> AsyncIterator[AgentEvent]:
        if response.get("plan"):
            session.plan = [str(step) for step in response["plan"]]
            await self.db.flush()
            yield await self._emit(
                session, AgentEvent("plan", {"steps": session.plan, "cursor": session.plan_cursor})
            )

        if response.get("thought"):
            await self._append_message(session, MessageRole.THOUGHT, str(response["thought"]))
            yield await self._emit(session, AgentEvent("thought", {"text": response["thought"]}))

        if response.get("message"):
            await self._append_message(
                session,
                MessageRole.ASSISTANT,
                str(response["message"]),
                citations=[r.to_dict() for r in rag_results],
            )
            yield await self._emit(session, AgentEvent("message", {"text": response["message"]}))

        tool_calls = response.get("tool_calls") or []
        needs_approval = bool(response.get("needs_approval")) or any(
            self.registry.has(str(call.get("tool")))
            and self.registry.requires_approval(str(call["tool"]))
            for call in tool_calls
            if call.get("tool")
        )

        if needs_approval and tool_calls:
            approval = await self._request_approval(
                session,
                tool_calls,
                response.get("approval_reason") or "Containment action proposed",
            )
            yield await self._emit(
                session,
                AgentEvent(
                    "approval_required",
                    {
                        "approval_id": approval.id,
                        "reason": approval.reason,
                        "actions": approval.requested_actions,
                        "expires_at": approval.expires_at.isoformat(),
                    },
                ),
            )

    async def _request_approval(
        self, session: AgentSession, tool_calls: list[dict[str, Any]], reason: str
    ) -> ApprovalRequest:
        approval = ApprovalRequest(
            session_id=session.id,
            reason=reason,
            requested_actions=[
                {
                    "tool": call.get("tool"),
                    "params": call.get("params", {}),
                    "reason": call.get("reason", ""),
                    "risk": (
                        self.registry.get(str(call["tool"])).risk.value
                        if call.get("tool") and self.registry.has(str(call["tool"]))
                        else "unknown"
                    ),
                }
                for call in tool_calls
            ],
            risk_score=self._risk_score(tool_calls),
            expires_at=datetime.now(UTC) + timedelta(seconds=settings.approval_timeout_seconds),
        )
        self.db.add(approval)
        session.status = AgentSessionStatus.AWAITING_APPROVAL.value
        await self.db.flush()
        logger.info("agent_approval_requested", session_id=session.id, approval_id=approval.id)
        return approval

    def _risk_score(self, tool_calls: list[dict[str, Any]]) -> float:
        weights = {"read_only": 0.0, "low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
        scores = [
            weights.get(self.registry.get(str(c["tool"])).risk.value, 0.5)
            for c in tool_calls
            if c.get("tool") and self.registry.has(str(c["tool"]))
        ]
        return round(max(scores) if scores else 0.0, 2)

    # ── tool execution ───────────────────────────────────────────────

    async def _execute_tools(
        self, session: AgentSession, tool_calls: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        session.status = AgentSessionStatus.EXECUTING.value
        await self.db.flush()

        observations: list[dict[str, Any]] = []
        for call in tool_calls:
            name = str(call.get("tool", ""))
            params = call.get("params") or {}
            reason = call.get("reason", "")

            if not self.registry.has(name):
                observations.append(
                    {
                        "tool": name,
                        "ok": False,
                        "result": {"error": f"Tool '{name}' is not registered."},
                        "duration_ms": 0,
                    }
                )
                continue

            result, record = await self.registry.execute(
                self.db,
                name,
                params,
                invoked_by=f"agent:{session.created_by}",
                session_id=session.id,
                incident_id=session.incident_id,
                reason=reason,
            )
            observations.append(
                {
                    "tool": name,
                    "ok": result.ok,
                    "params": record.params,
                    "reason": reason,
                    "result": result.to_dict(),
                    "duration_ms": result.duration_ms,
                    "dry_run": result.dry_run,
                    "execution_id": record.id,
                }
            )
            self._advance_plan(session, name)

        await self.db.flush()
        return observations

    def _advance_plan(self, session: AgentSession, tool_name: str) -> None:
        """Move the plan cursor when a step clearly maps to the tool just run."""
        if not session.plan or session.plan_cursor >= len(session.plan):
            return
        needle = tool_name.replace("_", " ")
        for index in range(session.plan_cursor, len(session.plan)):
            if needle in session.plan[index].lower():
                session.plan_cursor = index + 1
                return
        session.plan_cursor = min(session.plan_cursor + 1, len(session.plan))

    async def _emit_tool_events(
        self, session: AgentSession, observations: list[dict[str, Any]]
    ) -> AsyncIterator[AgentEvent]:
        for observation in observations:
            await self._append_message(
                session,
                MessageRole.TOOL,
                json.dumps(observation["result"], default=str)[:4000],
                meta={
                    "tool": observation["tool"],
                    "ok": observation["ok"],
                    "duration_ms": observation["duration_ms"],
                    "dry_run": observation.get("dry_run", False),
                },
            )
            yield await self._emit(session, AgentEvent("tool_result", observation))
        yield await self._emit(
            session, AgentEvent("plan", {"steps": session.plan, "cursor": session.plan_cursor})
        )

    @staticmethod
    def _format_observations(observations: list[dict[str, Any]]) -> str:
        parts = []
        for observation in observations:
            payload = json.dumps(observation["result"], default=str)[:1500]
            parts.append(f"Tool {observation['tool']} -> {payload}")
        return (
            "Tool results:\n"
            + "\n\n".join(parts)
            + "\n\nContinue the task, or set final_answer if everything is complete."
        )

    # ── resumption after approval ────────────────────────────────────

    async def resume_after_approval(
        self, approval_id: str, *, approved: bool, decided_by: str, note: str | None = None
    ) -> AgentSession:
        """Record the decision and put the session back into a runnable state."""
        approval = await self.db.get(ApprovalRequest, approval_id)
        if approval is None:
            raise NotFoundError(f"Approval request {approval_id} does not exist.")
        if approval.status != ApprovalStatus.PENDING.value:
            raise ConflictError(f"Approval {approval_id} was already {approval.status}.")
        if (ensure_utc(approval.expires_at) or datetime.now(UTC)) < datetime.now(UTC):
            approval.status = ApprovalStatus.EXPIRED.value
            await self.db.flush()
            raise ConflictError("This approval request has expired. Re-run the task.")

        approval.status = (
            ApprovalStatus.APPROVED.value if approved else ApprovalStatus.REJECTED.value
        )
        approval.decided_by = decided_by
        approval.decided_at = datetime.now(UTC)
        approval.decision_note = note

        session = await self.get_session(approval.session_id) if approval.session_id else None
        if session is None:
            await self.db.flush()
            raise NotFoundError("This approval is not attached to an agent session.")

        if approved:
            observations = await self._execute_tools(
                session, [dict(action) for action in approval.requested_actions]
            )
            await self._append_message(
                session,
                MessageRole.SYSTEM,
                f"Approved by {decided_by}. Executed {len(observations)} action(s).",
            )
        else:
            await self._append_message(
                session,
                MessageRole.SYSTEM,
                f"Rejected by {decided_by}. The agent will look for a less disruptive path.",
            )

        session.status = AgentSessionStatus.THINKING.value
        await self.db.flush()
        await self.bus.publish(
            session.id,
            AgentEvent(
                "approval_decided",
                {"approval_id": approval_id, "approved": approved, "by": decided_by},
            ),
        )
        return session

    async def expire_stale_approvals(self) -> int:
        """Mark timed-out approvals expired. Called by the maintenance worker."""
        now = datetime.now(UTC)
        stale = list(
            (
                await self.db.scalars(
                    select(ApprovalRequest).where(
                        ApprovalRequest.status == ApprovalStatus.PENDING.value,
                        ApprovalRequest.expires_at < now,
                    )
                )
            ).all()
        )
        for approval in stale:
            approval.status = ApprovalStatus.EXPIRED.value
            if approval.session_id:
                session = await self.db.get(AgentSession, approval.session_id)
                if session and not session.is_terminal:
                    session.status = AgentSessionStatus.STOPPED.value
                    session.finished_at = now
                    session.error = "Approval request expired without a decision."
        await self.db.flush()
        return len(stale)

    # ── helpers ──────────────────────────────────────────────────────

    async def _retrieve_context(self, session: AgentSession) -> list[RetrievalResult]:
        rag = RAGService(self.db)
        results = await rag.retrieve(session.task, top_k=settings.rag_top_k)
        session.rag_chunk_ids = [r.chunk_id for r in results]
        await self.db.flush()
        return results

    def _build_system_prompt(self, rag_results: list[RetrievalResult]) -> str:
        prompt = SYSTEM_PROMPT.format(tool_names=", ".join(self.registry.names()))
        context = RAGService.build_context(rag_results)
        if context:
            prompt += f"\n\nRelevant knowledge retrieved for this task:\n{context}\n"
        if not settings.allow_destructive_actions:
            prompt += (
                "\nIMPORTANT: this deployment runs with destructive actions disabled. "
                "Mutating tools execute as dry runs and report what they would have done. "
                "Say so explicitly in your final answer.\n"
            )
        return prompt

    async def _load_transcript(self, session: AgentSession) -> list[dict[str, Any]]:
        """Rebuild the Anthropic message list from persisted history.

        Only user/assistant turns are replayed — thoughts and tool payloads are
        UI artefacts and would bloat the context window on resume.
        """
        messages = list(
            (
                await self.db.scalars(
                    select(AgentMessage)
                    .where(AgentMessage.session_id == session.id)
                    .order_by(AgentMessage.sequence)
                )
            ).all()
        )
        transcript: list[dict[str, Any]] = []
        for message in messages:
            if message.role == MessageRole.USER.value:
                transcript.append({"role": "user", "content": message.content})
            elif message.role == MessageRole.ASSISTANT.value:
                transcript.append({"role": "assistant", "content": message.content})
        if not transcript:
            transcript.append({"role": "user", "content": session.task})
        return transcript

    async def _append_message(
        self,
        session: AgentSession,
        role: MessageRole,
        content: str,
        *,
        citations: list[dict[str, Any]] | None = None,
        meta: dict[str, Any] | None = None,
        is_final: bool = False,
    ) -> AgentMessage:
        next_sequence = (
            await self.db.scalar(
                select(AgentMessage.sequence)
                .where(AgentMessage.session_id == session.id)
                .order_by(AgentMessage.sequence.desc())
                .limit(1)
            )
            or 0
        ) + 1
        message = AgentMessage(
            session_id=session.id,
            sequence=next_sequence,
            role=role.value,
            content=content,
            citations=citations or [],
            meta=meta or {},
            is_final=is_final,
        )
        self.db.add(message)
        await self.db.flush()
        return message

    async def _finish(
        self,
        session: AgentSession,
        answer: str,
        rag_results: list[RetrievalResult],
        *,
        implicit: bool = False,
    ) -> None:
        session.final_answer = answer
        session.status = AgentSessionStatus.COMPLETED.value
        session.finished_at = datetime.now(UTC)
        session.plan_cursor = len(session.plan)
        if not implicit:
            await self._append_message(
                session,
                MessageRole.ASSISTANT,
                answer,
                citations=[r.to_dict() for r in rag_results],
                is_final=True,
            )
        await self.db.flush()
        logger.info(
            "agent_session_completed",
            session_id=session.id,
            iterations=session.iterations,
            input_tokens=session.input_tokens,
            output_tokens=session.output_tokens,
        )

    async def _emit(self, session: AgentSession, event: AgentEvent) -> AgentEvent:
        event.data.setdefault("session_id", session.id)
        event.data.setdefault("status", session.status)
        await self.bus.publish(session.id, event)
        return event


async def run_session_background(session_id: str) -> None:
    """Drive a session to completion without a streaming consumer.

    Used by the "run in background" path and by the worker that resumes a
    session after an approval decision.
    """
    from app.db.session import session_scope

    async with session_scope() as db:
        orchestrator = AgentOrchestrator(db)
        async for _ in orchestrator.run(session_id):
            await asyncio.sleep(0)
