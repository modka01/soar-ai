"""The agentic loop: planning, tool execution, approval gating, resumption."""

from __future__ import annotations

import pytest
from app.db.models import AgentSessionStatus, ApprovalStatus, MessageRole
from app.services.agent import AgentOrchestrator
from app.services.events import InMemoryEventBus


@pytest.fixture
def bus() -> InMemoryEventBus:
    return InMemoryEventBus()


async def collect(orchestrator: AgentOrchestrator, session_id: str) -> list:
    return [event async for event in orchestrator.run(session_id)]


async def reload(db, session, *relationships: str):
    """Load lazy relationships on a session object created in this transaction.

    Objects added and flushed in the same unit of work have no loaded
    collections yet, and touching one would trigger sync IO under asyncio.
    """
    await db.refresh(session, list(relationships))
    return session


async def test_session_creation_records_the_task(db, stub_llm, bus):
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Investigate INC-047", created_by="analyst")

    assert session.status == AgentSessionStatus.PENDING.value
    assert session.task == "Investigate INC-047"
    await reload(db, session, "messages")
    assert [m.role for m in session.messages] == [MessageRole.USER.value]


async def test_loop_runs_a_read_only_tool_and_finishes(db, stub_llm, bus):
    stub_llm.responses = [
        {
            "thought": "Start by querying the SIEM.",
            "plan": ["Query SIEM", "Summarise"],
            "tool_calls": [
                {
                    "tool": "query_siem",
                    "params": {"query": "index=* severity=critical"},
                    "reason": "gather events",
                }
            ],
            "message": "Querying the SIEM.",
            "final_answer": "",
        },
        {"thought": "Done.", "tool_calls": [], "message": "", "final_answer": "No threats found."},
    ]
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Check for critical alerts", created_by="analyst")

    events = await collect(orchestrator, session.id)
    types = [event.type for event in events]

    assert "plan" in types
    assert "tool_result" in types
    assert types[-1] == "final"
    assert session.status == AgentSessionStatus.COMPLETED.value
    assert session.final_answer == "No threats found."
    assert session.input_tokens > 0


async def test_destructive_tool_parks_the_loop_on_an_approval_gate(db, stub_llm, bus):
    stub_llm.responses = [
        {
            "thought": "The IOC is confirmed malicious; the host must be isolated.",
            "plan": ["Isolate host"],
            "tool_calls": [
                {
                    "tool": "isolate_host",
                    "params": {"hostname": "ws-finance-04", "reason": "confirmed C2"},
                    "reason": "contain",
                }
            ],
            "message": "Requesting approval to isolate ws-finance-04.",
            "needs_approval": True,
            "approval_reason": "Isolation cuts the host off the network.",
            "final_answer": "",
        }
    ]
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Contain the C2 host", created_by="analyst")

    events = await collect(orchestrator, session.id)

    assert "approval_required" in [event.type for event in events]
    assert session.status == AgentSessionStatus.AWAITING_APPROVAL.value
    # The tool must NOT have run while the gate is open.
    assert "tool_result" not in [event.type for event in events]
    await reload(db, session, "approvals")
    assert len(session.approvals) == 1
    assert session.approvals[0].status == ApprovalStatus.PENDING.value


async def test_approval_is_inferred_from_tool_risk_even_without_the_flag(db, stub_llm, bus):
    """A model that forgets needs_approval must still be gated by the registry."""
    stub_llm.responses = [
        {
            "thought": "Block it.",
            "tool_calls": [
                {
                    "tool": "block_ip",
                    "params": {"ip": "185.220.101.47", "reason": "C2"},
                    "reason": "block",
                }
            ],
            "message": "Blocking.",
            "needs_approval": False,
            "final_answer": "",
        }
    ]
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Block the C2 address", created_by="analyst")

    await collect(orchestrator, session.id)
    assert session.status == AgentSessionStatus.AWAITING_APPROVAL.value


async def test_approving_executes_the_gated_action(db, stub_llm, bus):
    stub_llm.responses = [
        {
            "tool_calls": [
                {
                    "tool": "isolate_host",
                    "params": {"hostname": "ws-01", "reason": "C2"},
                    "reason": "contain",
                }
            ],
            "message": "Approval needed.",
            "needs_approval": True,
            "final_answer": "",
        }
    ]
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Contain ws-01", created_by="analyst")
    await collect(orchestrator, session.id)

    await reload(db, session, "approvals")
    approval = session.approvals[0]
    resumed = await orchestrator.resume_after_approval(
        approval.id, approved=True, decided_by="ir-manager"
    )

    assert approval.status == ApprovalStatus.APPROVED.value
    assert approval.decided_by == "ir-manager"
    assert resumed.status == AgentSessionStatus.THINKING.value


async def test_rejecting_records_the_decision_and_does_not_execute(db, stub_llm, bus):
    stub_llm.responses = [
        {
            "tool_calls": [
                {
                    "tool": "isolate_host",
                    "params": {"hostname": "ws-01", "reason": "C2"},
                    "reason": "contain",
                }
            ],
            "message": "Approval needed.",
            "needs_approval": True,
            "final_answer": "",
        }
    ]
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Contain ws-01", created_by="analyst")
    await collect(orchestrator, session.id)

    await reload(db, session, "approvals")
    approval = session.approvals[0]
    await orchestrator.resume_after_approval(
        approval.id, approved=False, decided_by="ir-manager", note="Host is a decoy."
    )

    assert approval.status == ApprovalStatus.REJECTED.value
    assert approval.decision_note == "Host is a decoy."
    await reload(db, session, "messages")
    assert any("Rejected by" in m.content for m in session.messages)


async def test_deciding_the_same_approval_twice_conflicts(db, stub_llm, bus):
    from app.core.errors import ConflictError

    stub_llm.responses = [
        {
            "tool_calls": [
                {"tool": "isolate_host", "params": {"hostname": "ws-01", "reason": "C2"}}
            ],
            "needs_approval": True,
            "message": "gate",
            "final_answer": "",
        }
    ]
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Contain ws-01", created_by="analyst")
    await collect(orchestrator, session.id)

    await reload(db, session, "approvals")
    approval = session.approvals[0]
    await orchestrator.resume_after_approval(approval.id, approved=True, decided_by="a")
    with pytest.raises(ConflictError):
        await orchestrator.resume_after_approval(approval.id, approved=True, decided_by="b")


async def test_iteration_limit_terminates_the_loop(db, stub_llm, bus):
    """A model that never sets final_answer must not loop forever."""
    stub_llm.responses = [
        {
            "thought": "still working",
            "tool_calls": [{"tool": "query_siem", "params": {"query": "index=*"}}],
            "message": "working",
            "final_answer": "",
        }
    ]
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session(
        "Endless task", created_by="analyst", max_iterations=3
    )

    events = await collect(orchestrator, session.id)

    assert session.iterations == 3
    assert events[-1].type == "exhausted"
    assert session.status == AgentSessionStatus.COMPLETED.value


async def test_unknown_tool_is_reported_not_crashed(db, stub_llm, bus):
    stub_llm.responses = [
        {
            "tool_calls": [{"tool": "nonexistent_tool", "params": {}}],
            "message": "Trying a tool.",
            "final_answer": "",
        },
        {"tool_calls": [], "message": "", "final_answer": "Recovered."},
    ]
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Use a bad tool", created_by="analyst")

    events = await collect(orchestrator, session.id)
    tool_events = [e for e in events if e.type == "tool_result"]

    assert tool_events and tool_events[0].data["ok"] is False
    assert session.status == AgentSessionStatus.COMPLETED.value


async def test_stopping_a_session_marks_it_terminal(db, stub_llm, bus):
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Long task", created_by="analyst")

    stopped = await orchestrator.stop_session(session.id, stopped_by="analyst")
    assert stopped.status == AgentSessionStatus.STOPPED.value
    assert stopped.is_terminal


async def test_running_a_finished_session_conflicts(db, stub_llm, bus):
    from app.core.errors import ConflictError

    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Task", created_by="analyst")
    await orchestrator.stop_session(session.id, stopped_by="analyst")

    with pytest.raises(ConflictError):
        await collect(orchestrator, session.id)


async def test_rag_context_is_retrieved_and_recorded(db, stub_llm, bus):
    from app.services.rag import RAGService

    await RAGService(db).index_document(
        title="PsExec lateral movement",
        source="MITRE ATT&CK",
        category="Lateral Movement",
        content="PsExec creates a PSEXESVC service over the ADMIN$ share on the remote host.",
    )
    stub_llm.responses = [{"tool_calls": [], "message": "", "final_answer": "Done."}]

    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session(
        "Investigate PSEXESVC service creation", created_by="analyst"
    )
    events = await collect(orchestrator, session.id)

    context_events = [e for e in events if e.type == "context"]
    assert context_events and context_events[0].data["chunks"]
    assert session.rag_chunk_ids
    # The retrieved knowledge must actually reach the model's system prompt.
    assert "PSEXESVC" in stub_llm.calls[0]["system"]


async def test_dry_run_mode_is_announced_in_the_system_prompt(db, stub_llm, bus):
    stub_llm.responses = [{"tool_calls": [], "message": "", "final_answer": "Done."}]
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Any task", created_by="analyst")
    await collect(orchestrator, session.id)

    assert "destructive actions disabled" in stub_llm.calls[0]["system"]


async def test_llm_failure_marks_the_session_failed(db, bus):
    class BrokenLLM:
        model = "broken"
        configured = True

        async def complete_json(self, messages, *, system, max_tokens=None):
            raise RuntimeError("Anthropic API is unreachable")

    orchestrator = AgentOrchestrator(db, llm=BrokenLLM(), bus=bus)
    session = await orchestrator.create_session("Task", created_by="analyst")

    events = await collect(orchestrator, session.id)

    assert events[-1].type == "error"
    assert session.status == AgentSessionStatus.FAILED.value
    assert "unreachable" in (session.error or "")


async def test_expired_approvals_are_swept(db, stub_llm, bus):
    from datetime import UTC, datetime, timedelta

    stub_llm.responses = [
        {
            "tool_calls": [
                {"tool": "isolate_host", "params": {"hostname": "ws-01", "reason": "x"}}
            ],
            "needs_approval": True,
            "message": "gate",
            "final_answer": "",
        }
    ]
    orchestrator = AgentOrchestrator(db, llm=stub_llm, bus=bus)
    session = await orchestrator.create_session("Contain", created_by="analyst")
    await collect(orchestrator, session.id)

    await reload(db, session, "approvals")
    session.approvals[0].expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await db.flush()

    assert await orchestrator.expire_stale_approvals() == 1
    assert session.approvals[0].status == ApprovalStatus.EXPIRED.value
    assert session.status == AgentSessionStatus.STOPPED.value
