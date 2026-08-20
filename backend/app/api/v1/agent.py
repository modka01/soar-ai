"""Agent console: task submission, SSE streaming, transcripts and approvals."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from app.api.deps import CurrentPrincipal, DbSession, PaginationDep, Principal, require_permission
from app.core.logging import get_logger
from app.db.models import AgentSession, ApprovalRequest
from app.db.session import session_scope
from app.schemas.agent import (
    AgentSessionDetail,
    AgentSessionOut,
    AgentTaskCreate,
    ApprovalDecision,
    ApprovalOut,
)
from app.schemas.common import Page
from app.services.agent import AgentOrchestrator, run_session_background
from app.services.audit import AuditService
from app.services.events import get_event_bus

logger = get_logger(__name__)
router = APIRouter(prefix="/agent", tags=["agent"])

#: Interval between SSE keep-alive comments, below the typical 60s proxy idle timeout.
HEARTBEAT_SECONDS = 20


@router.post(
    "/tasks",
    response_model=AgentSessionOut,
    status_code=status.HTTP_201_CREATED,
    summary="Assign a task to the agent",
)
async def create_task(
    payload: AgentTaskCreate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("agent:run"))],
) -> AgentSession:
    """Create the session. Streaming happens on ``GET /agent/sessions/{id}/stream``.

    Splitting creation from streaming means a dropped connection never loses the
    task — the operator reconnects to the same session and picks the feed back up.
    """
    orchestrator = AgentOrchestrator(db)
    session = await orchestrator.create_session(
        payload.task,
        created_by=principal.display_name,
        incident_id=payload.incident_id,
        max_iterations=payload.max_iterations,
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="agent_task_create",
        resource_type="agent_session",
        resource_id=session.id,
        detail={"task": payload.task[:500]},
    )
    return session


@router.get(
    "/sessions/{session_id}/stream",
    summary="Stream agent progress (SSE)",
    response_class=StreamingResponse,
)
async def stream_session(
    session_id: str,
    principal: Annotated[Principal, Depends(require_permission("agent:run"))],
    follow: Annotated[
        bool,
        Query(description="Attach to an already-running session instead of starting it"),
    ] = False,
) -> StreamingResponse:
    """Drive the loop and stream events, or follow a session another client started."""

    async def event_stream() -> AsyncIterator[str]:
        try:
            if follow:
                async for event in _follow(session_id):
                    yield event
            else:
                # A dedicated session keeps the long-running loop off the
                # request-scoped one, which the response would otherwise hold open.
                async with session_scope() as db:
                    orchestrator = AgentOrchestrator(db)
                    async for event in orchestrator.run(session_id):
                        yield event.sse()
            yield "event: done\ndata: {}\n\n"
        except asyncio.CancelledError:
            logger.info("agent_stream_disconnected", session_id=session_id)
            raise
        except Exception as exc:
            logger.exception("agent_stream_failed", session_id=session_id)
            yield f"event: error\ndata: {json.dumps({'message': str(exc)[:300]})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "cache-control": "no-cache, no-transform",
            "connection": "keep-alive",
            # Stops nginx buffering the stream and delaying every event.
            "x-accel-buffering": "no",
        },
    )


async def _follow(session_id: str) -> AsyncIterator[str]:
    """Relay bus events for a session started elsewhere, with keep-alives."""
    bus = get_event_bus()
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=500)

    async def pump() -> None:
        async for payload in bus.subscribe(session_id):
            event_type = payload.pop("type", "message")
            await queue.put(f"event: {event_type}\ndata: {json.dumps(payload, default=str)}\n\n")

    task = asyncio.create_task(pump())
    try:
        while True:
            try:
                yield await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
            except TimeoutError:
                yield ": keep-alive\n\n"
            if task.done():
                return
    finally:
        task.cancel()


@router.post(
    "/sessions/{session_id}/run",
    response_model=AgentSessionOut,
    summary="Run a session in the background",
)
async def run_background(
    session_id: str,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("agent:run"))],
) -> AgentSession:
    """Start the loop without holding a connection open. Progress goes to the bus."""
    orchestrator = AgentOrchestrator(db)
    session = await orchestrator.get_session(session_id)
    # Detached deliberately: the caller gets an immediate acknowledgement and
    # follows progress over SSE.
    asyncio.create_task(run_session_background(session_id))  # noqa: RUF006
    return session


@router.get("/sessions", response_model=Page[AgentSessionOut], summary="List agent sessions")
async def list_sessions(
    db: DbSession,
    page: PaginationDep,
    principal: CurrentPrincipal,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
) -> Page[AgentSessionOut]:
    statement = select(AgentSession).order_by(AgentSession.created_at.desc())
    count_statement = select(func.count()).select_from(AgentSession)
    if status_filter:
        statement = statement.where(AgentSession.status == status_filter)
        count_statement = count_statement.where(AgentSession.status == status_filter)

    total = int(await db.scalar(count_statement) or 0)
    rows = list((await db.scalars(statement.limit(page.limit).offset(page.offset))).all())
    return Page(
        items=[AgentSessionOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get(
    "/sessions/{session_id}",
    response_model=AgentSessionDetail,
    summary="Get a session with its full transcript",
)
async def get_session(session_id: str, db: DbSession, principal: CurrentPrincipal) -> AgentSession:
    return await AgentOrchestrator(db).get_session(session_id)


@router.post(
    "/sessions/{session_id}/stop", response_model=AgentSessionOut, summary="Stop a running session"
)
async def stop_session(
    session_id: str,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("agent:run"))],
) -> AgentSession:
    session = await AgentOrchestrator(db).stop_session(
        session_id, stopped_by=principal.display_name
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="agent_stop",
        resource_type="agent_session",
        resource_id=session_id,
    )
    return session


# ── approvals ────────────────────────────────────────────────────────


@router.get("/approvals", response_model=Page[ApprovalOut], summary="List approval requests")
async def list_approvals(
    db: DbSession,
    page: PaginationDep,
    principal: CurrentPrincipal,
    status_filter: Annotated[str | None, Query(alias="status")] = "pending",
) -> Page[ApprovalOut]:
    statement = select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc())
    count_statement = select(func.count()).select_from(ApprovalRequest)
    if status_filter:
        statement = statement.where(ApprovalRequest.status == status_filter)
        count_statement = count_statement.where(ApprovalRequest.status == status_filter)

    total = int(await db.scalar(count_statement) or 0)
    rows = list((await db.scalars(statement.limit(page.limit).offset(page.offset))).all())
    return Page(
        items=[ApprovalOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post(
    "/approvals/{approval_id}/decide",
    response_model=AgentSessionOut,
    summary="Approve or reject a containment action",
)
async def decide_approval(
    approval_id: str,
    payload: ApprovalDecision,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("approval:decide"))],
) -> AgentSession:
    """Record the human decision, then resume the agent loop.

    Approving executes the proposed actions immediately, inside this request, so
    the operator sees the outcome rather than a fire-and-forget acknowledgement.
    """
    orchestrator = AgentOrchestrator(db)
    session = await orchestrator.resume_after_approval(
        approval_id,
        approved=payload.approved,
        decided_by=principal.display_name,
        note=payload.note,
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="approval_decide",
        resource_type="approval_request",
        resource_id=approval_id,
        outcome="success" if payload.approved else "rejected",
        detail={"approved": payload.approved, "note": payload.note},
    )
    if payload.approved and not session.is_terminal:
        asyncio.create_task(run_session_background(session.id))  # noqa: RUF006
    return session
