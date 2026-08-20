"""Event bus for streaming agent progress to the browser.

Backed by Redis pub/sub so an operator connected to replica B sees events
produced by replica A. Falls back to an in-process bus when Redis is absent
(local development and tests), which keeps a single-node deployment working.
"""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any, Protocol

import redis.asyncio as aioredis

from app.core.config import settings
from app.core.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids a circular import
    from app.services.agent import AgentEvent

logger = get_logger(__name__)

CHANNEL_PREFIX = "soar:agent:"
#: Sent when a stream ends so the client stops waiting.
SENTINEL = "__end__"


class EventBus(Protocol):
    async def publish(self, session_id: str, event: AgentEvent) -> None: ...

    def subscribe(self, session_id: str) -> AsyncIterator[dict[str, Any]]: ...

    async def close(self) -> None: ...


class InMemoryEventBus:
    """Single-process bus. Every subscriber gets its own queue."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[dict[str, Any] | None]]] = defaultdict(list)

    async def publish(self, session_id: str, event: AgentEvent) -> None:
        payload = {"type": event.type, **event.data}
        for queue in list(self._subscribers.get(session_id, [])):
            queue.put_nowait(payload)

    async def subscribe(self, session_id: str) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=1000)
        self._subscribers[session_id].append(queue)
        try:
            while True:
                payload = await queue.get()
                if payload is None:
                    return
                yield payload
        finally:
            self._subscribers[session_id].remove(queue)
            if not self._subscribers[session_id]:
                self._subscribers.pop(session_id, None)

    async def close(self) -> None:
        for queues in self._subscribers.values():
            for queue in queues:
                queue.put_nowait(None)
        self._subscribers.clear()


class RedisEventBus:
    """Cross-replica bus over Redis pub/sub."""

    def __init__(self, url: str) -> None:
        self.url = url
        self._client: aioredis.Redis | None = None

    @property
    def client(self) -> aioredis.Redis:
        if self._client is None:
            self._client = aioredis.from_url(self.url, decode_responses=True)
        return self._client

    async def publish(self, session_id: str, event: AgentEvent) -> None:
        payload = json.dumps({"type": event.type, **event.data}, default=str)
        try:
            await self.client.publish(f"{CHANNEL_PREFIX}{session_id}", payload)
        except Exception as exc:  # pragma: no cover - Redis outage path
            logger.warning("event_publish_failed", session_id=session_id, error=str(exc))

    async def subscribe(self, session_id: str) -> AsyncIterator[dict[str, Any]]:
        pubsub = self.client.pubsub()
        await pubsub.subscribe(f"{CHANNEL_PREFIX}{session_id}")
        try:
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                raw = message.get("data")
                if raw == SENTINEL:
                    return
                try:
                    yield json.loads(raw)
                except (TypeError, json.JSONDecodeError):
                    continue
        finally:
            await pubsub.unsubscribe(f"{CHANNEL_PREFIX}{session_id}")
            await pubsub.aclose()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        if settings.redis_url:
            _bus = RedisEventBus(settings.redis_url)  # type: ignore[assignment]
            logger.info("event_bus_selected", backend="redis")
        else:
            _bus = InMemoryEventBus()  # type: ignore[assignment]
            logger.info("event_bus_selected", backend="memory")
    return _bus  # type: ignore[return-value]


def set_event_bus(bus: EventBus | None) -> None:
    """Test hook."""
    global _bus
    _bus = bus
