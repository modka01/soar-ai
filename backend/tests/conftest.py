"""Test fixtures: in-memory database, stub LLM, authenticated client."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

# Settings are read at import time, so the test environment must be set first.
os.environ.setdefault("SOAR_ENVIRONMENT", "test")
os.environ.setdefault("SOAR_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SOAR_REDIS_URL", "")
os.environ.setdefault("SOAR_SECRET_KEY", "test-secret-key-not-used-in-production")
os.environ.setdefault("SOAR_WEBHOOK_HMAC_SECRET", "test-hmac-secret")
os.environ.setdefault("SOAR_EMBEDDING_PROVIDER", "hashing")
os.environ.setdefault("SOAR_ALLOW_DESTRUCTIVE_ACTIONS", "false")

import pytest
from app.core.security import ACCESS_TOKEN, Role, create_token, hash_password
from app.db.base import Base
from app.db.models import User
from app.db.session import get_db
from app.integrations.llm import LLMResponse
from app.main import create_app
from app.services.events import InMemoryEventBus, set_event_bus
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool


@pytest.fixture
async def engine() -> AsyncIterator[Any]:
    """One in-memory SQLite database per test, shared across connections."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db(engine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def admin_user(db: AsyncSession) -> User:
    user = User(
        email="admin@quantnexa.example.com",
        full_name="Test Admin",
        hashed_password=hash_password("Str0ng-Test-Passw0rd!"),
        role=Role.ADMIN.value,
    )
    db.add(user)
    await db.commit()
    return user


@pytest.fixture
async def analyst_user(db: AsyncSession) -> User:
    user = User(
        email="analyst@quantnexa.example.com",
        full_name="Test Analyst",
        hashed_password=hash_password("Str0ng-Test-Passw0rd!"),
        role=Role.SOC_L1.value,
    )
    db.add(user)
    await db.commit()
    return user


@pytest.fixture
async def app(engine):
    """App wired to the test database and an in-process event bus."""
    set_event_bus(InMemoryEventBus())
    application = create_app()
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    application.dependency_overrides[get_db] = override_get_db
    application.state.redis = None
    yield application
    application.dependency_overrides.clear()
    set_event_bus(None)


@pytest.fixture
async def client(app) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


@pytest.fixture
def admin_token(admin_user: User) -> str:
    return create_token(admin_user.id, token_type=ACCESS_TOKEN, role=admin_user.role)


@pytest.fixture
def analyst_token(analyst_user: User) -> str:
    return create_token(analyst_user.id, token_type=ACCESS_TOKEN, role=analyst_user.role)


@pytest.fixture
def auth(admin_token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {admin_token}"}


class StubLLM:
    """Deterministic LLM stand-in.

    Returns a scripted sequence of responses so agent-loop tests assert on
    behaviour rather than on whatever a live model happened to produce.
    """

    def __init__(self, responses: list[dict[str, Any]] | None = None) -> None:
        self.responses = responses or []
        self.calls: list[dict[str, Any]] = []
        self.model = "stub-model"
        self.configured = True

    async def complete(self, messages, *, system, max_tokens=None, temperature=None) -> LLMResponse:
        import json

        self.calls.append({"messages": list(messages), "system": system})
        index = min(len(self.calls) - 1, len(self.responses) - 1) if self.responses else 0
        payload = self.responses[index] if self.responses else {"message": "no response scripted"}
        return LLMResponse(
            text=json.dumps(payload), input_tokens=100, output_tokens=50, model=self.model
        )

    async def complete_json(self, messages, *, system, max_tokens=None):
        response = await self.complete(messages, system=system, max_tokens=max_tokens)
        return response.as_json(), response

    async def aclose(self) -> None:
        return None


@pytest.fixture
def stub_llm() -> StubLLM:
    return StubLLM()
