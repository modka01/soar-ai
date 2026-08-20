"""Shared FastAPI dependencies: current principal, RBAC guards, pagination."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AuthenticationError, ForbiddenError
from app.core.logging import actor_ctx
from app.core.security import Role, decode_token, hash_api_key, permissions_for
from app.db.base import ensure_utc
from app.db.models import ApiKey, User
from app.db.session import get_db

_bearer = HTTPBearer(auto_error=False, description="JWT access token")


@dataclass(slots=True)
class Principal:
    """Whoever is making the request — a human user or a machine API key."""

    id: str
    display_name: str
    role: Role
    kind: str = "user"
    permissions: frozenset[str] = frozenset()

    def has(self, permission: str) -> bool:
        return permission in self.permissions

    @property
    def is_admin(self) -> bool:
        return self.role is Role.ADMIN


async def _principal_from_api_key(db: AsyncSession, raw_key: str) -> Principal:
    digest = hash_api_key(raw_key)
    result = await db.execute(select(ApiKey).where(ApiKey.key_hash == digest))
    api_key = result.scalar_one_or_none()
    if api_key is None or not api_key.is_active:
        raise AuthenticationError("API key is invalid or has been revoked.")
    if api_key.expires_at and ensure_utc(api_key.expires_at) < datetime.now(UTC):
        raise AuthenticationError("API key has expired.")

    user = await db.get(User, api_key.user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("The account behind this API key is inactive.")

    api_key.last_used_at = datetime.now(UTC)
    role = Role(user.role)
    scopes = set(api_key.scopes or [])
    granted = permissions_for(role)
    # An API key can narrow its user's permissions but never widen them.
    permissions = granted & scopes if scopes else granted
    return Principal(
        id=user.id,
        display_name=f"{user.email} (key:{api_key.name})",
        role=role,
        kind="api_key",
        permissions=frozenset(permissions),
    )


async def _principal_from_token(db: AsyncSession, token: str) -> Principal:
    payload = decode_token(token)
    user = await db.get(User, payload["sub"])
    if user is None or not user.is_active:
        raise AuthenticationError("The account for this token is inactive.")
    role = Role(user.role)
    return Principal(
        id=user.id,
        display_name=user.email,
        role=role,
        kind="user",
        permissions=frozenset(permissions_for(role)),
    )


async def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
    db: Annotated[AsyncSession, Depends(get_db)] = ...,  # type: ignore[assignment]
) -> Principal:
    """Resolve the caller from either an ``X-API-Key`` header or a bearer token."""
    api_key = request.headers.get("x-api-key")
    if api_key:
        principal = await _principal_from_api_key(db, api_key)
    elif credentials and credentials.scheme.lower() == "bearer":
        principal = await _principal_from_token(db, credentials.credentials)
    else:
        raise AuthenticationError("Provide a bearer token or an X-API-Key header.")

    actor_ctx.set(principal.display_name)
    request.state.principal = principal
    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
DbSession = Annotated[AsyncSession, Depends(get_db)]


def require_permission(*permissions: str):
    """Guard a route on one or more permissions (all must be held)."""

    async def _guard(principal: CurrentPrincipal) -> Principal:
        missing = [p for p in permissions if not principal.has(p)]
        if missing:
            raise ForbiddenError(
                f"Role '{principal.role}' is missing required permission(s): {', '.join(missing)}."
            )
        return principal

    return _guard


def require_role(*roles: Role):
    async def _guard(principal: CurrentPrincipal) -> Principal:
        if principal.role not in roles:
            raise ForbiddenError(
                f"This action is restricted to: {', '.join(r.value for r in roles)}."
            )
        return principal

    return _guard


@dataclass(slots=True)
class Pagination:
    limit: int
    offset: int


def pagination(
    limit: Annotated[int, Query(ge=1, le=200, description="Page size")] = 50,
    offset: Annotated[int, Query(ge=0, description="Rows to skip")] = 0,
) -> Pagination:
    return Pagination(limit=limit, offset=offset)


PaginationDep = Annotated[Pagination, Depends(pagination)]
