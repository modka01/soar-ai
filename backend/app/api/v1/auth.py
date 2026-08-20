"""Authentication, user administration and API keys."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import func, select

from app.api.deps import CurrentPrincipal, DbSession, PaginationDep, Principal, require_permission
from app.core.config import settings
from app.core.errors import AuthenticationError, ConflictError, NotFoundError
from app.core.logging import get_logger
from app.core.security import (
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    Role,
    create_token,
    decode_token,
    generate_api_key,
    hash_password,
    verify_password,
)
from app.db.base import ensure_utc
from app.db.models import ApiKey, User
from app.schemas.auth import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    LoginRequest,
    PasswordChange,
    RefreshRequest,
    TokenPair,
    UserCreate,
    UserOut,
    UserUpdate,
)
from app.schemas.common import Message, Page
from app.services.audit import AuditService

logger = get_logger(__name__)
router = APIRouter(tags=["auth"])

#: Lock an account for this long after repeated failed logins.
LOCKOUT_DURATION = timedelta(minutes=15)
MAX_FAILED_LOGINS = 5


@router.post("/auth/login", response_model=TokenPair, summary="Exchange credentials for tokens")
async def login(payload: LoginRequest, request: Request, db: DbSession) -> TokenPair:
    audit = AuditService(db)
    source_ip = request.client.host if request.client else None

    user = await db.scalar(select(User).where(User.email == payload.email.lower()))

    # Always run a hash comparison so a missing account and a wrong password
    # take the same time — otherwise the endpoint enumerates valid emails.
    stored_hash = user.hashed_password if user and user.hashed_password else hash_password("_")
    password_ok = verify_password(payload.password, stored_hash)

    if user is None or not password_ok:
        if user is not None:
            user.failed_login_count += 1
            if user.failed_login_count >= MAX_FAILED_LOGINS:
                user.locked_until = datetime.now(UTC) + LOCKOUT_DURATION
                logger.warning("account_locked", email=user.email, ip=source_ip)
        await audit.record(
            actor=payload.email,
            action="login",
            outcome="failure",
            source_ip=source_ip,
            detail={"reason": "invalid_credentials"},
        )
        raise AuthenticationError("Email or password is incorrect.")

    if not user.is_active:
        raise AuthenticationError("This account is disabled.")
    if user.locked_until and ensure_utc(user.locked_until) > datetime.now(UTC):
        raise AuthenticationError(
            "Account is locked after repeated failed logins. "
            f"Try again after {ensure_utc(user.locked_until).isoformat()}."
        )

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = datetime.now(UTC)

    await audit.record(
        actor=user.email,
        action="login",
        resource_type="user",
        resource_id=user.id,
        source_ip=source_ip,
        user_agent=request.headers.get("user-agent"),
    )
    return _issue_tokens(user)


@router.post("/auth/refresh", response_model=TokenPair, summary="Rotate an access token")
async def refresh(payload: RefreshRequest, db: DbSession) -> TokenPair:
    claims = decode_token(payload.refresh_token, expected_type=REFRESH_TOKEN)
    user = await db.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise AuthenticationError("The account for this token is no longer active.")
    return _issue_tokens(user)


@router.get("/auth/me", response_model=UserOut, summary="Current principal")
async def me(principal: CurrentPrincipal, db: DbSession) -> User:
    user = await db.get(User, principal.id)
    if user is None:
        raise NotFoundError("The authenticated account no longer exists.")
    return user


@router.post("/auth/password", response_model=Message, summary="Change your own password")
async def change_password(
    payload: PasswordChange, principal: CurrentPrincipal, db: DbSession
) -> Message:
    user = await db.get(User, principal.id)
    if user is None or not user.hashed_password:
        raise NotFoundError("The authenticated account no longer exists.")
    if not verify_password(payload.current_password, user.hashed_password):
        raise AuthenticationError("Current password is incorrect.")

    user.hashed_password = hash_password(payload.new_password)
    await AuditService(db).record(
        actor=user.email, action="password_change", resource_type="user", resource_id=user.id
    )
    return Message(message="Password updated.")


# ── user administration ──────────────────────────────────────────────


@router.get("/users", response_model=Page[UserOut], summary="List users")
async def list_users(
    db: DbSession,
    page: PaginationDep,
    _: Annotated[Principal, Depends(require_permission("user:manage"))],
) -> Page[UserOut]:
    total = int(await db.scalar(select(func.count()).select_from(User)) or 0)
    rows = list(
        (
            await db.scalars(
                select(User).order_by(User.created_at.desc()).limit(page.limit).offset(page.offset)
            )
        ).all()
    )
    return Page(
        items=[UserOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post(
    "/users",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a user",
)
async def create_user(
    payload: UserCreate,
    db: DbSession,
    actor: Annotated[Principal, Depends(require_permission("user:manage"))],
) -> User:
    email = payload.email.lower()
    if await db.scalar(select(User).where(User.email == email)):
        raise ConflictError(f"A user with email {email} already exists.")

    user = User(
        email=email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role.value,
    )
    db.add(user)
    await db.flush()
    await AuditService(db).record(
        actor=actor.display_name,
        action="user_create",
        resource_type="user",
        resource_id=user.id,
        detail={"email": email, "role": payload.role.value},
    )
    return user


@router.patch("/users/{user_id}", response_model=UserOut, summary="Update a user")
async def update_user(
    user_id: str,
    payload: UserUpdate,
    db: DbSession,
    actor: Annotated[Principal, Depends(require_permission("user:manage"))],
) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise NotFoundError(f"User {user_id} does not exist.")

    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.role is not None:
        user.role = payload.role.value
    if payload.is_active is not None:
        # Refuse to disable the last active admin — that would lock everyone out.
        if not payload.is_active and user.role == Role.ADMIN.value:
            remaining = int(
                await db.scalar(
                    select(func.count())
                    .select_from(User)
                    .where(
                        User.role == Role.ADMIN.value,
                        User.is_active.is_(True),
                        User.id != user.id,
                    )
                )
                or 0
            )
            if remaining == 0:
                raise ConflictError("Cannot disable the last active administrator.")
        user.is_active = payload.is_active

    await AuditService(db).record(
        actor=actor.display_name,
        action="user_update",
        resource_type="user",
        resource_id=user.id,
        detail=payload.model_dump(exclude_none=True),
    )
    return user


# ── API keys ─────────────────────────────────────────────────────────


@router.get("/api-keys", response_model=list[ApiKeyOut], summary="List your API keys")
async def list_api_keys(principal: CurrentPrincipal, db: DbSession) -> list[ApiKey]:
    return list((await db.scalars(select(ApiKey).where(ApiKey.user_id == principal.id))).all())


@router.post(
    "/api-keys",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Create an API key",
)
async def create_api_key(
    payload: ApiKeyCreate, principal: CurrentPrincipal, db: DbSession
) -> ApiKeyCreated:
    raw, digest = generate_api_key()
    api_key = ApiKey(
        name=payload.name,
        key_prefix=raw[:16],
        key_hash=digest,
        user_id=principal.id,
        scopes=payload.scopes,
        expires_at=(
            datetime.now(UTC) + timedelta(days=payload.expires_in_days)
            if payload.expires_in_days
            else None
        ),
    )
    db.add(api_key)
    await db.flush()
    await AuditService(db).record(
        actor=principal.display_name,
        action="api_key_create",
        resource_type="api_key",
        resource_id=api_key.id,
        detail={"name": payload.name, "scopes": payload.scopes},
    )
    return ApiKeyCreated(**ApiKeyOut.model_validate(api_key).model_dump(), api_key=raw)


@router.delete("/api-keys/{key_id}", response_model=Message, summary="Revoke an API key")
async def revoke_api_key(key_id: str, principal: CurrentPrincipal, db: DbSession) -> Message:
    api_key = await db.get(ApiKey, key_id)
    if api_key is None or (api_key.user_id != principal.id and not principal.is_admin):
        raise NotFoundError(f"API key {key_id} does not exist.")
    api_key.is_active = False
    await AuditService(db).record(
        actor=principal.display_name,
        action="api_key_revoke",
        resource_type="api_key",
        resource_id=key_id,
    )
    return Message(message="API key revoked.")


def _issue_tokens(user: User) -> TokenPair:
    return TokenPair(
        access_token=create_token(user.id, token_type=ACCESS_TOKEN, role=user.role),
        refresh_token=create_token(user.id, token_type=REFRESH_TOKEN, role=user.role),
        expires_in=settings.access_token_ttl_minutes * 60,
    )
