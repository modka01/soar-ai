"""Password hashing, JWT issuing/verification, HMAC webhook signatures, RBAC."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.core.errors import AuthenticationError

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

ACCESS_TOKEN = "access"  # noqa: S105 - token *type* discriminator, not a secret
REFRESH_TOKEN = "refresh"  # noqa: S105


class Role(StrEnum):
    """Platform roles, ordered from least to most privileged."""

    READ_ONLY = "read_only"
    SOC_L1 = "soc_l1"
    SOC_L2 = "soc_l2"
    SOC_L3 = "soc_l3"
    IR_MANAGER = "ir_manager"
    AUTOMATION = "automation"
    ADMIN = "admin"


#: Role → permission set. Checked by :func:`app.api.deps.require_permission`.
ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.READ_ONLY: {"read"},
    Role.SOC_L1: {"read", "alert:triage", "agent:run"},
    Role.SOC_L2: {"read", "alert:triage", "agent:run", "incident:write", "playbook:run"},
    Role.SOC_L3: {
        "read",
        "alert:triage",
        "agent:run",
        "incident:write",
        "playbook:run",
        "approval:decide",
        "sigma:write",
        "rag:write",
    },
    Role.IR_MANAGER: {
        "read",
        "alert:triage",
        "agent:run",
        "incident:write",
        "playbook:run",
        "approval:decide",
        "sigma:write",
        "sigma:deploy",
        "rag:write",
        "containment:execute",
    },
    Role.AUTOMATION: {"read", "agent:run", "alert:triage", "incident:write", "playbook:run"},
    Role.ADMIN: {
        "read",
        "alert:triage",
        "agent:run",
        "incident:write",
        "playbook:run",
        "approval:decide",
        "sigma:write",
        "sigma:deploy",
        "rag:write",
        "containment:execute",
        "settings:write",
        "user:manage",
        "audit:read",
    },
}


def permissions_for(role: Role | str) -> set[str]:
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return set()


# ── Passwords ────────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _pwd_context.verify(plain, hashed)
    except ValueError:
        return False


def generate_api_key(prefix: str = "qntx_sk") -> tuple[str, str]:
    """Return ``(clear_text_key, sha256_digest)``. Only the digest is stored."""
    raw = f"{prefix}_{secrets.token_urlsafe(32)}"
    return raw, hash_api_key(raw)


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ── JWT ──────────────────────────────────────────────────────────────


def create_token(
    subject: str,
    *,
    token_type: str = ACCESS_TOKEN,
    role: str | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(UTC)
    ttl = (
        timedelta(minutes=settings.access_token_ttl_minutes)
        if token_type == ACCESS_TOKEN
        else timedelta(days=settings.refresh_token_ttl_days)
    )
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        "jti": secrets.token_hex(16),
        "iss": "quantnexa-soar",
    }
    if role:
        payload["role"] = role
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str, *, expected_type: str = ACCESS_TOKEN) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer="quantnexa-soar",
        )
    except JWTError as exc:
        raise AuthenticationError("Token is invalid or has expired.") from exc
    if payload.get("type") != expected_type:
        raise AuthenticationError(f"Expected a {expected_type} token.")
    return payload


# ── Webhook signatures ───────────────────────────────────────────────


def sign_payload(body: bytes, *, secret: str | None = None) -> str:
    """HMAC-SHA256 signature in the ``sha256=<hex>`` form used by our webhooks."""
    key = (secret or settings.webhook_hmac_secret).encode()
    return "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()


def verify_signature(body: bytes, signature: str, *, secret: str | None = None) -> bool:
    """Constant-time comparison — never short-circuit on the first differing byte."""
    if not signature:
        return False
    return hmac.compare_digest(sign_payload(body, secret=secret), signature)
