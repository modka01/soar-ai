"""Password hashing, JWT and webhook signature verification."""

from __future__ import annotations

import pytest
from app.core.errors import AuthenticationError
from app.core.security import (
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    Role,
    create_token,
    decode_token,
    generate_api_key,
    hash_api_key,
    hash_password,
    permissions_for,
    sign_payload,
    verify_password,
    verify_signature,
)


def test_password_round_trip():
    hashed = hash_password("Str0ng-Passw0rd!")
    assert hashed != "Str0ng-Passw0rd!"
    assert verify_password("Str0ng-Passw0rd!", hashed)
    assert not verify_password("wrong", hashed)


def test_password_hashes_are_salted():
    """Two hashes of the same password must differ, or the store is rainbow-tableable."""
    assert hash_password("same-input") != hash_password("same-input")


def test_token_round_trip():
    token = create_token("user-123", role=Role.ADMIN.value)
    claims = decode_token(token)
    assert claims["sub"] == "user-123"
    assert claims["role"] == Role.ADMIN.value
    assert claims["iss"] == "quantnexa-soar"


def test_token_type_is_enforced():
    """A refresh token must not be accepted where an access token is required."""
    refresh = create_token("user-123", token_type=REFRESH_TOKEN)
    with pytest.raises(AuthenticationError):
        decode_token(refresh, expected_type=ACCESS_TOKEN)


def test_tampered_token_is_rejected():
    token = create_token("user-123")
    tampered = token[:-6] + ("aaaaaa" if not token.endswith("aaaaaa") else "bbbbbb")
    with pytest.raises(AuthenticationError):
        decode_token(tampered)


def test_api_key_is_stored_only_as_a_digest():
    raw, digest = generate_api_key()
    assert raw.startswith("qntx_sk_")
    assert digest == hash_api_key(raw)
    assert raw not in digest


def test_webhook_signature_round_trip():
    body = b'{"alert": "test"}'
    signature = sign_payload(body)
    assert signature.startswith("sha256=")
    assert verify_signature(body, signature)


def test_webhook_signature_rejects_modified_body():
    signature = sign_payload(b'{"severity": "low"}')
    assert not verify_signature(b'{"severity": "critical"}', signature)
    assert not verify_signature(b'{"severity": "low"}', "")


@pytest.mark.parametrize(
    ("role", "permission", "expected"),
    [
        (Role.READ_ONLY, "read", True),
        (Role.READ_ONLY, "containment:execute", False),
        (Role.SOC_L1, "agent:run", True),
        (Role.SOC_L1, "approval:decide", False),
        (Role.SOC_L3, "approval:decide", True),
        (Role.SOC_L3, "settings:write", False),
        (Role.ADMIN, "settings:write", True),
        (Role.ADMIN, "containment:execute", True),
    ],
)
def test_role_permissions(role: Role, permission: str, expected: bool):
    assert (permission in permissions_for(role)) is expected
