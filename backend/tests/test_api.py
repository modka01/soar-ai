"""HTTP-level tests: authentication, authorisation, validation and error shape."""

from __future__ import annotations

import json

import pytest
from app.core.security import sign_payload


async def test_health_live_needs_no_auth(client):
    response = await client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


async def test_health_ready_reports_the_database(client):
    response = await client.get("/health/ready")
    assert response.status_code == 200
    assert response.json()["checks"]["database"] == "ok"


async def test_metrics_endpoint_records_requests(client):
    await client.get("/api/v1/alerts")  # generate one labelled sample
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert "soar_http_requests_total" in response.text
    assert "soar_http_request_duration_seconds" in response.text


async def test_protected_route_rejects_anonymous_callers(client):
    response = await client.get("/api/v1/alerts")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


async def test_error_envelope_carries_the_request_id(client):
    response = await client.get("/api/v1/alerts")
    body = response.json()
    assert set(body["error"]) >= {"code", "message", "details", "request_id"}
    assert response.headers["x-request-id"] == body["error"]["request_id"]


async def test_security_headers_are_applied(client):
    response = await client.get("/health/live")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


async def test_login_issues_a_token_pair(client, admin_user):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "Str0ng-Test-Passw0rd!"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"] and body["refresh_token"]
    assert body["token_type"] == "bearer"


async def test_login_with_a_wrong_password_is_rejected(client, admin_user):
    response = await client.post(
        "/api/v1/auth/login", json={"email": admin_user.email, "password": "wrong"}
    )
    assert response.status_code == 401


async def test_login_does_not_reveal_whether_an_account_exists(client, admin_user):
    unknown = await client.post(
        "/api/v1/auth/login", json={"email": "nobody@quantnexa.example.com", "password": "whatever"}
    )
    wrong = await client.post(
        "/api/v1/auth/login", json={"email": admin_user.email, "password": "whatever"}
    )
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["error"]["message"] == wrong.json()["error"]["message"]


async def test_me_returns_the_current_principal(client, auth, admin_user):
    response = await client.get("/api/v1/auth/me", headers=auth)
    assert response.status_code == 200
    assert response.json()["email"] == admin_user.email


async def test_refresh_rotates_the_access_token(client, admin_user):
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "Str0ng-Test-Passw0rd!"},
    )
    refresh = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": login.json()["refresh_token"]}
    )
    assert refresh.status_code == 200
    assert refresh.json()["access_token"]


async def test_an_access_token_cannot_be_used_to_refresh(client, admin_token):
    response = await client.post("/api/v1/auth/refresh", json={"refresh_token": admin_token})
    assert response.status_code == 401


async def test_weak_passwords_are_rejected_on_user_creation(client, auth):
    response = await client.post(
        "/api/v1/users",
        headers=auth,
        json={
            "email": "weak@quantnexa.example.com",
            "full_name": "Weak Password",
            "password": "alllowercaseletters",
            "role": "soc_l1",
        },
    )
    assert response.status_code == 422


async def test_analyst_cannot_manage_users(client, analyst_token):
    response = await client.get(
        "/api/v1/users", headers={"authorization": f"Bearer {analyst_token}"}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


async def test_admin_can_list_users(client, auth):
    response = await client.get("/api/v1/users", headers=auth)
    assert response.status_code == 200
    assert response.json()["total"] >= 1


async def test_api_key_is_returned_once_and_then_authenticates(client, auth):
    created = await client.post(
        "/api/v1/api-keys", headers=auth, json={"name": "ci-pipeline", "scopes": ["read"]}
    )
    assert created.status_code == 201
    raw_key = created.json()["api_key"]

    listed = await client.get("/api/v1/api-keys", headers=auth)
    assert all("api_key" not in item for item in listed.json())

    used = await client.get("/api/v1/alerts", headers={"x-api-key": raw_key})
    assert used.status_code == 200


async def test_api_key_scopes_cannot_widen_the_users_permissions(client, auth):
    """A read-scoped key on an admin account must not reach an admin-only route."""
    created = await client.post(
        "/api/v1/api-keys", headers=auth, json={"name": "read-only", "scopes": ["read"]}
    )
    raw_key = created.json()["api_key"]
    response = await client.get("/api/v1/users", headers={"x-api-key": raw_key})
    assert response.status_code == 403


async def test_a_revoked_api_key_stops_working(client, auth):
    created = await client.post("/api/v1/api-keys", headers=auth, json={"name": "temp"})
    raw_key, key_id = created.json()["api_key"], created.json()["id"]

    await client.delete(f"/api/v1/api-keys/{key_id}", headers=auth)
    response = await client.get("/api/v1/alerts", headers={"x-api-key": raw_key})
    assert response.status_code == 401


# ── alert ingestion ──────────────────────────────────────────────────

ALERT = {
    "title": "Suspected C2 beacon — DNS tunneling",
    "severity": "critical",
    "source": "Splunk",
    "asset": "ws-finance-04",
    "description": "847 queries per minute to a .xyz domain.",
    "indicators": ["185.220.101.47"],
}


async def test_alert_ingestion_requires_a_valid_signature(client):
    body = json.dumps(ALERT).encode()
    response = await client.post(
        "/api/v1/alerts/ingest",
        content=body,
        headers={"content-type": "application/json", "x-signature": "sha256=deadbeef"},
    )
    assert response.status_code == 401


async def test_alert_ingestion_accepts_a_signed_payload(client):
    body = json.dumps(ALERT).encode()
    response = await client.post(
        "/api/v1/alerts/ingest",
        content=body,
        headers={"content-type": "application/json", "x-signature": sign_payload(body)},
    )
    assert response.status_code == 202
    assert response.json()["reference"].startswith("ALT-")
    assert response.json()["risk_score"] > 50


async def test_repeat_alerts_are_deduplicated(client, auth):
    body = json.dumps(ALERT).encode()
    headers = {"content-type": "application/json", "x-signature": sign_payload(body)}

    first = await client.post("/api/v1/alerts/ingest", content=body, headers=headers)
    second = await client.post("/api/v1/alerts/ingest", content=body, headers=headers)

    assert first.json()["id"] == second.json()["id"]
    assert second.json()["duplicate_count"] == 1

    listed = await client.get("/api/v1/alerts", headers=auth)
    assert listed.json()["total"] == 1


async def test_alert_validation_rejects_an_unknown_severity(client):
    payload = {**ALERT, "severity": "apocalyptic"}
    body = json.dumps(payload).encode()
    response = await client.post(
        "/api/v1/alerts/ingest",
        content=body,
        headers={"content-type": "application/json", "x-signature": sign_payload(body)},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


async def test_alert_filters_and_pagination(client, auth):
    for index, severity in enumerate(["critical", "high", "low"]):
        payload = {
            **ALERT,
            "title": f"Alert {index}",
            "severity": severity,
            "asset": f"host-{index}",
        }
        body = json.dumps(payload).encode()
        await client.post(
            "/api/v1/alerts/ingest",
            content=body,
            headers={"content-type": "application/json", "x-signature": sign_payload(body)},
        )

    critical = await client.get("/api/v1/alerts?severity=critical", headers=auth)
    assert critical.json()["total"] == 1

    paged = await client.get("/api/v1/alerts?limit=2&offset=0", headers=auth)
    assert len(paged.json()["items"]) == 2
    assert paged.json()["total"] == 3


async def test_pagination_bounds_are_enforced(client, auth):
    assert (await client.get("/api/v1/alerts?limit=0", headers=auth)).status_code == 422
    assert (await client.get("/api/v1/alerts?limit=500", headers=auth)).status_code == 422


# ── other modules ────────────────────────────────────────────────────


async def test_mcp_tool_catalogue_is_served(client, auth):
    response = await client.get("/api/v1/mcp/tools", headers=auth)
    assert response.status_code == 200
    tools = response.json()
    assert len(tools) == 10
    isolate = next(tool for tool in tools if tool["name"] == "isolate_host")
    assert isolate["requires_approval"] is True
    assert isolate["schema"]["type"] == "object"


async def test_manual_invocation_of_a_destructive_tool_needs_containment_rights(
    client, analyst_token
):
    response = await client.post(
        "/api/v1/mcp/tools/isolate_host/invoke",
        headers={"authorization": f"Bearer {analyst_token}"},
        json={"params": {"hostname": "ws-01", "reason": "test"}},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "approval_required"


async def test_a_read_only_tool_can_be_invoked_directly(client, auth):
    response = await client.post(
        "/api/v1/mcp/tools/query_siem/invoke",
        headers=auth,
        json={"params": {"query": "index=* | head 5"}},
    )
    assert response.status_code == 200
    assert response.json()["tool_name"] == "query_siem"


async def test_invoking_an_unknown_tool_returns_404(client, auth):
    response = await client.post(
        "/api/v1/mcp/tools/no_such_tool/invoke", headers=auth, json={"params": {}}
    )
    assert response.status_code == 404


async def test_rag_index_and_retrieve_over_http(client, auth):
    created = await client.post(
        "/api/v1/rag/documents",
        headers=auth,
        json={
            "title": "Kerberoasting detection",
            "source": "MITRE ATT&CK",
            "category": "Credential Access",
            "content": (
                "Event ID 4769 with RC4 ticket encryption indicates a Kerberoasting attempt "
                "against accounts holding a service principal name."
            ),
        },
    )
    assert created.status_code == 201

    retrieved = await client.post(
        "/api/v1/rag/retrieve", headers=auth, json={"query": "kerberoasting 4769", "top_k": 3}
    )
    assert retrieved.status_code == 200
    assert retrieved.json()[0]["source"] == "MITRE ATT&CK"


async def test_sigma_generation_without_ai_and_conversion(client, auth):
    generated = await client.post(
        "/api/v1/sigma/generate",
        headers=auth,
        json={
            "scenario": "PsExec service creation on a domain controller",
            "tactic": "Lateral Movement",
            "log_source": "Windows EventLog",
            "severity": "high",
            "use_ai": False,
        },
    )
    assert generated.status_code == 201
    rule = generated.json()

    converted = await client.post(
        "/api/v1/sigma/convert",
        headers=auth,
        json={"yaml_body": rule["yaml_body"], "backend": "splunk"},
    )
    assert converted.status_code == 200
    assert converted.json()["query"].startswith("index=windows")


async def test_sigma_validation_rejects_a_broken_rule(client, auth):
    response = await client.post(
        "/api/v1/sigma/validate", headers=auth, json={"yaml_body": "title: incomplete\n"}
    )
    assert response.status_code == 422


async def test_agent_task_creation_and_retrieval(client, auth):
    created = await client.post(
        "/api/v1/agent/tasks",
        headers=auth,
        json={"task": "Investigate the critical alert queue", "stream": False},
    )
    assert created.status_code == 201
    session_id = created.json()["id"]

    fetched = await client.get(f"/api/v1/agent/sessions/{session_id}", headers=auth)
    assert fetched.status_code == 200
    assert fetched.json()["messages"][0]["role"] == "user"


async def test_agent_task_requires_the_run_permission(client, db):
    from app.core.security import ACCESS_TOKEN, Role, create_token, hash_password
    from app.db.models import User

    reader = User(
        email="reader@quantnexa.example.com",
        full_name="Read Only",
        hashed_password=hash_password("Str0ng-Test-Passw0rd!"),
        role=Role.READ_ONLY.value,
    )
    db.add(reader)
    await db.commit()

    token = create_token(reader.id, token_type=ACCESS_TOKEN, role=reader.role)
    response = await client.post(
        "/api/v1/agent/tasks",
        headers={"authorization": f"Bearer {token}"},
        json={"task": "Do something"},
    )
    assert response.status_code == 403


async def test_dashboard_rollup_is_served(client, auth):
    response = await client.get("/api/v1/dashboard", headers=auth)
    assert response.status_code == 200
    body = response.json()
    assert set(body) >= {
        "critical_alerts",
        "open_incidents",
        "alert_distribution",
        "integration_health",
        "recent_alerts",
    }


async def test_playbooks_are_seeded_and_runnable(client, auth, db):
    from app.services.seed import seed_playbooks

    await seed_playbooks(db)
    await db.commit()

    listed = await client.get("/api/v1/playbooks", headers=auth)
    assert listed.status_code == 200
    assert len(listed.json()) == 6

    run = await client.post("/api/v1/playbooks/phishing-response/run", headers=auth, json={})
    assert run.status_code == 202
    # Destructive actions are disabled in tests, so the run must be a dry run.
    assert run.json()["dry_run"] is True
    assert run.json()["status"] == "dry_run"


async def test_incident_lifecycle(client, auth):
    created = await client.post(
        "/api/v1/incidents",
        headers=auth,
        json={"title": "APT-29 C2 confirmed", "severity": "critical", "asset": "ws-finance-04"},
    )
    assert created.status_code == 201
    incident_id = created.json()["id"]

    await client.post(
        f"/api/v1/incidents/{incident_id}/events",
        headers=auth,
        json={"message": "Host isolated via CrowdStrike RTR.", "kind": "containment"},
    )
    contained = await client.patch(
        f"/api/v1/incidents/{incident_id}/status", headers=auth, json={"status": "contained"}
    )
    assert contained.json()["status"] == "contained"
    assert contained.json()["contained_at"]

    detail = await client.get(f"/api/v1/incidents/{incident_id}", headers=auth)
    kinds = [event["kind"] for event in detail.json()["events"]]
    assert "created" in kinds and "containment" in kinds and "status_change" in kinds


async def test_audit_log_records_privileged_actions(client, auth):
    await client.post(
        "/api/v1/incidents",
        headers=auth,
        json={"title": "Audited incident", "severity": "high"},
    )
    response = await client.get("/api/v1/audit", headers=auth)
    assert response.status_code == 200
    actions = [entry["action"] for entry in response.json()["items"]]
    assert "incident_create" in actions


async def test_audit_log_is_admin_only(client, analyst_token):
    response = await client.get(
        "/api/v1/audit", headers={"authorization": f"Bearer {analyst_token}"}
    )
    assert response.status_code == 403


async def test_settings_secrets_are_masked_on_read(client, auth):
    await client.put(
        "/api/v1/settings/agent",
        headers=auth,
        json={"values": {"anthropic_api_key": "sk-ant-real-secret", "max_tokens": 2000}},
    )
    response = await client.get("/api/v1/settings/agent", headers=auth)
    body = response.json()
    assert body["anthropic_api_key"] == "••••••••"
    assert body["max_tokens"] == 2000


async def test_settings_export_redacts_every_secret(client, auth):
    await client.put(
        "/api/v1/settings/notify",
        headers=auth,
        json={"values": {"smtp_password": "hunter2", "smtp_host": "smtp.example.com"}},
    )
    response = await client.get("/api/v1/settings-export", headers=auth)
    exported = response.json()["settings"]["notify"]
    assert exported["smtp_password"] == "***redacted***"
    assert exported["smtp_host"] == "smtp.example.com"


async def test_settings_write_requires_admin(client, analyst_token):
    response = await client.put(
        "/api/v1/settings/general",
        headers={"authorization": f"Bearer {analyst_token}"},
        json={"values": {"org_name": "Attacker Corp"}},
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/threats/feed",
        "/api/v1/threats/stats",
        "/api/v1/rag/stats",
        "/api/v1/mcp/stats",
        "/api/v1/integrations",
        "/api/v1/incidents/metrics",
        "/api/v1/alerts/distribution",
        "/api/v1/sigma/backends",
        "/api/v1/playbooks/stats",
    ],
)
async def test_read_endpoints_respond(client, auth, path: str):
    response = await client.get(path, headers=auth)
    assert response.status_code == 200


async def test_dedup_folds_numeric_variance_but_not_distinct_assets(client, auth):
    """ "847 attempts" and "912 attempts" are one alert; two hosts are never one."""

    async def ingest(title: str, asset: str):
        body = json.dumps({**ALERT, "title": title, "asset": asset}).encode()
        return await client.post(
            "/api/v1/alerts/ingest",
            content=body,
            headers={"content-type": "application/json", "x-signature": sign_payload(body)},
        )

    first = await ingest("SSH brute force — 847 attempts", "srv-app-07")
    same = await ingest("SSH brute force — 912 attempts", "srv-app-07")
    other_host = await ingest("SSH brute force — 847 attempts", "srv-app-08")

    assert same.json()["id"] == first.json()["id"]
    assert other_host.json()["id"] != first.json()["id"]
    assert (await client.get("/api/v1/alerts", headers=auth)).json()["total"] == 2
