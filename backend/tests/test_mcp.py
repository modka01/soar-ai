"""MCP tool registry, safety rails and dry-run behaviour."""

from __future__ import annotations

import pytest
from app.core.errors import NotFoundError
from app.services.mcp import RiskLevel, classify_indicator, get_registry
from app.services.mcp.tools import EnrichIOCTool


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("185.220.101.47", "ip"),
        ("10.0.0.0/24", "ip"),
        ("2001:db8::1", "ip"),
        ("update-service.xyz", "domain"),
        ("update-service[.]xyz", "domain"),
        ("https://evil.example/payload", "url"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
        ("a" * 64, "hash"),
        ("attacker@example.com", "email"),
        ("CVE-2024-3400", "cve"),
    ],
)
def test_indicator_classification(value: str, expected: str):
    assert classify_indicator(value) == expected


def test_registry_exposes_ten_tools():
    registry = get_registry()
    assert len(registry.all()) == 10
    assert "isolate_host" in registry.names()


def test_unknown_tool_raises_not_found():
    with pytest.raises(NotFoundError):
        get_registry().get("definitely_not_a_tool")


def test_destructive_tools_require_approval():
    registry = get_registry()
    for name in ("isolate_host", "block_ip", "aws_remediate", "run_playbook"):
        assert registry.requires_approval(name), f"{name} must be approval-gated"


def test_read_only_tools_do_not_require_approval():
    registry = get_registry()
    for name in ("query_siem", "enrich_ioc", "threat_intel"):
        assert not registry.requires_approval(name)


def test_mutating_tools_default_to_dry_run():
    """With SOAR_ALLOW_DESTRUCTIVE_ACTIONS false, mutating tools must not act."""
    registry = get_registry()
    assert registry.is_dry_run("block_ip")
    assert registry.is_dry_run("isolate_host")
    assert not registry.is_dry_run("query_siem")


def test_anthropic_schemas_are_well_formed():
    for schema in get_registry().anthropic_schemas():
        assert schema["name"]
        assert schema["description"]
        assert schema["input_schema"]["type"] == "object"
        for required in schema["input_schema"]["required"]:
            assert required in schema["input_schema"]["properties"]


@pytest.mark.parametrize("value", ["10.1.4.22", "192.168.1.10", "127.0.0.1"])
async def test_block_ip_refuses_non_routable_ranges(value: str):
    tool = get_registry().get("block_ip")
    result = await tool.execute({"ip": value, "reason": "test"}, dry_run=True)
    assert not result.ok
    assert "not globally routable" in (result.error or "").lower()


async def test_block_ip_refuses_overly_broad_cidr():
    tool = get_registry().get("block_ip")
    result = await tool.execute({"ip": "185.220.0.0/16", "reason": "test"}, dry_run=True)
    assert not result.ok
    assert "broader" in (result.error or "").lower()


async def test_block_ip_accepts_a_public_host_in_dry_run():
    tool = get_registry().get("block_ip")
    result = await tool.execute({"ip": "185.220.101.47", "reason": "C2"}, dry_run=True)
    assert result.ok
    assert result.dry_run
    assert result.to_dict()["would_block"] == "185.220.101.47/32"


async def test_block_ip_rejects_malformed_input():
    tool = get_registry().get("block_ip")
    result = await tool.execute({"ip": "not-an-ip", "reason": "test"}, dry_run=True)
    assert not result.ok


async def test_isolate_host_dry_run_changes_nothing():
    tool = get_registry().get("isolate_host")
    result = await tool.execute(
        {"hostname": "ws-finance-04", "reason": "confirmed C2"}, dry_run=True
    )
    assert result.ok and result.dry_run
    assert result.to_dict()["would_isolate"] == "ws-finance-04"


async def test_unconfigured_tool_reports_rather_than_fabricating():
    """With no SIEM credentials the tool must say so, not invent events."""
    tool = get_registry().get("query_siem")
    result = await tool.execute({"query": "index=* | head 10"})
    assert not result.ok
    assert result.data["status"] == "not_configured"
    assert "events" not in result.data


def test_ioc_verdict_uses_the_strongest_signal():
    """One provider flagging a known-bad IOC must not be diluted by silent ones."""
    verdict, confidence = EnrichIOCTool._consolidate(
        {
            "virustotal": {"malicious": 45, "total_engines": 70},
            "abuseipdb": {"abuse_confidence_score": 5},
        }
    )
    assert verdict == "malicious"
    assert confidence >= 70


def test_ioc_verdict_clean_when_nothing_is_flagged():
    verdict, confidence = EnrichIOCTool._consolidate(
        {
            "virustotal": {"malicious": 0, "total_engines": 70},
            "abuseipdb": {"abuse_confidence_score": 2},
        }
    )
    assert verdict == "clean"
    assert confidence < 35


def test_ioc_verdict_unknown_without_signals():
    assert EnrichIOCTool._consolidate({}) == ("unknown", 0)


async def test_execution_is_persisted_with_redacted_params(db):
    registry = get_registry()
    result, record = await registry.execute(
        db,
        "block_ip",
        {"ip": "203.0.113.9", "reason": "C2", "api_key": "super-secret-value"},
        invoked_by="tester",
    )
    assert result.dry_run
    assert record.tool_name == "block_ip"
    assert record.params["api_key"] == "***redacted***"
    assert record.params["ip"] == "203.0.113.9"


async def test_usage_stats_reflect_executions(db):
    registry = get_registry()
    await registry.execute(db, "query_siem", {"query": "index=*"}, invoked_by="tester")
    stats = {row["tool_name"]: row for row in await registry.usage_stats(db)}
    assert stats["query_siem"]["calls"] == 1


def test_risk_levels_map_to_approval_correctly():
    assert RiskLevel.CRITICAL.requires_approval
    assert RiskLevel.HIGH.requires_approval
    assert not RiskLevel.MEDIUM.requires_approval
    assert not RiskLevel.READ_ONLY.requires_approval
