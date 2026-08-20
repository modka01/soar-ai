"""Sigma generation, validation and SIEM backend conversion."""

from __future__ import annotations

import pytest
import yaml
from app.core.errors import ValidationError
from app.services.sigma import SigmaService, convert_rule


async def test_generated_rule_is_valid_sigma():
    draft = await SigmaService.generate_rule_yaml(
        scenario="PsExec service creation on a domain controller",
        tactic="Lateral Movement",
        log_source="Windows EventLog",
        severity="high",
    )
    document = SigmaService.validate(draft.yaml_body)
    assert document["title"]
    assert document["level"] == "high"
    assert document["logsource"]["product"] == "windows"
    assert "T1021" in draft.mitre_techniques


async def test_log_source_maps_to_the_right_product():
    for label, product in (
        ("Sysmon", "windows"),
        ("AWS CloudTrail", "aws"),
        ("Linux Auditd", "linux"),
        ("DNS", "dns"),
        ("Network/Firewall", "firewall"),
    ):
        draft = await SigmaService.generate_rule_yaml(
            scenario="test", tactic="Execution", log_source=label, severity="medium"
        )
        assert yaml.safe_load(draft.yaml_body)["logsource"]["product"] == product


async def test_title_is_truncated_to_sigma_limits():
    draft = await SigmaService.generate_rule_yaml(
        scenario="x" * 200, tactic="Execution", log_source="Sysmon", severity="low"
    )
    assert len(yaml.safe_load(draft.yaml_body)["title"]) <= 60


def test_validation_rejects_invalid_yaml():
    with pytest.raises(ValidationError, match="not valid YAML"):
        SigmaService.validate("title: [unclosed")


def test_validation_rejects_missing_required_keys():
    with pytest.raises(ValidationError, match="missing required key"):
        SigmaService.validate("title: Only a title\n")


def test_validation_rejects_detection_without_condition():
    with pytest.raises(ValidationError, match="condition"):
        SigmaService.validate(
            "title: T\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n"
        )


def test_validation_rejects_an_unknown_level():
    with pytest.raises(ValidationError, match="not a valid Sigma level"):
        SigmaService.validate(
            "title: T\nlogsource:\n  product: windows\n"
            "detection:\n  selection:\n    EventID: 1\n  condition: selection\nlevel: urgent\n"
        )


SAMPLE_RULE = """
title: PsExec Service Creation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 7045
    ServiceName|contains: PSEXESVC
  filter:
    User|contains: SYSTEM
  condition: selection and not filter
level: high
"""


def test_splunk_conversion_maps_fields_and_index():
    query = convert_rule(yaml.safe_load(SAMPLE_RULE), "splunk")
    assert query.startswith("index=windows")
    assert "EventCode=" in query  # EventID is mapped for Splunk
    assert "*PSEXESVC*" in query
    assert "AND NOT" in query


def test_elastic_conversion_uses_ecs_field_names():
    query = convert_rule(yaml.safe_load(SAMPLE_RULE), "elastic")
    assert "winlog.event_id" in query


def test_sentinel_conversion_targets_a_table():
    query = convert_rule(yaml.safe_load(SAMPLE_RULE), "sentinel")
    assert query.startswith("SecurityEvent")
    assert "| where" in query
    assert "contains" in query


def test_qradar_conversion_emits_sql():
    assert convert_rule(yaml.safe_load(SAMPLE_RULE), "qradar").startswith("SELECT * FROM events")


def test_unsupported_backend_is_rejected():
    with pytest.raises(ValidationError, match="not a supported backend"):
        convert_rule(yaml.safe_load(SAMPLE_RULE), "arcsight")


def test_list_values_convert_to_an_or_group():
    rule = yaml.safe_load(
        "title: T\nlogsource:\n  product: windows\n"
        "detection:\n  selection:\n    EventID:\n      - 4624\n      - 4625\n"
        "  condition: selection\n"
    )
    query = convert_rule(rule, "splunk")
    assert " OR " in query
    assert "4624" in query and "4625" in query


async def test_saving_persists_a_draft(db):
    service = SigmaService(db)
    draft = await SigmaService.generate_rule_yaml(
        scenario="Kerberoasting via RC4 ticket requests",
        tactic="Credential Access",
        log_source="Windows EventLog",
        severity="high",
    )
    rule = await service.save(draft, author="tester")
    assert rule.reference.startswith("S")
    assert rule.status == "draft"

    fetched = await service.get(rule.reference)
    assert fetched.id == rule.id


async def test_deploy_records_a_converted_query_per_backend(db):
    service = SigmaService(db)
    draft = await SigmaService.generate_rule_yaml(
        scenario="Suspicious encoded PowerShell",
        tactic="Execution",
        log_source="Sysmon",
        severity="medium",
    )
    rule = await service.save(draft, author="tester")
    deployments = await service.deploy(rule.id, ["splunk", "elastic"], deployed_by="tester")

    assert len(deployments) == 2
    assert all(d.status == "converted" and d.converted_query for d in deployments)
    assert rule.status == "testing"
