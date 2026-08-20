"""The ten MCP tools the SOAR agent can call.

Each tool talks to a real integration when credentials are present. Without
credentials a tool reports ``not_configured`` rather than inventing data — a
SOC console that fabricates enrichment is worse than one that says it cannot
reach VirusTotal.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.integrations.aws import AWSSecurityClient
from app.integrations.edr import CrowdStrikeClient
from app.integrations.firewall import PaloAltoClient
from app.integrations.n8n import N8NClient
from app.integrations.siem import ElasticClient, SplunkClient
from app.integrations.ticketing import JiraClient
from app.integrations.tip import AbuseIPDBClient, MISPClient, OTXClient, VirusTotalClient
from app.integrations.vuln import TenableClient
from app.services.mcp.base import MCPTool, RiskLevel, ToolCategory, ToolResult

logger = get_logger(__name__)

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")


def classify_indicator(value: str) -> str:
    """Infer an IOC's type so callers need not pass ``ioc_type`` explicitly."""
    value = value.strip().replace("[.]", ".")
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return "ip"
    except ValueError:
        pass
    if value.lower().startswith(("http://", "https://")):
        return "url"
    if _HASH_RE.match(value):
        return "hash"
    if "@" in value:
        return "email"
    if value.upper().startswith("CVE-"):
        return "cve"
    if _DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


def _now() -> str:
    return datetime.now(UTC).isoformat()


# ══ Analytics ═══════════════════════════════════════════════════════


class QuerySIEMTool(MCPTool):
    name = "query_siem"
    label = "SIEM Query"
    description = (
        "Execute a search against the configured SIEM (Splunk SPL or Elastic EQL/Lucene) "
        "and return matching events. Read-only."
    )
    category = ToolCategory.ANALYTICS
    risk = RiskLevel.READ_ONLY
    icon = "📊"
    parameters = {
        "query": {"type": "string", "description": "SPL, EQL or Lucene query to execute"},
        "time_range": {
            "type": "string",
            "description": "Relative window, e.g. 'last 24h', 'last 7d'",
            "default": "last 24h",
        },
        "limit": {"type": "integer", "description": "Maximum rows to return", "default": 100},
        "backend": {"type": "string", "enum": ["splunk", "elastic", "auto"], "default": "auto"},
    }
    required = ["query"]

    async def run(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        query = params["query"]
        time_range = params.get("time_range", "last 24h")
        limit = min(int(params.get("limit", 100)), 1000)
        backend = params.get("backend", "auto")

        splunk = SplunkClient()
        elastic = ElasticClient()

        if backend == "splunk" or (backend == "auto" and splunk.is_configured()):
            async with splunk:
                events = await splunk.search(query, time_range=time_range, limit=limit)
                return ToolResult(
                    ok=True,
                    data={
                        "backend": "splunk",
                        "query": query,
                        "time_range": time_range,
                        "event_count": len(events),
                        "events": events,
                    },
                )
        if backend == "elastic" or (backend == "auto" and elastic.is_configured()):
            async with elastic:
                events = await elastic.search(query, time_range=time_range, limit=limit)
                return ToolResult(
                    ok=True,
                    data={
                        "backend": "elastic",
                        "query": query,
                        "time_range": time_range,
                        "event_count": len(events),
                        "events": events,
                    },
                )

        return ToolResult(
            ok=False,
            error="No SIEM backend is configured. Add Splunk or Elastic credentials in Settings.",
            data={"status": "not_configured"},
        )


class GenerateSigmaTool(MCPTool):
    name = "generate_sigma"
    label = "Generate Sigma"
    description = (
        "Generate a Sigma detection rule from an attack scenario, MITRE tactic and log source. "
        "Returns validated YAML; the rule is saved as a draft, never auto-deployed."
    )
    category = ToolCategory.ANALYTICS
    risk = RiskLevel.LOW
    icon = "Σ"
    parameters = {
        "scenario": {"type": "string", "description": "Attack scenario or observed behaviour"},
        "tactic": {"type": "string", "description": "MITRE ATT&CK tactic"},
        "log_source": {"type": "string", "description": "Log source, e.g. 'Sysmon', 'DNS'"},
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
            "default": "high",
        },
    }
    required = ["scenario"]

    async def run(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        # Imported lazily: sigma service imports the registry, so a module-level
        # import here would create a cycle.
        from app.services.sigma import SigmaService

        draft = await SigmaService.generate_rule_yaml(
            scenario=params["scenario"],
            tactic=params.get("tactic", "Execution"),
            log_source=params.get("log_source", "Windows EventLog"),
            severity=params.get("severity", "high"),
        )
        return ToolResult(
            ok=True,
            data={
                "rule_uuid": draft.rule_uuid,
                "title": draft.title,
                "severity": draft.severity,
                "tactic": draft.tactic,
                "yaml": draft.yaml_body,
                "mitre_techniques": draft.mitre_techniques,
                "status": "draft",
            },
        )


# ══ Intel ═══════════════════════════════════════════════════════════


class EnrichIOCTool(MCPTool):
    name = "enrich_ioc"
    label = "IOC Enrichment"
    description = (
        "Enrich an IP, domain, URL or file hash across VirusTotal, AbuseIPDB and AlienVault OTX. "
        "Returns a consolidated verdict and confidence. Read-only."
    )
    category = ToolCategory.INTEL
    risk = RiskLevel.READ_ONLY
    icon = "🔍"
    parameters = {
        "ioc": {"type": "string", "description": "The indicator to enrich"},
        "ioc_type": {
            "type": "string",
            "enum": ["ip", "domain", "url", "hash", "email", "auto"],
            "default": "auto",
        },
    }
    required = ["ioc"]

    async def run(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        ioc = params["ioc"].strip().replace("[.]", ".")
        ioc_type = params.get("ioc_type", "auto")
        if ioc_type in ("auto", None, ""):
            ioc_type = classify_indicator(ioc)

        sources: dict[str, Any] = {}
        errors: dict[str, str] = {}

        for client_cls, key in (
            (VirusTotalClient, "virustotal"),
            (AbuseIPDBClient, "abuseipdb"),
            (OTXClient, "otx"),
        ):
            client = client_cls()
            if not client.is_configured():
                continue
            try:
                async with client:
                    sources[key] = await client.lookup(ioc, ioc_type)
            except Exception as exc:
                errors[key] = str(exc)[:200]

        if not sources:
            return ToolResult(
                ok=False,
                error=(
                    "No threat-intelligence provider is configured. "
                    "Add a VirusTotal, AbuseIPDB or OTX key in Settings."
                ),
                data={"ioc": ioc, "ioc_type": ioc_type, "status": "not_configured"},
            )

        verdict, confidence = self._consolidate(sources)
        return ToolResult(
            ok=True,
            data={
                "ioc": ioc,
                "ioc_type": ioc_type,
                "verdict": verdict,
                "confidence": confidence,
                "sources": sources,
                "source_errors": errors,
                "enriched_at": _now(),
            },
        )

    @staticmethod
    def _consolidate(sources: dict[str, Any]) -> tuple[str, int]:
        """Combine provider signals into one verdict and a 0-100 confidence.

        Confidence is the strongest single signal rather than an average, so
        one provider flagging a known C2 is not diluted by two that have never
        seen the indicator.
        """
        signals: list[int] = []

        vt = sources.get("virustotal") or {}
        malicious = int(vt.get("malicious", 0))
        total = int(vt.get("total_engines", 0)) or 1
        if malicious:
            signals.append(min(100, int(malicious / total * 100) + 50))

        abuse = sources.get("abuseipdb") or {}
        if abuse.get("abuse_confidence_score") is not None:
            signals.append(int(abuse["abuse_confidence_score"]))

        otx = sources.get("otx") or {}
        pulses = int(otx.get("pulse_count", 0))
        if pulses:
            signals.append(min(100, 40 + pulses * 10))

        if not signals:
            return "unknown", 0
        confidence = max(signals)
        if confidence >= 70:
            return "malicious", confidence
        if confidence >= 35:
            return "suspicious", confidence
        return "clean", confidence


class ThreatIntelTool(MCPTool):
    name = "threat_intel"
    label = "Threat Intel"
    description = (
        "Query MISP and AlienVault OTX for threat-actor attribution, related IOC clusters "
        "and observed TTPs. Read-only."
    )
    category = ToolCategory.INTEL
    risk = RiskLevel.READ_ONLY
    icon = "🕵"
    parameters = {
        "query": {"type": "string", "description": "Actor, campaign, malware family or IOC"},
        "source": {"type": "string", "enum": ["misp", "otx", "all"], "default": "all"},
    }
    required = ["query"]

    async def run(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        query = params["query"]
        source = params.get("source", "all")
        results: dict[str, Any] = {}
        errors: dict[str, str] = {}

        if source in ("misp", "all"):
            misp = MISPClient()
            if misp.is_configured():
                try:
                    async with misp:
                        results["misp"] = await misp.search(query)
                except Exception as exc:
                    errors["misp"] = str(exc)[:200]

        if source in ("otx", "all"):
            otx = OTXClient()
            if otx.is_configured():
                try:
                    async with otx:
                        results["otx"] = await otx.search_pulses(query)
                except Exception as exc:
                    errors["otx"] = str(exc)[:200]

        if not results:
            return ToolResult(
                ok=False,
                error="No threat-intelligence platform is configured (MISP or OTX).",
                data={"query": query, "status": "not_configured"},
            )

        actors: set[str] = set()
        techniques: set[str] = set()
        for payload in results.values():
            actors.update(payload.get("threat_actors", []))
            techniques.update(payload.get("mitre_techniques", []))

        return ToolResult(
            ok=True,
            data={
                "query": query,
                "threat_actors": sorted(actors),
                "mitre_techniques": sorted(techniques),
                "sources": results,
                "source_errors": errors,
                "queried_at": _now(),
            },
        )


# ══ Network / response ══════════════════════════════════════════════


class BlockIPTool(MCPTool):
    name = "block_ip"
    label = "Firewall Block"
    description = (
        "Add an IP or CIDR to the perimeter firewall deny list. Destructive: requires "
        "human approval and refuses ranges broader than /24 without an explicit override."
    )
    category = ToolCategory.NETWORK
    risk = RiskLevel.HIGH
    icon = "🔒"
    mutating = True
    parameters = {
        "ip": {"type": "string", "description": "IP address or CIDR to block"},
        "reason": {"type": "string", "description": "Justification recorded in the audit log"},
        "duration": {
            "type": "string",
            "enum": ["1h", "24h", "7d", "permanent"],
            "default": "24h",
        },
        "allow_wide_range": {
            "type": "boolean",
            "description": "Explicitly permit a prefix broader than /24",
            "default": False,
        },
    }
    required = ["ip", "reason"]

    async def run(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        raw = params["ip"].strip()
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            return ToolResult(ok=False, error=f"'{raw}' is not a valid IP or CIDR: {exc}")

        if not network.is_global and not params.get("allow_wide_range"):
            # Covers RFC1918, loopback, link-local and the reserved documentation
            # ranges — none of which belong in a perimeter deny list.
            return ToolResult(
                ok=False,
                error=(
                    f"{network} is not globally routable (private, loopback or reserved space). "
                    "Blocking it at the perimeter is almost always a mistake — isolate the host "
                    "instead."
                ),
            )

        max_prefix = 24 if network.version == 4 else 64
        if network.prefixlen < max_prefix and not params.get("allow_wide_range"):
            return ToolResult(
                ok=False,
                error=(
                    f"{network} covers {network.num_addresses} addresses. Blocking a range "
                    f"broader than /{max_prefix} needs allow_wide_range=true and a second approval."
                ),
            )

        if dry_run:
            return ToolResult(
                ok=True,
                dry_run=True,
                data={
                    "would_block": str(network),
                    "duration": params.get("duration", "24h"),
                    "reason": params["reason"],
                },
            )

        client = PaloAltoClient()
        async with client:
            result = await client.block_address(
                str(network), reason=params["reason"], duration=params.get("duration", "24h")
            )
        return ToolResult(ok=True, data={**result, "blocked_at": _now()})


class IsolateHostTool(MCPTool):
    name = "isolate_host"
    label = "Isolate Host"
    description = (
        "Network-isolate an endpoint through the EDR (CrowdStrike RTR containment), keeping the "
        "IR channel open. Destructive: always requires human approval."
    )
    category = ToolCategory.RESPONSE
    risk = RiskLevel.CRITICAL
    icon = "🛑"
    mutating = True
    parameters = {
        "hostname": {"type": "string", "description": "Hostname or EDR device ID"},
        "reason": {"type": "string", "description": "Justification recorded in the audit log"},
        "preserve_ir_channel": {"type": "boolean", "default": True},
    }
    required = ["hostname", "reason"]

    async def run(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        hostname = params["hostname"].strip()
        if dry_run:
            return ToolResult(
                ok=True,
                dry_run=True,
                data={"would_isolate": hostname, "reason": params["reason"]},
            )

        client = CrowdStrikeClient()
        async with client:
            device_id = await client.resolve_device_id(hostname)
            result = await client.contain_host(device_id, reason=params["reason"])
        return ToolResult(
            ok=True,
            data={
                **result,
                "hostname": hostname,
                "ir_channel_preserved": bool(params.get("preserve_ir_channel", True)),
                "isolated_at": _now(),
            },
        )


class CreateTicketTool(MCPTool):
    name = "create_ticket"
    label = "Create Ticket"
    description = "Open an incident ticket in Jira for tracking and hand-off to a human analyst."
    category = ToolCategory.RESPONSE
    risk = RiskLevel.LOW
    icon = "🎫"
    mutating = True
    parameters = {
        "title": {"type": "string"},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "description": {"type": "string"},
        "incident_id": {"type": "string", "description": "SOAR incident reference to link"},
    }
    required = ["title", "severity", "description"]

    async def run(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        if dry_run:
            return ToolResult(ok=True, dry_run=True, data={"would_create": params["title"]})
        client = JiraClient()
        async with client:
            result = await client.create_issue(
                summary=params["title"],
                description=params["description"],
                severity=params["severity"],
                labels=["soar", "ai-agent"],
            )
        return ToolResult(ok=True, data={**result, "created_at": _now()})


class RunPlaybookTool(MCPTool):
    name = "run_playbook"
    label = "Run Playbook"
    description = (
        "Execute a named response playbook through the n8n workflow engine. "
        "Playbooks marked as requiring approval are gated before any step runs."
    )
    category = ToolCategory.RESPONSE
    risk = RiskLevel.HIGH
    icon = "▶"
    mutating = True
    parameters = {
        "playbook": {"type": "string", "description": "Playbook slug or name"},
        "incident_id": {"type": "string"},
        "parameters": {"type": "object", "description": "Playbook-specific inputs"},
    }
    required = ["playbook"]

    async def run(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        playbook = params["playbook"]
        if dry_run:
            return ToolResult(ok=True, dry_run=True, data={"would_run": playbook})
        client = N8NClient()
        async with client:
            result = await client.trigger_workflow(
                playbook,
                payload={
                    "incident_id": params.get("incident_id"),
                    **(params.get("parameters") or {}),
                },
            )
        return ToolResult(ok=True, data={**result, "triggered_at": _now()})


# ══ Cloud / security ════════════════════════════════════════════════


class AWSRemediateTool(MCPTool):
    name = "aws_remediate"
    label = "AWS Remediate"
    description = (
        "Apply an AWS remediation: block a security group, revoke IAM credentials, "
        "block public S3 access, or snapshot an EC2 volume. Destructive: requires approval."
    )
    category = ToolCategory.CLOUD
    risk = RiskLevel.HIGH
    icon = "☁"
    mutating = True
    parameters = {
        "action": {
            "type": "string",
            "enum": ["block_sg", "revoke_iam", "block_s3", "snapshot_ec2", "disable_access_key"],
        },
        "resource_id": {"type": "string", "description": "SG id, IAM user, bucket or instance id"},
        "region": {"type": "string", "description": "AWS region", "default": ""},
        "reason": {"type": "string"},
    }
    required = ["action", "resource_id"]

    async def run(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        action = params["action"]
        resource_id = params["resource_id"]
        region = params.get("region") or settings.aws_region

        if dry_run:
            return ToolResult(
                ok=True,
                dry_run=True,
                data={"would_apply": action, "resource_id": resource_id, "region": region},
            )

        client = AWSSecurityClient(region=region)
        result = await client.remediate(
            action, resource_id, reason=params.get("reason", "SOAR automated remediation")
        )
        return ToolResult(ok=True, data={**result, "remediated_at": _now()})


class VulnScanTool(MCPTool):
    name = "vuln_scan"
    label = "Vulnerability Scan"
    description = "Launch or fetch a Tenable/Nessus scan for a target asset. Read-mostly."
    category = ToolCategory.SECURITY
    risk = RiskLevel.MEDIUM
    icon = "🔬"
    mutating = True
    parameters = {
        "target": {"type": "string", "description": "IP, hostname or CIDR to scan"},
        "profile": {
            "type": "string",
            "enum": ["basic", "full", "compliance"],
            "default": "basic",
        },
    }
    required = ["target"]

    async def run(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        target = params["target"]
        profile = params.get("profile", "basic")
        if dry_run:
            return ToolResult(
                ok=True, dry_run=True, data={"would_scan": target, "profile": profile}
            )
        client = TenableClient()
        async with client:
            result = await client.launch_scan(target, profile=profile)
        return ToolResult(ok=True, data={**result, "requested_at": _now()})


#: Instantiated in registry order — this is the order the UI renders them.
ALL_TOOLS: list[MCPTool] = [
    QuerySIEMTool(),
    EnrichIOCTool(),
    BlockIPTool(),
    IsolateHostTool(),
    AWSRemediateTool(),
    CreateTicketTool(),
    ThreatIntelTool(),
    RunPlaybookTool(),
    GenerateSigmaTool(),
    VulnScanTool(),
]
