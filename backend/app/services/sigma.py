"""Sigma rule generation, validation, storage and SIEM backend conversion."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.db.models import RuleDeployment, RuleStatus, Severity, SigmaRule
from app.integrations.llm import LLMClient, get_llm_client
from app.services.rag import RAGService

logger = get_logger(__name__)

#: Log source label → Sigma ``logsource`` product/service pair.
LOG_SOURCE_MAP: dict[str, tuple[str, str]] = {
    "windows eventlog": ("windows", "security"),
    "sysmon": ("windows", "sysmon"),
    "aws cloudtrail": ("aws", "cloudtrail"),
    "linux auditd": ("linux", "auditd"),
    "azure ad": ("azure", "signinlogs"),
    "dns": ("dns", ""),
    "network/firewall": ("firewall", ""),
}

#: MITRE tactic → the technique most commonly used to represent it in a rule tag.
TACTIC_TECHNIQUES: dict[str, str] = {
    "initial access": "T1566",
    "execution": "T1059",
    "persistence": "T1543",
    "privilege escalation": "T1068",
    "defense evasion": "T1070",
    "credential access": "T1003",
    "discovery": "T1087",
    "lateral movement": "T1021",
    "collection": "T1005",
    "command and control": "T1071",
    "exfiltration": "T1041",
    "impact": "T1486",
}

GENERATION_PROMPT = """You are a detection engineer at QuantNexa Technologies writing Sigma \
rules. Produce a rule that is specific enough to fire on the described behaviour and tuned \
enough not to drown the SOC in false positives.

Reply with a single JSON object:
{
  "title": "concise rule title, under 60 characters",
  "description": "what this detects and why it matters",
  "detection": {"selection": {...}, "condition": "selection and not filter"},
  "filter": {"...": "exclusions that suppress known-good activity"},
  "falsepositives": ["known benign sources of this signal"],
  "mitre_techniques": ["T1021.002"],
  "level": "critical|high|medium|low",
  "fields": ["fields an analyst should pivot on"]
}

Rules:
- Use real field names for the log source given (Sysmon uses Image/ParentImage/CommandLine, \
Windows Security uses EventID/TargetUserName, CloudTrail uses eventName/userIdentity.arn).
- Sigma modifiers you may use: |contains, |startswith, |endswith, |re, |all.
- Always include a filter that excludes obvious legitimate activity.
"""

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass(slots=True)
class SigmaDraft:
    """A generated rule, before it is persisted."""

    rule_uuid: str
    title: str
    description: str
    tactic: str
    log_source: str
    severity: str
    yaml_body: str
    mitre_techniques: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    ai_generated: bool = False


class SigmaService:
    """Generates, stores, converts and deploys Sigma rules."""

    def __init__(self, db: AsyncSession, llm: LLMClient | None = None) -> None:
        self.db = db
        self.llm = llm or get_llm_client()

    # ── generation ───────────────────────────────────────────────────

    @staticmethod
    async def generate_rule_yaml(
        *,
        scenario: str,
        tactic: str,
        log_source: str,
        severity: str,
        detection: dict[str, Any] | None = None,
        title: str | None = None,
        description: str | None = None,
        false_positives: list[str] | None = None,
        techniques: list[str] | None = None,
        author: str = "QuantNexa SOAR·AI Agent",
    ) -> SigmaDraft:
        """Assemble a valid Sigma document. Used with or without the LLM."""
        product, service = LOG_SOURCE_MAP.get(log_source.lower(), ("windows", "security"))
        severity = Severity(severity).value if severity != "info" else "low"
        rule_uuid = str(uuid.uuid4())

        techniques = [t for t in (techniques or []) if _TECHNIQUE_RE.match(t)]
        if not techniques:
            fallback = TACTIC_TECHNIQUES.get(tactic.lower())
            techniques = [fallback] if fallback else []

        detection = detection or {
            "selection": {"EventID": [4688], "CommandLine|contains": ["-enc", "bypass"]},
            "condition": "selection",
        }
        if "condition" not in detection:
            detection["condition"] = " and ".join(k for k in detection if k != "condition")

        document: dict[str, Any] = {
            "title": (title or scenario)[:60].strip(),
            "id": rule_uuid,
            "status": RuleStatus.EXPERIMENTAL.value,
            "description": description or f"Detects: {scenario}",
            "author": author,
            "date": date.today().isoformat(),
            "references": [
                f"https://attack.mitre.org/techniques/{t.split('.')[0]}/" for t in techniques
            ],
            "tags": [f"attack.{tactic.lower().replace(' ', '_')}"]
            + [f"attack.{t.lower()}" for t in techniques],
            "logsource": {"product": product, **({"service": service} if service else {})},
            "detection": detection,
            "falsepositives": false_positives
            or ["Legitimate administrative activity", "Deployment tooling (SCCM, Ansible)"],
            "level": severity,
        }

        yaml_body = yaml.safe_dump(document, sort_keys=False, default_flow_style=False, width=100)
        return SigmaDraft(
            rule_uuid=rule_uuid,
            title=document["title"],
            description=document["description"],
            tactic=tactic,
            log_source=log_source,
            severity=severity,
            yaml_body=yaml_body,
            mitre_techniques=techniques,
            false_positives=document["falsepositives"],
        )

    async def generate_with_ai(
        self,
        *,
        scenario: str,
        tactic: str,
        log_source: str,
        severity: str,
        author: str = "QuantNexa SOAR·AI Agent",
    ) -> SigmaDraft:
        """Ask the model for the detection logic, then assemble valid Sigma around it."""
        rag = RAGService(self.db)
        context_results = await rag.retrieve(f"{scenario} {tactic} detection", top_k=4)
        context = RAGService.build_context(context_results)

        system = GENERATION_PROMPT + (
            f"\n\nRelevant detection knowledge:\n{context}" if context else ""
        )
        prompt = (
            f"Scenario: {scenario}\nMITRE tactic: {tactic}\n"
            f"Log source: {log_source}\nTarget severity: {severity}"
        )

        result, _ = await self.llm.complete_json(
            [{"role": "user", "content": prompt}], system=system, max_tokens=2000
        )

        detection = result.get("detection") or {}
        if result.get("filter"):
            detection["filter"] = result["filter"]
            detection.setdefault("condition", "selection and not filter")

        draft = await self.generate_rule_yaml(
            scenario=scenario,
            tactic=tactic,
            log_source=log_source,
            severity=result.get("level", severity),
            detection=detection or None,
            title=result.get("title"),
            description=result.get("description"),
            false_positives=result.get("falsepositives"),
            techniques=result.get("mitre_techniques"),
            author=author,
        )
        draft.ai_generated = True
        return draft

    # ── validation ───────────────────────────────────────────────────

    @staticmethod
    def validate(yaml_body: str) -> dict[str, Any]:
        """Parse and structurally validate a Sigma document.

        Raises :class:`ValidationError` rather than returning a flag, so an
        invalid rule can never reach a SIEM deployment path.
        """
        try:
            document = yaml.safe_load(yaml_body)
        except yaml.YAMLError as exc:
            raise ValidationError(f"Rule is not valid YAML: {exc}") from exc

        if not isinstance(document, dict):
            raise ValidationError("A Sigma rule must be a YAML mapping.")

        missing = [key for key in ("title", "logsource", "detection") if key not in document]
        if missing:
            raise ValidationError(f"Sigma rule is missing required key(s): {', '.join(missing)}")

        detection = document["detection"]
        if not isinstance(detection, dict) or "condition" not in detection:
            raise ValidationError("The 'detection' block must be a mapping containing 'condition'.")
        if len(detection) < 2:
            raise ValidationError("The 'detection' block needs at least one search identifier.")

        level = document.get("level", "medium")
        if level not in {"critical", "high", "medium", "low", "informational"}:
            raise ValidationError(f"'{level}' is not a valid Sigma level.")

        return document

    # ── persistence ──────────────────────────────────────────────────

    async def save(
        self, draft: SigmaDraft, *, author: str, source_incident_id: str | None = None
    ) -> SigmaRule:
        self.validate(draft.yaml_body)
        rule = SigmaRule(
            reference=await self._next_reference(),
            rule_uuid=draft.rule_uuid,
            name=draft.title,
            description=draft.description,
            tactic=draft.tactic,
            log_source=draft.log_source,
            severity=draft.severity,
            status=RuleStatus.DRAFT.value,
            yaml_body=draft.yaml_body,
            mitre_techniques=draft.mitre_techniques,
            false_positives=draft.false_positives,
            author=author,
            ai_generated=draft.ai_generated,
            source_incident_id=source_incident_id,
        )
        self.db.add(rule)
        await self.db.flush()
        logger.info("sigma_rule_saved", rule=rule.reference, ai=draft.ai_generated)
        return rule

    async def _next_reference(self) -> str:
        count = int(await self.db.scalar(select(func.count()).select_from(SigmaRule)) or 0)
        return f"S{count + 1:03d}"

    async def get(self, rule_id: str) -> SigmaRule:
        rule = await self.db.get(SigmaRule, rule_id)
        if rule is None:
            rule = await self.db.scalar(select(SigmaRule).where(SigmaRule.reference == rule_id))
        if rule is None:
            raise NotFoundError(f"Sigma rule {rule_id} does not exist.")
        return rule

    async def list(
        self,
        *,
        search: str | None = None,
        tactic: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[SigmaRule], int]:
        statement = select(SigmaRule)
        count_statement = select(func.count()).select_from(SigmaRule)

        conditions = []
        if search:
            conditions.append(func.lower(SigmaRule.name).like(f"%{search.lower()}%"))
        if tactic:
            conditions.append(SigmaRule.tactic == tactic)
        if severity:
            conditions.append(SigmaRule.severity == severity.lower())
        if status:
            conditions.append(SigmaRule.status == status)
        for condition in conditions:
            statement = statement.where(condition)
            count_statement = count_statement.where(condition)

        total = int(await self.db.scalar(count_statement) or 0)
        rows = list(
            (
                await self.db.scalars(
                    statement.order_by(SigmaRule.created_at.desc()).limit(limit).offset(offset)
                )
            ).all()
        )
        return rows, total

    async def update_yaml(self, rule_id: str, yaml_body: str, *, actor: str) -> SigmaRule:
        rule = await self.get(rule_id)
        document = self.validate(yaml_body)
        rule.yaml_body = yaml_body
        rule.name = document.get("title", rule.name)
        rule.severity = document.get("level", rule.severity)
        rule.version += 1
        rule.author = actor
        await self.db.flush()
        return rule

    # ── backend conversion ───────────────────────────────────────────

    async def deploy(
        self, rule_id: str, backends: list[str], *, deployed_by: str
    ) -> list[RuleDeployment]:
        """Convert the rule for each backend and record the deployment.

        Conversion is always performed and stored, even when the SIEM's API is
        not configured — the analyst still gets a query they can paste, and the
        deployment row shows exactly what would be pushed.
        """
        rule = await self.get(rule_id)
        document = self.validate(rule.yaml_body)
        deployments: list[RuleDeployment] = []

        for backend in backends:
            try:
                query = convert_rule(document, backend)
                status, error = "converted", None
            except ValidationError as exc:
                query, status, error = "", "failed", exc.message

            deployment = RuleDeployment(
                rule_id=rule.id,
                backend=backend,
                converted_query=query,
                status=status,
                deployed_by=deployed_by,
                deployed_at=datetime.now(UTC) if status == "converted" else None,
                error=error,
            )
            self.db.add(deployment)
            deployments.append(deployment)

        if any(d.status == "converted" for d in deployments):
            rule.status = RuleStatus.TESTING.value
        await self.db.flush()
        logger.info("sigma_rule_deployed", rule=rule.reference, backends=backends)
        return deployments


# ── Sigma → SIEM query conversion ────────────────────────────────────

#: Sigma field name → backend field name, per backend.
_FIELD_MAPS: dict[str, dict[str, str]] = {
    "splunk": {"EventID": "EventCode", "CommandLine": "CommandLine", "Image": "Image"},
    "elastic": {
        "EventID": "winlog.event_id",
        "CommandLine": "process.command_line",
        "Image": "process.executable",
        "ParentImage": "process.parent.executable",
    },
    "sentinel": {
        "EventID": "EventID",
        "CommandLine": "CommandLine",
        "Image": "NewProcessName",
    },
}

SUPPORTED_BACKENDS = ("splunk", "elastic", "sentinel", "qradar")


def convert_rule(document: dict[str, Any], backend: str) -> str:
    """Convert a parsed Sigma document into a backend query string.

    This is a focused converter covering the field/modifier subset the platform
    generates. Rules authored elsewhere with exotic modifiers should be
    converted with pySigma before import.
    """
    backend = backend.lower()
    if backend not in SUPPORTED_BACKENDS:
        raise ValidationError(
            f"'{backend}' is not a supported backend.",
            details={"supported": list(SUPPORTED_BACKENDS)},
        )

    detection = document.get("detection", {})
    condition = str(detection.get("condition", "selection"))
    field_map = _FIELD_MAPS.get(backend, {})

    clauses: dict[str, str] = {}
    for name, block in detection.items():
        if name == "condition":
            continue
        clauses[name] = _render_block(block, backend, field_map)

    expression = condition
    for name, rendered in clauses.items():
        expression = re.sub(rf"\b{re.escape(name)}\b", f"({rendered})", expression)

    expression = expression.replace(" and not ", " AND NOT ").replace(" and ", " AND ")
    expression = expression.replace(" or ", " OR ").replace(" not ", " NOT ")

    logsource = document.get("logsource", {})
    match backend:
        case "splunk":
            index = _splunk_index(logsource)
            return f"{index} {expression}"
        case "elastic":
            return expression
        case "sentinel":
            table = _sentinel_table(logsource)
            kql = expression.replace(" AND ", " and ").replace(" OR ", " or ")
            kql = kql.replace(" NOT ", " not ").replace("=", " == ")
            return f"{table}\n| where {kql}"
        case _:  # qradar
            # Emitted as text for the analyst to run in QRadar AQL — this is
            # never executed against the platform database.
            return f"SELECT * FROM events WHERE {expression}"  # noqa: S608


def _render_block(block: Any, backend: str, field_map: dict[str, str]) -> str:
    if isinstance(block, list):
        return " OR ".join(_render_block(item, backend, field_map) for item in block)
    if not isinstance(block, dict):
        return str(block)

    parts: list[str] = []
    for raw_field, value in block.items():
        field_name, _, modifier = raw_field.partition("|")
        mapped = field_map.get(field_name, field_name)
        parts.append(_render_comparison(mapped, modifier, value, backend))
    return " AND ".join(parts)


def _render_comparison(field_name: str, modifier: str, value: Any, backend: str) -> str:
    values = value if isinstance(value, list) else [value]
    rendered = [_render_value(field_name, modifier, item, backend) for item in values]
    if len(rendered) == 1:
        return rendered[0]
    return "(" + " OR ".join(rendered) + ")"


def _render_value(field_name: str, modifier: str, value: Any, backend: str) -> str:
    text = str(value).replace('"', '\\"')
    match (backend, modifier):
        case ("splunk", "contains"):
            return f'{field_name}="*{text}*"'
        case ("splunk", "startswith"):
            return f'{field_name}="{text}*"'
        case ("splunk", "endswith"):
            return f'{field_name}="*{text}"'
        case ("splunk", _):
            return f'{field_name}="{text}"'
        case ("elastic", "contains"):
            return f"{field_name}:*{text}*"
        case ("elastic", "startswith"):
            return f"{field_name}:{text}*"
        case ("elastic", "endswith"):
            return f"{field_name}:*{text}"
        case ("elastic", _):
            return f'{field_name}:"{text}"'
        case ("sentinel", "contains"):
            return f'{field_name} contains "{text}"'
        case ("sentinel", "startswith"):
            return f'{field_name} startswith "{text}"'
        case ("sentinel", "endswith"):
            return f'{field_name} endswith "{text}"'
        case ("sentinel", _):
            return f'{field_name} =~ "{text}"'
        case _:
            return f"{field_name}='{text}'"


def _splunk_index(logsource: dict[str, Any]) -> str:
    product = logsource.get("product", "")
    service = logsource.get("service", "")
    index = {
        "windows": "index=windows",
        "linux": "index=linux",
        "aws": "index=aws sourcetype=aws:cloudtrail",
        "dns": "index=dns",
        "firewall": "index=network",
    }.get(product, "index=*")
    if service == "sysmon":
        index += " source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    return index


def _sentinel_table(logsource: dict[str, Any]) -> str:
    return {
        "windows": "SecurityEvent",
        "aws": "AWSCloudTrail",
        "azure": "SigninLogs",
        "dns": "DnsEvents",
        "firewall": "CommonSecurityLog",
    }.get(logsource.get("product", ""), "SecurityEvent")
