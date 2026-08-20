"""Baseline content shipped with the platform.

Seeding is idempotent: it creates what is missing and leaves existing rows
alone, so it is safe to run on every deployment as part of the migration job.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import Role, hash_password
from app.db.models import Playbook, User
from app.services.rag import RAGService

logger = get_logger(__name__)

#: MITRE ATT&CK, cloud, detection and IR knowledge indexed into RAG at install.
KNOWLEDGE_SEED: list[dict[str, str]] = [
    {
        "external_id": "mitre-t1071",
        "title": "T1071 — Application Layer Protocol (C2)",
        "source": "MITRE ATT&CK",
        "category": "Command and Control",
        "content": (
            "Adversaries communicate with compromised systems over application layer protocols "
            "(HTTP, HTTPS, DNS, SMTP) to blend with normal traffic. DNS tunneling encodes command "
            "and control data inside query subdomains. Detection focuses on anomalous query length "
            "above 40 characters, high request frequency from a single host, and unusual top level "
            "domains such as .xyz, .top and .pw. Correlate DNS anomalies with EDR process network "
            "telemetry to identify the responsible binary. Beacon intervals with jitter between 30 "
            "and 300 seconds are a strong indicator of a commercial C2 framework."
        ),
    },
    {
        "external_id": "mitre-t1021",
        "title": "T1021.002 — SMB / Windows Admin Shares (PsExec)",
        "source": "MITRE ATT&CK",
        "category": "Lateral Movement",
        "content": (
            "Lateral movement via SMB using administrative shares ADMIN$ and C$. PsExec creates a "
            "PSEXESVC service on the remote host. Key indicators are Windows Event ID 7045 service "
            "creation where ServiceName contains PSEXESVC and ServiceFileName references ADMIN$. "
            "Also monitor Event ID 4624 network logon type 3 immediately followed by process "
            "creation. False positives come from SCCM and Ansible deployments, which should be "
            "excluded by source host rather than by service name."
        ),
    },
    {
        "external_id": "mitre-t1003",
        "title": "T1003.001 — LSASS Memory Credential Dumping",
        "source": "MITRE ATT&CK",
        "category": "Credential Access",
        "content": (
            "Credential dumping from LSASS process memory using Mimikatz, ProcDump or comsvcs.dll "
            "MiniDump. Detection relies on Sysmon Event ID 10 process access events targeting "
            "lsass.exe with GrantedAccess values of 0x1010 or 0x1410. Preventive controls are "
            "attack surface reduction rules, Windows Credential Guard, and membership of the "
            "Protected Users group for privileged accounts."
        ),
    },
    {
        "external_id": "mitre-t1486",
        "title": "T1486 — Data Encrypted for Impact (Ransomware)",
        "source": "MITRE ATT&CK",
        "category": "Impact",
        "content": (
            "Ransomware encrypts files to extort the victim. Precursor indicators are mass file "
            "renaming, shadow copy deletion via vssadmin or wmic, sustained high disk I/O, and "
            "honeypot canary file access. Containment sequence: isolate the endpoint immediately, "
            "capture a memory dump and disk snapshot before any recovery attempt, then preserve "
            "the"
            "evidence chain. Recovering before snapshotting destroys the forensic timeline."
        ),
    },
    {
        "external_id": "mitre-t1566",
        "title": "T1566.001 — Spearphishing Attachment",
        "source": "MITRE ATT&CK",
        "category": "Initial Access",
        "content": (
            "Targeted phishing carrying malicious attachments such as Office documents with macros "
            "or LNK files. Office applications spawning cmd.exe, powershell.exe or wscript.exe are "
            "high fidelity indicators. Detection: ParentImage ending in WINWORD.EXE or EXCEL.EXE "
            "with ChildImage of a scripting host. Monitor PowerShell Event ID 4104 script block "
            "logging for obfuscated macro payloads."
        ),
    },
    {
        "external_id": "mitre-t1558",
        "title": "T1558.003 — Kerberoasting",
        "source": "MITRE ATT&CK",
        "category": "Credential Access",
        "content": (
            "An attacker requests Kerberos TGS tickets for accounts with a Service Principal Name "
            "and cracks them offline. Detection: Event ID 4769 with TicketEncryptionType 0x17 "
            "(RC4)"
            "and TicketOptions 0x40810000. A high volume of 4769 events from a single source IP is "
            "suspicious. Mitigation: enforce AES encryption for all SPNs and use long random "
            "passwords on service accounts."
        ),
    },
    {
        "external_id": "aws-gd-backdoor",
        "title": "Backdoor:EC2/C&CActivity.B — GuardDuty",
        "source": "AWS GuardDuty",
        "category": "Cloud",
        "content": (
            "GuardDuty finding indicating an EC2 instance is communicating with a known command "
            "and"
            "control server. Remediation sequence: modify the security group to remove all egress, "
            "tag the instance as quarantined, capture memory and EBS snapshots for forensics, "
            "notify the response team via SNS, and create a Security Hub finding. Relevant CLI: "
            "aws ec2 modify-instance-attribute, aws ec2 create-snapshot."
        ),
    },
    {
        "external_id": "aws-iam-tor",
        "title": "UnauthorizedAccess:IAMUser/TorIPCaller — GuardDuty",
        "source": "AWS GuardDuty",
        "category": "Cloud",
        "content": (
            "Console or API access originating from a Tor exit node. Immediate actions: delete the "
            "console login profile, deactivate all access keys for the principal, and revoke "
            "active"
            "sessions by attaching a deny policy with an aws:TokenIssueTime condition. Review "
            "CloudTrail for every action taken during the session window and notify the CISO."
        ),
    },
    {
        "external_id": "aws-s3-public",
        "title": "S3 Bucket Public Access — AWS Config",
        "source": "AWS Config",
        "category": "Cloud Misconfiguration",
        "content": (
            "A public S3 bucket permits unauthenticated access to stored objects. Remediation: "
            "call"
            "put-public-access-block with BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy and "
            "RestrictPublicBuckets all set to true, then run a Macie scan to determine whether any "
            "personally identifiable information was exposed. Review both the bucket policy and "
            "the"
            "object ACLs, since either can grant public access independently."
        ),
    },
    {
        "external_id": "playbook-ransomware",
        "title": "Ransomware Response Playbook",
        "source": "IR Playbook",
        "category": "Response",
        "content": (
            "1. Isolate the endpoint at both EDR and firewall. 2. Terminate the malicious process "
            "tree. 3. Preserve a memory dump and disk snapshot before any recovery. 4. Identify "
            "patient zero from the EDR timeline. 5. Hunt for lateral movement from that host over "
            "the preceding seven days. 6. Notify legal and communications. 7. Engage the incident "
            "response retainer. 8. Work the ransom decision tree with executive leadership."
        ),
    },
    {
        "external_id": "playbook-phishing",
        "title": "Phishing Response Playbook",
        "source": "IR Playbook",
        "category": "Response",
        "content": (
            "1. Quarantine the message across all mailboxes. 2. Detonate attachments in a sandbox. "
            "3. Check URL reputation through VirusTotal and URLScan. 4. Block the sender domain at "
            "the mail gateway and web proxy. 5. Enumerate every recipient. 6. For any user who "
            "clicked: isolate the endpoint, reset credentials and force MFA re-enrollment."
        ),
    },
    {
        "external_id": "ioc-apt29",
        "title": "APT-29 / Cozy Bear Tradecraft",
        "source": "Threat Intel",
        "category": "APT",
        "content": (
            "APT-29 is attributed to the Russian SVR. Tradecraft includes spearphishing delivering "
            "BEATDROP and BOOMMIC loaders, DLL sideloading against signed binaries, and abuse of "
            "stolen VPN credentials. Command and control uses .xyz and .onion infrastructure with "
            "DNS beacon intervals of 30 to 300 seconds plus jitter. Exfiltration commonly abuses "
            "the OneDrive and Google Drive APIs to blend with sanctioned traffic."
        ),
    },
    {
        "external_id": "cve-2024-3400",
        "title": "CVE-2024-3400 — Palo Alto PAN-OS GlobalProtect RCE",
        "source": "CVE Database",
        "category": "Vulnerability",
        "content": (
            "CVSS 10.0 unauthenticated command injection in the PAN-OS GlobalProtect feature, "
            "actively exploited in the wild. Fixed in PAN-OS 10.2.9-h1, 11.0.4-h1 and 11.1.2-h3 or "
            "later. Interim mitigation is to disable GlobalProtect device telemetry. Inspect "
            "/var/log/pan/sslvpn_ngfw.log for anomalous session entries indicating exploitation."
        ),
    },
    {
        "external_id": "qn-soar-arch",
        "title": "QuantNexa SOAR·AI Platform Architecture",
        "source": "QuantNexa Platform",
        "category": "Architecture",
        "content": (
            "Event ingestion from SIEM and EDR webhooks feeds the alert pipeline, which "
            "deduplicates and risk-scores each detection. Correlated alerts open an incident case. "
            "The agentic loop plans a response, retrieves knowledge base context, and calls MCP "
            "tools; containment actions pass through a human approval gate. n8n executes "
            "multi-step"
            "playbooks. Every tool call and decision is written to the append-only audit log."
        ),
    },
    {
        "external_id": "splunk-queries",
        "title": "Splunk SPL Detection Queries",
        "source": "SIEM Docs",
        "category": "Detection",
        "content": (
            "Lateral movement: index=windows EventCode=7045 ServiceName=*PSEXE* | stats count by "
            "ComputerName. DNS tunneling: index=dns | eval qlen=len(query) | where qlen>40 | stats "
            "count by src_ip | where count>100. Ransomware file activity: index=endpoints "
            "EventCode=4663 | stats dc(Object_Name) as unique_files by host | where "
            "unique_files>500."
        ),
    },
    {
        "external_id": "crowdstrike-api",
        "title": "CrowdStrike Falcon API Reference",
        "source": "Integration Docs",
        "category": "EDR",
        "content": (
            "Host containment: POST /devices/entities/devices-actions/v2 with action_name=contain "
            "and the device id in the ids array. Resolve a device id with GET "
            "/devices/queries/devices/v1?filter=hostname:'NAME'. Manage custom indicators through "
            "POST /iocs/entities/indicators/v1. New detections: GET /detects/queries/detects/v1 "
            "with filter=status:'new'. Lift containment with action_name=lift_containment."
        ),
    },
    {
        "external_id": "sigma-convert",
        "title": "Sigma Backend Conversion",
        "source": "Sigma Docs",
        "category": "Detection",
        "content": (
            "Sigma YAML converts to Splunk SPL, Elastic EQL and Microsoft Sentinel KQL. Field "
            "names"
            "are translated through a backend field mapping; the same logical field has a "
            "different"
            "name in each product. Always test a converted rule against historical data in a "
            "development index before production deployment, and tune false positives first — an "
            "untuned rule erodes analyst trust faster than a missing one."
        ),
    },
]

#: Response playbooks available out of the box.
PLAYBOOK_SEED: list[dict] = [
    {
        "slug": "phishing-response",
        "name": "Phishing Response",
        "icon": "🎣",
        "severity": "high",
        "estimated_seconds": 120,
        "requires_approval": False,
        "description": (
            "Extract URLs and attachments, check reputation, quarantine the message across all "
            "mailboxes, block the sender domain and notify affected users."
        ),
        "steps": [
            {
                "name": "Receive email security alert",
                "kind": "trigger",
                "description": "Ingest the detection from the mail gateway.",
            },
            {
                "name": "Extract headers, URLs and attachments",
                "kind": "action",
                "tool": "query_siem",
                "description": "Pull the full message artefacts.",
            },
            {
                "name": "Check URL and attachment reputation",
                "kind": "action",
                "tool": "enrich_ioc",
                "description": "Enrich every extracted indicator.",
            },
            {
                "name": "AI analysis of message body",
                "kind": "ai",
                "description": "Assess spearphishing indicators and intent.",
            },
            {
                "name": "Quarantine message in all mailboxes",
                "kind": "action",
                "description": "Remove the message from every recipient inbox.",
            },
            {
                "name": "Block sender domain",
                "kind": "action",
                "tool": "block_ip",
                "description": "Add the sending infrastructure to the deny list.",
            },
            {
                "name": "Draft user notification",
                "kind": "ai",
                "description": "Generate the recipient advisory.",
            },
            {
                "name": "Notify affected users",
                "kind": "action",
                "description": "Send the advisory via Slack and email.",
            },
            {
                "name": "Open incident case",
                "kind": "action",
                "tool": "create_ticket",
                "description": "Record the case with all artefacts attached.",
            },
        ],
    },
    {
        "slug": "ransomware-containment",
        "name": "Ransomware Containment",
        "icon": "🔒",
        "severity": "critical",
        "estimated_seconds": 300,
        "requires_approval": True,
        "description": (
            "Isolate the endpoint, capture forensic evidence, terminate the encryption process "
            "tree, and page the incident response team."
        ),
        "steps": [
            {
                "name": "Ransomware behaviour detected",
                "kind": "trigger",
                "description": "EDR reports encryption indicators.",
            },
            {
                "name": "Isolate endpoint",
                "kind": "action",
                "tool": "isolate_host",
                "description": "Cut network access while preserving the IR channel.",
            },
            {
                "name": "Capture process tree",
                "kind": "action",
                "description": "Record the full process ancestry before termination.",
            },
            {
                "name": "Block all traffic for the asset",
                "kind": "action",
                "tool": "block_ip",
                "description": "Add a perimeter deny for the host.",
            },
            {
                "name": "Snapshot for forensics",
                "kind": "action",
                "tool": "aws_remediate",
                "description": "Preserve disk state before any recovery.",
            },
            {
                "name": "AI ransomware family analysis",
                "kind": "ai",
                "description": "Identify the variant and known decryption options.",
            },
            {
                "name": "Generate CISO incident brief",
                "kind": "ai",
                "description": "Produce the executive summary.",
            },
            {
                "name": "Page the IR team",
                "kind": "action",
                "description": "Trigger a PagerDuty critical incident.",
            },
            {
                "name": "Open incident case",
                "kind": "action",
                "tool": "create_ticket",
                "description": "Track the response to closure.",
            },
        ],
    },
    {
        "slug": "credential-stuffing",
        "name": "Credential Stuffing Response",
        "icon": "🔑",
        "severity": "high",
        "estimated_seconds": 90,
        "requires_approval": False,
        "description": (
            "Detect brute force patterns, lock the targeted accounts, force MFA re-enrollment and "
            "block the source infrastructure."
        ),
        "steps": [
            {
                "name": "Authentication anomaly detected",
                "kind": "trigger",
                "description": "Failed logon volume crosses the threshold.",
            },
            {
                "name": "Query authentication logs",
                "kind": "action",
                "tool": "query_siem",
                "description": "Establish scope and targeted accounts.",
            },
            {
                "name": "Enrich source addresses",
                "kind": "action",
                "tool": "enrich_ioc",
                "description": "Score the attacking infrastructure.",
            },
            {
                "name": "Lock targeted accounts",
                "kind": "action",
                "description": "Disable accounts pending verification.",
            },
            {
                "name": "Force MFA re-enrollment",
                "kind": "action",
                "description": "Invalidate existing MFA registrations.",
            },
            {
                "name": "Block source addresses",
                "kind": "action",
                "tool": "block_ip",
                "description": "Deny the attacking ranges at the perimeter.",
            },
            {
                "name": "Notify account owners",
                "kind": "action",
                "description": "Send AI-drafted notifications.",
            },
        ],
    },
    {
        "slug": "data-exfiltration",
        "name": "Data Exfiltration Response",
        "icon": "📤",
        "severity": "critical",
        "estimated_seconds": 180,
        "requires_approval": True,
        "description": (
            "Capture netflow, identify the exfiltration path, block egress and preserve the "
            "evidence chain for the compliance report."
        ),
        "steps": [
            {
                "name": "Exfiltration indicators detected",
                "kind": "trigger",
                "description": "Outbound volume anomaly.",
            },
            {
                "name": "Capture netflow",
                "kind": "action",
                "tool": "query_siem",
                "description": "Reconstruct the transfer.",
            },
            {
                "name": "Identify exfiltration path",
                "kind": "ai",
                "description": "Determine destination and data classification.",
            },
            {
                "name": "Block egress",
                "kind": "action",
                "tool": "block_ip",
                "description": "Cut the destination at the perimeter.",
            },
            {
                "name": "Preserve evidence chain",
                "kind": "action",
                "description": "Snapshot and hash all relevant artefacts.",
            },
            {
                "name": "Generate compliance report",
                "kind": "ai",
                "description": "Draft the regulatory notification assessment.",
            },
        ],
    },
    {
        "slug": "insider-threat",
        "name": "Insider Threat Assessment",
        "icon": "👤",
        "severity": "medium",
        "estimated_seconds": 240,
        "requires_approval": True,
        "description": (
            "Correlate DLP alerts with access logs, score the behavioural risk and escalate to the "
            "HR workflow when the threshold is exceeded."
        ),
        "steps": [
            {
                "name": "DLP alert received",
                "kind": "trigger",
                "description": "Data loss prevention signal.",
            },
            {
                "name": "Correlate DLP alerts",
                "kind": "action",
                "tool": "query_siem",
                "description": "Group related events for the principal.",
            },
            {
                "name": "Pull access logs",
                "kind": "action",
                "tool": "query_siem",
                "description": "Reconstruct the access pattern.",
            },
            {
                "name": "AI behavioural risk score",
                "kind": "ai",
                "description": "Assess deviation from the established baseline.",
            },
            {
                "name": "Escalate to HR workflow",
                "kind": "action",
                "description": "Route to HR when the risk threshold is crossed.",
            },
        ],
    },
    {
        "slug": "vuln-patch",
        "name": "Vulnerability Patch Workflow",
        "icon": "🛡",
        "severity": "medium",
        "estimated_seconds": 30,
        "requires_approval": False,
        "description": (
            "Ingest CVE data, correlate against the asset inventory, prioritise by real exposure "
            "and schedule patch windows."
        ),
        "steps": [
            {
                "name": "CVE feed update",
                "kind": "trigger",
                "description": "New advisory published.",
            },
            {
                "name": "Correlate with asset inventory",
                "kind": "action",
                "tool": "vuln_scan",
                "description": "Identify affected assets.",
            },
            {
                "name": "AI exposure prioritisation",
                "kind": "ai",
                "description": "Rank by internet exposure and asset criticality.",
            },
            {
                "name": "Create patch tickets",
                "kind": "action",
                "tool": "create_ticket",
                "description": "One ticket per owning team.",
            },
            {
                "name": "Schedule patch window",
                "kind": "action",
                "description": "Book the change window.",
            },
        ],
    },
]


async def seed_knowledge_base(db: AsyncSession, *, force: bool = False) -> int:
    """Index the baseline knowledge. Returns the number of documents written."""
    rag = RAGService(db)
    written = 0
    for entry in KNOWLEDGE_SEED:
        await rag.index_document(
            title=entry["title"],
            source=entry["source"],
            category=entry["category"],
            content=entry["content"],
            external_id=entry["external_id"],
            meta={"seeded": True},
        )
        written += 1
    logger.info("knowledge_base_seeded", documents=written)
    return written


async def seed_playbooks(db: AsyncSession) -> int:
    """Create any missing baseline playbook. Existing rows are left untouched."""
    created = 0
    for entry in PLAYBOOK_SEED:
        existing = await db.scalar(select(Playbook).where(Playbook.slug == entry["slug"]))
        if existing is not None:
            continue
        db.add(
            Playbook(
                slug=entry["slug"],
                name=entry["name"],
                description=entry["description"],
                severity=entry["severity"],
                icon=entry["icon"],
                estimated_seconds=entry["estimated_seconds"],
                requires_approval=entry["requires_approval"],
                n8n_workflow_id=entry["slug"],
                steps=entry["steps"],
            )
        )
        created += 1
    await db.flush()
    logger.info("playbooks_seeded", created=created)
    return created


async def seed_admin_user(db: AsyncSession) -> User | None:
    """Create the bootstrap admin when the platform has no users at all.

    Requires ``SOAR_BOOTSTRAP_ADMIN_PASSWORD`` — the platform never ships with a
    default credential.
    """
    user_count = int(await db.scalar(select(func.count()).select_from(User)) or 0)
    if user_count:
        return None
    if not settings.bootstrap_admin_password:
        logger.warning(
            "bootstrap_admin_skipped",
            reason="SOAR_BOOTSTRAP_ADMIN_PASSWORD is not set; create the first admin manually",
        )
        return None

    admin = User(
        email=settings.bootstrap_admin_email,
        full_name="Platform Administrator",
        hashed_password=hash_password(settings.bootstrap_admin_password),
        role=Role.ADMIN.value,
        is_active=True,
    )
    db.add(admin)
    await db.flush()
    logger.info("bootstrap_admin_created", email=admin.email)
    return admin


async def seed_all(db: AsyncSession) -> dict[str, int]:
    """Run every seeder. Safe to call repeatedly."""
    documents = await seed_knowledge_base(db)
    playbooks = await seed_playbooks(db)
    admin = await seed_admin_user(db)
    return {
        "knowledge_documents": documents,
        "playbooks_created": playbooks,
        "admin_created": 1 if admin else 0,
    }
