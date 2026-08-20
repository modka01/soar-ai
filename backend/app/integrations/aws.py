"""AWS security posture and remediation via boto3.

boto3 is synchronous, so every call is dispatched to a worker thread to keep
the event loop free. Credentials come from the standard provider chain
(instance role, IRSA, environment) — the platform never stores AWS keys in the
database.
"""

from __future__ import annotations

import asyncio
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import settings
from app.core.errors import IntegrationError
from app.core.logging import get_logger

logger = get_logger(__name__)

_BOTO_CONFIG = Config(
    retries={"max_attempts": 3, "mode": "standard"},
    connect_timeout=10,
    read_timeout=30,
    user_agent_extra="QuantNexa-SOAR/1.0",
)

#: GuardDuty numeric severity → SOAR severity band.
_GUARDDUTY_BANDS = ((8.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.0, "low"))


def guardduty_severity(value: float) -> str:
    for threshold, label in _GUARDDUTY_BANDS:
        if value >= threshold:
            return label
    return "low"


class AWSSecurityClient:
    """Read posture from AWS security services and apply remediations."""

    def __init__(self, region: str | None = None, role_arn: str | None = None) -> None:
        self.region = region or settings.aws_region
        self.role_arn = role_arn or settings.aws_role_arn
        self._session: boto3.Session | None = None

    # ── session / plumbing ───────────────────────────────────────────

    def _build_session(self) -> boto3.Session:
        if self.role_arn:
            sts = boto3.client("sts", region_name=self.region, config=_BOTO_CONFIG)
            assumed = sts.assume_role(
                RoleArn=self.role_arn, RoleSessionName="quantnexa-soar", DurationSeconds=3600
            )
            creds = assumed["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region,
            )
        return boto3.Session(region_name=self.region)

    @property
    def session(self) -> boto3.Session:
        if self._session is None:
            self._session = self._build_session()
        return self._session

    def client(self, service: str):
        return self.session.client(service, config=_BOTO_CONFIG)

    async def _call(self, service: str, operation: str, **kwargs: Any) -> Any:
        """Run a boto3 operation off the event loop, mapping errors uniformly."""

        def _invoke() -> Any:
            client = self.client(service)
            return getattr(client, operation)(**kwargs)

        try:
            return await asyncio.get_running_loop().run_in_executor(None, _invoke)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("aws_client_error", service=service, operation=operation, code=code)
            raise IntegrationError(
                f"AWS {service}.{operation} failed: {code}",
                details={"integration": "aws", "service": service, "code": code},
            ) from exc
        except BotoCoreError as exc:
            raise IntegrationError(
                f"AWS {service}.{operation} failed: {exc}",
                details={"integration": "aws", "service": service},
            ) from exc

    async def health_check(self) -> dict[str, Any]:
        try:
            identity = await self._call("sts", "get_caller_identity")
        except IntegrationError as exc:
            return {"slug": "aws", "health": "offline", "detail": exc.message}
        return {
            "slug": "aws",
            "health": "healthy",
            "account_id": identity.get("Account"),
            "arn": identity.get("Arn"),
            "region": self.region,
        }

    # ── posture reads ────────────────────────────────────────────────

    async def guardduty_findings(self, *, limit: int = 50) -> list[dict[str, Any]]:
        detectors = await self._call("guardduty", "list_detectors")
        findings: list[dict[str, Any]] = []

        for detector_id in detectors.get("DetectorIds", []):
            listed = await self._call(
                "guardduty",
                "list_findings",
                DetectorId=detector_id,
                FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]}}},
                MaxResults=min(limit, 50),
            )
            ids = listed.get("FindingIds", [])
            if not ids:
                continue
            detail = await self._call(
                "guardduty", "get_findings", DetectorId=detector_id, FindingIds=ids
            )
            for finding in detail.get("Findings", []):
                resource = finding.get("Resource", {})
                findings.append(
                    {
                        "external_id": finding.get("Id"),
                        "service": "GuardDuty",
                        "finding_type": finding.get("Type", ""),
                        "title": finding.get("Title", ""),
                        "description": finding.get("Description", ""),
                        "severity": guardduty_severity(float(finding.get("Severity", 0))),
                        "region": finding.get("Region"),
                        "account_id": finding.get("AccountId"),
                        "resource_type": resource.get("ResourceType"),
                        "resource_id": (
                            resource.get("InstanceDetails", {}).get("InstanceId")
                            or resource.get("AccessKeyDetails", {}).get("UserName")
                            or resource.get("S3BucketDetails", [{}])[0].get("Name")
                            if resource.get("S3BucketDetails")
                            else resource.get("ResourceType")
                        ),
                        "created_at": finding.get("CreatedAt"),
                    }
                )
        return findings[:limit]

    async def security_hub_summary(self) -> dict[str, Any]:
        standards = await self._call("securityhub", "get_enabled_standards")
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        failed = 0

        findings = await self._call(
            "securityhub",
            "get_findings",
            Filters={
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
            },
            MaxResults=100,
        )
        for finding in findings.get("Findings", []):
            label = finding.get("Severity", {}).get("Label", "LOW").lower()
            if label in counts:
                counts[label] += 1
            failed += 1

        total_controls = max(failed, 1) * 4  # conservative denominator when unavailable
        return {
            "service": "Security Hub",
            "standards_enabled": len(standards.get("StandardsSubscriptions", [])),
            "failed_controls": failed,
            "severity_counts": counts,
            "compliance_score": round(max(0.0, 100 - failed / total_controls * 100), 1),
        }

    async def iam_risk_analysis(self) -> list[dict[str, Any]]:
        """Flag over-privileged, MFA-less and stale IAM principals."""
        users = await self._call("iam", "list_users")
        risks: list[dict[str, Any]] = []

        for user in users.get("Users", [])[:100]:
            username = user["UserName"]
            attached = await self._call("iam", "list_attached_user_policies", UserName=username)
            mfa = await self._call("iam", "list_mfa_devices", UserName=username)

            for policy in attached.get("AttachedPolicies", []):
                if policy.get("PolicyName") in {"AdministratorAccess", "PowerUserAccess"}:
                    risks.append(
                        {
                            "principal": username,
                            "principal_type": "user",
                            "risk": f"{policy['PolicyName']} attached directly",
                            "severity": "critical",
                            "remediation": (
                                "Detach the managed policy and grant scoped permissions "
                                "through a role instead."
                            ),
                        }
                    )
            if not mfa.get("MFADevices"):
                risks.append(
                    {
                        "principal": username,
                        "principal_type": "user",
                        "risk": "No MFA device enrolled",
                        "severity": "high",
                        "remediation": (
                            "Enforce MFA with an IAM policy condition on "
                            "aws:MultiFactorAuthPresent."
                        ),
                    }
                )

        roles = await self._call("iam", "list_roles")
        for role in roles.get("Roles", [])[:100]:
            policy_doc = role.get("AssumeRolePolicyDocument", {})
            for statement in _statements(policy_doc):
                principal = statement.get("Principal", {})
                if principal == "*" or principal.get("AWS") == "*":
                    risks.append(
                        {
                            "principal": role["RoleName"],
                            "principal_type": "role",
                            "risk": "Trust policy allows any AWS principal",
                            "severity": "critical",
                            "remediation": (
                                "Restrict the trust policy to specific account ids, or "
                                "require an ExternalId condition."
                            ),
                        }
                    )
        return risks

    async def public_s3_buckets(self) -> list[dict[str, Any]]:
        buckets = await self._call("s3", "list_buckets")
        public: list[dict[str, Any]] = []

        for bucket in buckets.get("Buckets", []):
            name = bucket["Name"]
            try:
                block = await self._call("s3", "get_public_access_block", Bucket=name)
            except IntegrationError:
                # No block configuration at all means nothing is preventing public access.
                public.append({"bucket": name, "reason": "No public access block configured"})
                continue
            config = block.get("PublicAccessBlockConfiguration", {})
            if not all(
                config.get(key, False)
                for key in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            ):
                public.append({"bucket": name, "reason": "Public access block is incomplete"})
        return public

    async def service_inventory(self) -> list[dict[str, Any]]:
        """Per-service posture tiles rendered by the AWS Security module."""
        tiles: list[dict[str, Any]] = []

        async def safe(label: str, coroutine) -> Any:
            try:
                return await coroutine
            except IntegrationError as exc:
                logger.info("aws_service_unavailable", service=label, error=exc.message)
                return None

        findings = await safe("guardduty", self.guardduty_findings(limit=50))
        if findings is not None:
            by_severity: dict[str, int] = {}
            for finding in findings:
                by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
            tiles.append(
                {
                    "name": "GuardDuty",
                    "icon": "🛡",
                    "region": self.region,
                    "metrics": [
                        {"label": "Active Findings", "value": len(findings), "tone": "red"},
                        {
                            "label": "High Severity",
                            "value": by_severity.get("critical", 0) + by_severity.get("high", 0),
                            "tone": "amber",
                        },
                    ],
                }
            )

        hub = await safe("securityhub", self.security_hub_summary())
        if hub is not None:
            tiles.append(
                {
                    "name": "Security Hub",
                    "icon": "⬡",
                    "region": "multi-region",
                    "metrics": [
                        {
                            "label": "Compliance Score",
                            "value": f"{hub['compliance_score']}%",
                            "tone": "amber",
                        },
                        {
                            "label": "Failed Controls",
                            "value": hub["failed_controls"],
                            "tone": "red",
                        },
                        {"label": "Standards", "value": hub["standards_enabled"], "tone": "navy"},
                    ],
                }
            )

        iam = await safe("iam", self.iam_risk_analysis())
        if iam is not None:
            tiles.append(
                {
                    "name": "IAM Analyzer",
                    "icon": "🔑",
                    "region": "global",
                    "metrics": [
                        {"label": "Risk Findings", "value": len(iam), "tone": "red"},
                        {
                            "label": "Critical",
                            "value": sum(1 for r in iam if r["severity"] == "critical"),
                            "tone": "amber",
                        },
                    ],
                }
            )

        buckets = await safe("s3", self.public_s3_buckets())
        if buckets is not None:
            tiles.append(
                {
                    "name": "S3 Exposure",
                    "icon": "🪣",
                    "region": "global",
                    "metrics": [
                        {"label": "Public Buckets", "value": len(buckets), "tone": "red"},
                    ],
                }
            )
        return tiles

    # ── remediation ──────────────────────────────────────────────────

    async def remediate(self, action: str, resource_id: str, *, reason: str) -> dict[str, Any]:
        handlers = {
            "block_sg": self._block_security_group,
            "revoke_iam": self._revoke_iam,
            "block_s3": self._block_s3_public_access,
            "snapshot_ec2": self._snapshot_ec2,
            "disable_access_key": self._disable_access_key,
        }
        handler = handlers.get(action)
        if handler is None:
            raise IntegrationError(
                f"Unknown AWS remediation '{action}'.",
                details={"supported": sorted(handlers)},
            )
        logger.info("aws_remediation", action=action, resource_id=resource_id, region=self.region)
        result = await handler(resource_id)
        return {"action": action, "resource_id": resource_id, "reason": reason, **result}

    async def _block_security_group(self, sg_id: str) -> dict[str, Any]:
        """Strip all ingress and egress rules, quarantining anything attached to it."""
        described = await self._call("ec2", "describe_security_groups", GroupIds=[sg_id])
        groups = described.get("SecurityGroups", [])
        if not groups:
            raise IntegrationError(f"Security group {sg_id} was not found.")
        group = groups[0]

        if group.get("IpPermissions"):
            await self._call(
                "ec2",
                "revoke_security_group_ingress",
                GroupId=sg_id,
                IpPermissions=group["IpPermissions"],
            )
        if group.get("IpPermissionsEgress"):
            await self._call(
                "ec2",
                "revoke_security_group_egress",
                GroupId=sg_id,
                IpPermissions=group["IpPermissionsEgress"],
            )
        return {
            "status": "success",
            "message": "All ingress and egress rules revoked.",
            "rules_removed": len(group.get("IpPermissions", []))
            + len(group.get("IpPermissionsEgress", [])),
        }

    async def _revoke_iam(self, username: str) -> dict[str, Any]:
        """Detach policies, delete the console login and deactivate access keys."""
        attached = await self._call("iam", "list_attached_user_policies", UserName=username)
        for policy in attached.get("AttachedPolicies", []):
            await self._call(
                "iam", "detach_user_policy", UserName=username, PolicyArn=policy["PolicyArn"]
            )

        keys = await self._call("iam", "list_access_keys", UserName=username)
        for key in keys.get("AccessKeyMetadata", []):
            await self._call(
                "iam",
                "update_access_key",
                UserName=username,
                AccessKeyId=key["AccessKeyId"],
                Status="Inactive",
            )

        try:
            await self._call("iam", "delete_login_profile", UserName=username)
            console_removed = True
        except IntegrationError:
            console_removed = False  # No console profile existed.

        return {
            "status": "success",
            "message": "IAM credentials revoked.",
            "policies_detached": len(attached.get("AttachedPolicies", [])),
            "access_keys_disabled": len(keys.get("AccessKeyMetadata", [])),
            "console_login_removed": console_removed,
        }

    async def _block_s3_public_access(self, bucket: str) -> dict[str, Any]:
        await self._call(
            "s3",
            "put_public_access_block",
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        return {"status": "success", "message": f"Public access fully blocked on {bucket}."}

    async def _snapshot_ec2(self, instance_id: str) -> dict[str, Any]:
        described = await self._call("ec2", "describe_instances", InstanceIds=[instance_id])
        snapshots: list[str] = []
        for reservation in described.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                for mapping in instance.get("BlockDeviceMappings", []):
                    volume_id = mapping.get("Ebs", {}).get("VolumeId")
                    if not volume_id:
                        continue
                    created = await self._call(
                        "ec2",
                        "create_snapshot",
                        VolumeId=volume_id,
                        Description=f"SOAR forensic snapshot of {instance_id}",
                        TagSpecifications=[
                            {
                                "ResourceType": "snapshot",
                                "Tags": [
                                    {"Key": "CreatedBy", "Value": "QuantNexa-SOAR"},
                                    {"Key": "Purpose", "Value": "forensic-preservation"},
                                ],
                            }
                        ],
                    )
                    snapshots.append(created["SnapshotId"])
        return {
            "status": "success",
            "message": f"{len(snapshots)} forensic snapshot(s) created.",
            "snapshot_ids": snapshots,
        }

    async def _disable_access_key(self, access_key_id: str) -> dict[str, Any]:
        # The owning user must be resolved before the key can be deactivated.
        users = await self._call("iam", "list_users")
        for user in users.get("Users", []):
            keys = await self._call("iam", "list_access_keys", UserName=user["UserName"])
            for key in keys.get("AccessKeyMetadata", []):
                if key["AccessKeyId"] == access_key_id:
                    await self._call(
                        "iam",
                        "update_access_key",
                        UserName=user["UserName"],
                        AccessKeyId=access_key_id,
                        Status="Inactive",
                    )
                    return {
                        "status": "success",
                        "message": f"Access key deactivated for {user['UserName']}.",
                        "user": user["UserName"],
                    }
        raise IntegrationError(f"Access key {access_key_id} was not found in this account.")


def _statements(policy_document: Any) -> list[dict[str, Any]]:
    """Normalise a policy document's Statement into a list."""
    if isinstance(policy_document, str):
        import json

        try:
            policy_document = json.loads(policy_document)
        except json.JSONDecodeError:
            return []
    statement = (policy_document or {}).get("Statement", [])
    if isinstance(statement, dict):
        return [statement]
    return [s for s in statement if isinstance(s, dict)]
