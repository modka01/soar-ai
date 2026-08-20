"""Platform settings: namespaced key/value configuration edited from the UI.

Secrets are never returned in plaintext. A secret value is stored write-only
and read back as a masked placeholder, so the Settings screen can show that a
credential is present without ever exposing it.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.models import Setting

logger = get_logger(__name__)

MASK = "••••••••"

#: Namespaces the Settings module exposes, in navigation order.
NAMESPACES: list[dict[str, str]] = [
    {"key": "general", "label": "General", "icon": "⬡"},
    {"key": "agent", "label": "AI Agent", "icon": "✦"},
    {"key": "rag", "label": "RAG / Knowledge", "icon": "◈"},
    {"key": "mcp", "label": "MCP Config", "icon": "◎"},
    {"key": "n8n", "label": "n8n Engine", "icon": "▷"},
    {"key": "alerting", "label": "Alert Rules", "icon": "⬤"},
    {"key": "aws", "label": "AWS Config", "icon": "☁"},
    {"key": "sigma", "label": "Sigma / SIEM", "icon": "Σ"},
    {"key": "notify", "label": "Notifications", "icon": "◷"},
    {"key": "users", "label": "Users & Roles", "icon": "◑"},
    {"key": "api", "label": "API & Webhooks", "icon": "∿"},
    {"key": "retention", "label": "Retention", "icon": "◫"},
    {"key": "compliance", "label": "Compliance", "icon": "◪"},
    {"key": "audit", "label": "Audit Log", "icon": "≡"},
]

#: Keys whose values are credentials — stored write-only, never read back.
SECRET_KEYS = frozenset(
    {
        "anthropic_api_key",
        "mcp_api_key",
        "n8n_api_key",
        "aws_secret_access_key",
        "splunk_token",
        "elastic_api_key",
        "smtp_password",
        "slack_webhook_url",
        "pagerduty_key",
        "hmac_secret",
        "crowdstrike_client_secret",
        "virustotal_api_key",
        "jira_token",
    }
)


class SettingsService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def get_namespace(self, namespace: str, *, reveal: bool = False) -> dict[str, Any]:
        rows = list(
            (await self.db.scalars(select(Setting).where(Setting.namespace == namespace))).all()
        )
        return {
            row.key: (MASK if row.is_secret and not reveal else row.value.get("value"))
            for row in rows
        }

    async def get_all(self) -> dict[str, dict[str, Any]]:
        rows = list((await self.db.scalars(select(Setting))).all())
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            bucket = result.setdefault(row.namespace, {})
            bucket[row.key] = MASK if row.is_secret else row.value.get("value")
        return result

    async def set(
        self,
        namespace: str,
        key: str,
        value: Any,
        *,
        updated_by: str,
        is_secret: bool | None = None,
    ) -> Setting:
        if is_secret is None:
            is_secret = key in SECRET_KEYS

        # A masked value means "unchanged" — never overwrite a real secret with the mask.
        if is_secret and value == MASK:
            existing = await self.db.get(Setting, (namespace, key))
            if existing is not None:
                return existing

        setting = await self.db.get(Setting, (namespace, key))
        if setting is None:
            setting = Setting(namespace=namespace, key=key, is_secret=is_secret)
            self.db.add(setting)
        setting.value = {"value": value}
        setting.is_secret = is_secret
        setting.updated_by = updated_by
        await self.db.flush()
        logger.info(
            "setting_updated", namespace=namespace, key=key, secret=is_secret, by=updated_by
        )
        return setting

    async def set_namespace(
        self, namespace: str, values: dict[str, Any], *, updated_by: str
    ) -> dict[str, Any]:
        for key, value in values.items():
            await self.set(namespace, key, value, updated_by=updated_by)
        return await self.get_namespace(namespace)

    async def export(self) -> dict[str, Any]:
        """Full configuration export with every secret redacted."""
        rows = list((await self.db.scalars(select(Setting))).all())
        export: dict[str, Any] = {}
        for row in rows:
            bucket = export.setdefault(row.namespace, {})
            bucket[row.key] = "***redacted***" if row.is_secret else row.value.get("value")
        return {"namespaces": NAMESPACES, "settings": export}
