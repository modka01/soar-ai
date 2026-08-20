"""Jira issue creation for incident hand-off."""

from __future__ import annotations

import base64
from typing import Any

from app.core.config import settings
from app.integrations.base import BaseIntegration

#: SOAR severity → Jira priority name.
PRIORITY_MAP = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}


class JiraClient(BaseIntegration):
    slug = "jira"
    display_name = "Jira"
    category = "ticketing"

    def __init__(self, project_key: str = "SOC") -> None:
        super().__init__(base_url=settings.jira_url or "")
        self.user = settings.jira_user
        self.token = settings.jira_token
        self.project_key = project_key

    def default_headers(self) -> dict[str, str]:
        headers = super().default_headers()
        headers["content-type"] = "application/json"
        if self.user and self.token:
            basic = base64.b64encode(f"{self.user}:{self.token}".encode()).decode()
            headers["authorization"] = f"Basic {basic}"
        return headers

    def is_configured(self) -> bool:
        return bool(self.base_url and self.user and self.token)

    async def ping(self) -> None:
        await self.request("GET", "/rest/api/3/myself")

    async def create_issue(
        self,
        *,
        summary: str,
        description: str,
        severity: str,
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary[:250],
                "issuetype": {"name": "Incident"},
                "priority": {"name": PRIORITY_MAP.get(severity, "Medium")},
                "labels": labels or ["soar"],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description[:30000]}],
                        }
                    ],
                },
            }
        }
        result = await self.request("POST", "/rest/api/3/issue", json=payload)
        key = result.get("key", "")
        return {
            "ticket_id": key,
            "url": f"{self.base_url}/browse/{key}" if key else None,
            "status": "open",
            "platform": "Jira",
        }
