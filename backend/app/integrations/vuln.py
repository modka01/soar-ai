"""Tenable.io vulnerability scanning."""

from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.integrations.base import BaseIntegration


class TenableClient(BaseIntegration):
    slug = "tenable"
    display_name = "Tenable.io"
    category = "vulnerability"

    def __init__(self) -> None:
        super().__init__(base_url="https://cloud.tenable.com")
        # Tenable authenticates with a paired access/secret key.
        self.access_key = settings.tenable_access_key
        self.secret_key = settings.tenable_secret_key

    def default_headers(self) -> dict[str, str]:
        headers = super().default_headers()
        headers["content-type"] = "application/json"
        if self.access_key and self.secret_key:
            headers["x-apikeys"] = f"accessKey={self.access_key};secretKey={self.secret_key}"
        return headers

    def is_configured(self) -> bool:
        return bool(self.access_key and self.secret_key)

    async def ping(self) -> None:
        await self.request("GET", "/scans")

    async def launch_scan(self, target: str, *, profile: str = "basic") -> dict[str, Any]:
        payload = await self.request(
            "POST",
            "/scans",
            json={
                "uuid": profile,
                "settings": {
                    "name": f"SOAR scan — {target}",
                    "text_targets": target,
                    "enabled": True,
                },
            },
        )
        scan = payload.get("scan", {})
        return {
            "scan_id": scan.get("id"),
            "target": target,
            "profile": profile,
            "status": "queued",
            "platform": "Tenable.io",
        }

    async def get_scan_results(self, scan_id: str) -> dict[str, Any]:
        payload = await self.request("GET", f"/scans/{scan_id}")
        hosts = payload.get("hosts", [])
        vulnerabilities = payload.get("vulnerabilities", [])
        return {
            "scan_id": scan_id,
            "status": payload.get("info", {}).get("status"),
            "host_count": len(hosts),
            "findings": [
                {
                    "plugin_id": v.get("plugin_id"),
                    "name": v.get("plugin_name"),
                    "severity": ["info", "low", "medium", "high", "critical"][
                        min(int(v.get("severity", 0)), 4)
                    ],
                    "count": v.get("count"),
                }
                for v in vulnerabilities[:50]
            ],
        }
