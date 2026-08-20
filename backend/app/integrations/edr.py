"""CrowdStrike Falcon — device lookup and network containment."""

from __future__ import annotations

import time
from typing import Any

from app.core.config import settings
from app.core.errors import IntegrationError
from app.integrations.base import BaseIntegration


class CrowdStrikeClient(BaseIntegration):
    slug = "crowdstrike"
    display_name = "CrowdStrike Falcon"
    category = "edr"

    def __init__(self) -> None:
        super().__init__(base_url=settings.crowdstrike_base_url)
        self.client_id = settings.crowdstrike_client_id
        self.client_secret = settings.crowdstrike_client_secret
        self._token: str | None = None
        self._token_expiry: float = 0.0

    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    async def _access_token(self) -> str:
        """OAuth2 client-credentials token, cached until 60s before expiry."""
        if self._token and time.time() < self._token_expiry - 60:
            return self._token

        response = await self.client.post(
            "/oauth2/token",
            data={"client_id": self.client_id, "client_secret": self.client_secret},
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        if response.status_code >= 400:
            raise IntegrationError(
                f"CrowdStrike authentication failed (HTTP {response.status_code}).",
                details={"integration": self.slug},
            )
        payload = response.json()
        self._token = payload["access_token"]
        self._token_expiry = time.time() + int(payload.get("expires_in", 1800))
        return self._token

    async def _authed(self, method: str, path: str, **kwargs: Any) -> Any:
        token = await self._access_token()
        headers = {"authorization": f"Bearer {token}", "content-type": "application/json"}
        return await self.request(method, path, headers=headers, **kwargs)

    async def ping(self) -> None:
        await self._authed("GET", "/devices/queries/devices/v1", params={"limit": 1})

    async def resolve_device_id(self, hostname: str) -> str:
        """Map a hostname to a Falcon device id. Accepts a device id directly."""
        # Falcon device ids are 32 lowercase hex characters.
        if len(hostname) == 32 and all(c in "0123456789abcdef" for c in hostname.lower()):
            return hostname

        payload = await self._authed(
            "GET",
            "/devices/queries/devices/v1",
            params={"filter": f"hostname:'{hostname}'", "limit": 1},
        )
        resources = payload.get("resources", [])
        if not resources:
            raise IntegrationError(
                f"No CrowdStrike device matches hostname '{hostname}'.",
                details={"integration": self.slug, "hostname": hostname},
            )
        return resources[0]

    async def contain_host(self, device_id: str, *, reason: str) -> dict[str, Any]:
        payload = await self._authed(
            "POST",
            "/devices/entities/devices-actions/v2",
            params={"action_name": "contain"},
            json={
                "action_parameters": [{"name": "reason", "value": reason[:200]}],
                "ids": [device_id],
            },
        )
        resources = payload.get("resources", [])
        return {
            "status": "contained",
            "device_id": device_id,
            "platform": "CrowdStrike Falcon",
            "resource": resources[0] if resources else {},
            "rollback_hint": "Use action_name=lift_containment with the same device id.",
        }

    async def lift_containment(self, device_id: str) -> dict[str, Any]:
        await self._authed(
            "POST",
            "/devices/entities/devices-actions/v2",
            params={"action_name": "lift_containment"},
            json={"ids": [device_id]},
        )
        return {"status": "released", "device_id": device_id}

    async def list_detections(self, limit: int = 50) -> list[dict[str, Any]]:
        query = await self._authed(
            "GET",
            "/detects/queries/detects/v1",
            params={"filter": "status:'new'", "limit": limit, "sort": "created_timestamp.desc"},
        )
        ids = query.get("resources", [])
        if not ids:
            return []
        details = await self._authed(
            "POST", "/detects/entities/summaries/GET/v1", json={"ids": ids}
        )
        return details.get("resources", [])
