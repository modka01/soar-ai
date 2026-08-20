"""Palo Alto NGFW — dynamic address-group blocking via the XML API."""

from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.integrations.base import BaseIntegration

#: Address group the firewall policy denies. Created once by the platform installer.
BLOCK_GROUP = "SOAR-BLOCKLIST"


class PaloAltoClient(BaseIntegration):
    slug = "paloalto"
    display_name = "Palo Alto NGFW"
    category = "firewall"

    def __init__(self) -> None:
        super().__init__(base_url=settings.paloalto_url or "")
        self.api_key = settings.paloalto_api_key

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    async def ping(self) -> None:
        await self.request(
            "GET",
            "/api/",
            params={
                "type": "op",
                "cmd": "<show><system><info/></system></show>",
                "key": self.api_key,
            },
            expect_json=False,
        )

    async def block_address(
        self, address: str, *, reason: str, duration: str = "24h"
    ) -> dict[str, Any]:
        """Register the address in the SOAR dynamic address group.

        Uses a *dynamic* group rather than editing a policy rule so the block
        takes effect without a config commit, and can be lifted the same way.
        """
        register_xml = (
            "<uid-message><version>2.0</version><type>update</type><payload><register>"
            f'<entry ip="{address}"><tag><member>{BLOCK_GROUP}</member></tag></entry>'
            "</register></payload></uid-message>"
        )
        await self.request(
            "POST",
            "/api/",
            params={"type": "user-id", "key": self.api_key, "cmd": register_xml},
            expect_json=False,
        )
        return {
            "status": "blocked",
            "address": address,
            "platform": "Palo Alto NGFW",
            "address_group": BLOCK_GROUP,
            "duration": duration,
            "reason": reason,
            "rollback_hint": f"Unregister {address} from {BLOCK_GROUP} to lift the block.",
        }

    async def unblock_address(self, address: str) -> dict[str, Any]:
        unregister_xml = (
            "<uid-message><version>2.0</version><type>update</type><payload><unregister>"
            f'<entry ip="{address}"><tag><member>{BLOCK_GROUP}</member></tag></entry>'
            "</unregister></payload></uid-message>"
        )
        await self.request(
            "POST",
            "/api/",
            params={"type": "user-id", "key": self.api_key, "cmd": unregister_xml},
            expect_json=False,
        )
        return {"status": "unblocked", "address": address}
