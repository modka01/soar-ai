"""Threat-intelligence providers: VirusTotal, AbuseIPDB, AlienVault OTX, MISP."""

from __future__ import annotations

import base64
from typing import Any

from app.core.config import settings
from app.integrations.base import BaseIntegration


class VirusTotalClient(BaseIntegration):
    slug = "virustotal"
    display_name = "VirusTotal"
    category = "threat_intel"

    def __init__(self) -> None:
        super().__init__(base_url="https://www.virustotal.com/api/v3")
        self.api_key = settings.virustotal_api_key

    def default_headers(self) -> dict[str, str]:
        headers = super().default_headers()
        if self.api_key:
            headers["x-apikey"] = self.api_key
        return headers

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def ping(self) -> None:
        await self.request("GET", "/ip_addresses/8.8.8.8")

    async def lookup(self, ioc: str, ioc_type: str) -> dict[str, Any]:
        path = {
            "ip": f"/ip_addresses/{ioc}",
            "domain": f"/domains/{ioc}",
            "hash": f"/files/{ioc}",
            "url": f"/urls/{base64.urlsafe_b64encode(ioc.encode()).decode().rstrip('=')}",
        }.get(ioc_type)
        if path is None:
            return {"supported": False, "reason": f"VirusTotal has no lookup for '{ioc_type}'."}

        payload = await self.request("GET", path)
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        total = sum(int(v) for v in stats.values()) or 0
        return {
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "total_engines": total,
            "reputation": attributes.get("reputation"),
            "tags": attributes.get("tags", [])[:10],
            "last_analysis_date": attributes.get("last_analysis_date"),
        }


class AbuseIPDBClient(BaseIntegration):
    slug = "abuseipdb"
    display_name = "AbuseIPDB"
    category = "threat_intel"

    def __init__(self) -> None:
        super().__init__(base_url="https://api.abuseipdb.com/api/v2")
        self.api_key = settings.abuseipdb_api_key

    def default_headers(self) -> dict[str, str]:
        headers = super().default_headers()
        if self.api_key:
            headers["key"] = self.api_key
        return headers

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def ping(self) -> None:
        await self.request("GET", "/check", params={"ipAddress": "8.8.8.8"})

    async def lookup(self, ioc: str, ioc_type: str) -> dict[str, Any]:
        if ioc_type != "ip":
            return {"supported": False, "reason": "AbuseIPDB only scores IP addresses."}
        payload = await self.request(
            "GET", "/check", params={"ipAddress": ioc, "maxAgeInDays": 90, "verbose": ""}
        )
        data = payload.get("data", {})
        return {
            "abuse_confidence_score": int(data.get("abuseConfidenceScore", 0)),
            "total_reports": int(data.get("totalReports", 0)),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "is_tor": bool(data.get("isTor", False)),
            "last_reported_at": data.get("lastReportedAt"),
        }


class OTXClient(BaseIntegration):
    slug = "otx"
    display_name = "AlienVault OTX"
    category = "threat_intel"

    def __init__(self) -> None:
        super().__init__(base_url="https://otx.alienvault.com/api/v1")
        self.api_key = settings.otx_api_key

    def default_headers(self) -> dict[str, str]:
        headers = super().default_headers()
        if self.api_key:
            headers["x-otx-api-key"] = self.api_key
        return headers

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def ping(self) -> None:
        await self.request("GET", "/user/me")

    async def lookup(self, ioc: str, ioc_type: str) -> dict[str, Any]:
        section = {
            "ip": "IPv4",
            "domain": "domain",
            "hash": "file",
            "url": "url",
        }.get(ioc_type)
        if section is None:
            return {"supported": False, "reason": f"OTX has no indicator type '{ioc_type}'."}

        payload = await self.request("GET", f"/indicators/{section}/{ioc}/general")
        pulse_info = payload.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        return {
            "pulse_count": int(pulse_info.get("count", 0)),
            "pulse_names": [p.get("name") for p in pulses[:5]],
            "threat_actors": sorted(
                {actor for p in pulses for actor in (p.get("adversary"),) if actor}
            ),
            "malware_families": sorted(
                {fam.get("display_name") for p in pulses for fam in p.get("malware_families", [])}
                - {None}
            )[:10],
            "reputation": payload.get("reputation"),
        }

    async def search_pulses(self, query: str) -> dict[str, Any]:
        payload = await self.request("GET", "/search/pulses", params={"q": query, "limit": 10})
        results = payload.get("results", [])
        techniques = {
            tag
            for pulse in results
            for tag in pulse.get("tags", [])
            if tag.upper().startswith("T1")
        }
        return {
            "match_count": int(payload.get("count", 0)),
            "threat_actors": sorted({p["adversary"] for p in results if p.get("adversary")}),
            "mitre_techniques": sorted(techniques),
            "pulses": [
                {"name": p.get("name"), "created": p.get("created"), "tags": p.get("tags", [])[:6]}
                for p in results[:5]
            ],
        }


class MISPClient(BaseIntegration):
    slug = "misp"
    display_name = "MISP"
    category = "threat_intel"

    def __init__(self) -> None:
        super().__init__(base_url=settings.misp_url or "")
        self.api_key = settings.misp_api_key

    def default_headers(self) -> dict[str, str]:
        headers = super().default_headers()
        headers["content-type"] = "application/json"
        if self.api_key:
            headers["authorization"] = self.api_key
        return headers

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    async def ping(self) -> None:
        await self.request("GET", "/servers/getVersion")

    async def search(self, query: str) -> dict[str, Any]:
        payload = await self.request(
            "POST",
            "/attributes/restSearch",
            json={"value": query, "limit": 50, "includeEventTags": True},
        )
        attributes = payload.get("response", {}).get("Attribute", [])
        tags = {tag.get("name", "") for attribute in attributes for tag in attribute.get("Tag", [])}
        return {
            "attribute_count": len(attributes),
            "threat_actors": sorted(
                {
                    tag.split('="')[-1].rstrip('"')
                    for tag in tags
                    if "threat-actor" in tag or "intrusion-set" in tag
                }
            ),
            "mitre_techniques": sorted(
                {
                    part.split(" ")[0].upper()
                    for tag in tags
                    if "attack-pattern" in tag
                    for part in (tag.split("=")[-1].strip('"'),)
                    if part.upper().startswith("T1")
                }
            ),
            "categories": sorted({a.get("category", "") for a in attributes} - {""}),
        }
