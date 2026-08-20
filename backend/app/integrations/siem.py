"""SIEM search backends: Splunk and Elasticsearch."""

from __future__ import annotations

import re
from typing import Any

from app.core.config import settings
from app.integrations.base import BaseIntegration

#: Relative windows accepted by the ``time_range`` parameter.
_RANGE_RE = re.compile(r"^\s*(?:last\s+)?(\d+)\s*([smhd])\s*$", re.I)


def parse_time_range(value: str, default: str = "-24h") -> str:
    """Normalise 'last 24h' / '7d' into a Splunk-style relative modifier."""
    match = _RANGE_RE.match(value or "")
    if not match:
        return default
    amount, unit = match.groups()
    return f"-{amount}{unit.lower()}"


class SplunkClient(BaseIntegration):
    slug = "splunk"
    display_name = "Splunk"
    category = "siem"

    def __init__(self) -> None:
        super().__init__(base_url=settings.splunk_url or "")
        self.token = settings.splunk_token

    def default_headers(self) -> dict[str, str]:
        headers = super().default_headers()
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"
        return headers

    def is_configured(self) -> bool:
        return bool(self.base_url and self.token)

    async def ping(self) -> None:
        await self.request("GET", "/services/server/info", params={"output_mode": "json"})

    async def search(
        self, query: str, *, time_range: str = "last 24h", limit: int = 100
    ) -> list[dict[str, Any]]:
        """Run a blocking (oneshot) search and return the result rows."""
        search = query if query.strip().startswith("|") else f"search {query}"
        payload = await self.request(
            "POST",
            "/services/search/jobs/export",
            params={
                "search": f"{search} | head {limit}",
                "earliest_time": parse_time_range(time_range),
                "latest_time": "now",
                "output_mode": "json",
                "exec_mode": "oneshot",
            },
            expect_json=False,
        )
        rows: list[dict[str, Any]] = []
        import json

        for line in str(payload).splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "result" in record:
                rows.append(record["result"])
        return rows[:limit]


class ElasticClient(BaseIntegration):
    slug = "elastic"
    display_name = "Elasticsearch"
    category = "siem"

    def __init__(self) -> None:
        super().__init__(base_url=settings.elastic_url or "")
        self.api_key = settings.elastic_api_key

    def default_headers(self) -> dict[str, str]:
        headers = super().default_headers()
        if self.api_key:
            headers["authorization"] = f"ApiKey {self.api_key}"
        headers["content-type"] = "application/json"
        return headers

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    async def ping(self) -> None:
        await self.request("GET", "/_cluster/health")

    async def search(
        self,
        query: str,
        *,
        time_range: str = "last 24h",
        limit: int = 100,
        index: str = "logs-*",
    ) -> list[dict[str, Any]]:
        window = parse_time_range(time_range).lstrip("-")
        body = {
            "size": limit,
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query}}],
                    "filter": [{"range": {"@timestamp": {"gte": f"now-{window}", "lte": "now"}}}],
                }
            },
        }
        payload = await self.request("POST", f"/{index}/_search", json=body)
        return [hit.get("_source", {}) for hit in payload.get("hits", {}).get("hits", [])]
