"""n8n workflow engine — trigger workflows and read execution state."""

from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.core.errors import IntegrationError
from app.integrations.base import BaseIntegration


class N8NClient(BaseIntegration):
    slug = "n8n"
    display_name = "n8n Workflow Engine"
    category = "orchestration"

    def __init__(self) -> None:
        super().__init__(base_url=settings.n8n_url)
        self.api_key = settings.n8n_api_key

    def default_headers(self) -> dict[str, str]:
        headers = super().default_headers()
        headers["content-type"] = "application/json"
        if self.api_key:
            headers["x-n8n-api-key"] = self.api_key
        return headers

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    async def ping(self) -> None:
        await self.request("GET", "/api/v1/workflows", params={"limit": 1})

    async def list_workflows(self, *, active_only: bool = False) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": 100}
        if active_only:
            params["active"] = "true"
        payload = await self.request("GET", "/api/v1/workflows", params=params)
        return [
            {
                "id": w.get("id"),
                "name": w.get("name"),
                "active": bool(w.get("active")),
                "tags": [t.get("name") for t in w.get("tags", [])],
                "updated_at": w.get("updatedAt"),
                "nodes": [
                    {"name": n.get("name"), "type": n.get("type"), "position": n.get("position")}
                    for n in w.get("nodes", [])
                ],
            }
            for w in payload.get("data", [])
        ]

    async def get_workflow(self, workflow_id: str) -> dict[str, Any]:
        return await self.request("GET", f"/api/v1/workflows/{workflow_id}")

    async def trigger_workflow(
        self, workflow_ref: str, *, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Fire a workflow through its webhook path.

        ``workflow_ref`` is the webhook path configured on the workflow's
        trigger node (the playbook's ``n8n_workflow_id``).
        """
        self.require_configured()
        response = await self.client.post(
            f"/webhook/{workflow_ref.lstrip('/')}",
            json=payload or {},
            headers={"content-type": "application/json"},
        )
        if response.status_code >= 400:
            raise IntegrationError(
                f"n8n workflow '{workflow_ref}' returned HTTP {response.status_code}.",
                details={"integration": self.slug, "body": response.text[:300]},
            )
        try:
            body = response.json()
        except ValueError:
            body = {"raw": response.text[:500]}
        return {
            "workflow": workflow_ref,
            "status": "triggered",
            "execution_id": body.get("executionId") if isinstance(body, dict) else None,
            "response": body,
        }

    async def list_executions(
        self, *, workflow_id: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit}
        if workflow_id:
            params["workflowId"] = workflow_id
        payload = await self.request("GET", "/api/v1/executions", params=params)
        return [
            {
                "id": e.get("id"),
                "workflow_id": e.get("workflowId"),
                "status": "success" if e.get("finished") else (e.get("status") or "running"),
                "started_at": e.get("startedAt"),
                "stopped_at": e.get("stoppedAt"),
                "mode": e.get("mode"),
            }
            for e in payload.get("data", [])
        ]
