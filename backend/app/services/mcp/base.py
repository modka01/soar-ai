"""MCP tool contract.

Every capability the agent can invoke is a :class:`MCPTool`. A tool declares
its JSON schema, its risk class, and whether it mutates the environment. The
registry enforces two rails before any tool runs:

1. **Approval** — destructive tools require a human decision.
2. **Dry run** — when ``SOAR_ALLOW_DESTRUCTIVE_ACTIONS`` is false, mutating
   tools describe what they *would* do and change nothing.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


class ToolCategory(StrEnum):
    ANALYTICS = "analytics"
    INTEL = "intel"
    NETWORK = "network"
    RESPONSE = "response"
    CLOUD = "cloud"
    SECURITY = "security"


class RiskLevel(StrEnum):
    """How much damage a mistaken invocation could do."""

    READ_ONLY = "read_only"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def requires_approval(self) -> bool:
        return self in {RiskLevel.HIGH, RiskLevel.CRITICAL}


@dataclass(slots=True)
class ToolResult:
    """Uniform envelope returned by every tool."""

    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"ok": self.ok, **self.data}
        if self.error:
            payload["error"] = self.error
        if self.dry_run:
            payload["dry_run"] = True
            payload.setdefault("note", "Dry run — no change was made to any production system.")
        return payload


class MCPTool(ABC):
    """Base class for a tool exposed over MCP and to the agent loop."""

    name: str
    label: str
    description: str
    category: ToolCategory
    risk: RiskLevel = RiskLevel.READ_ONLY
    icon: str = "•"
    #: JSON-schema ``properties`` for the tool's parameters.
    parameters: dict[str, Any] = {}
    required: list[str] = []
    #: True when the tool changes state in a downstream system.
    mutating: bool = False

    @abstractmethod
    async def run(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        """Execute the tool. Implementations must honour ``dry_run``."""

    async def execute(self, params: dict[str, Any], *, dry_run: bool = False) -> ToolResult:
        """Wrapper adding timing and uniform error capture."""
        started = time.perf_counter()
        try:
            result = await self.run(params or {}, dry_run=dry_run)
        except Exception as exc:
            duration = int((time.perf_counter() - started) * 1000)
            logger.warning("tool_failed", tool=self.name, error=str(exc), duration_ms=duration)
            return ToolResult(ok=False, error=str(exc)[:500], duration_ms=duration, dry_run=dry_run)
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        result.dry_run = result.dry_run or dry_run
        return result

    def json_schema(self) -> dict[str, Any]:
        """Anthropic tool-use schema for this tool."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": self.parameters,
                "required": self.required,
            },
        }

    def describe(self) -> dict[str, Any]:
        """Registry metadata rendered by the MCP Tools module in the UI."""
        return {
            "name": self.name,
            "label": self.label,
            "description": self.description,
            "category": self.category.value,
            "risk": self.risk.value,
            "icon": self.icon,
            "mutating": self.mutating,
            "requires_approval": self.risk.requires_approval,
            "schema": {
                "type": "object",
                "properties": self.parameters,
                "required": self.required,
            },
        }
