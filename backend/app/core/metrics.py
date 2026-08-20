"""Prometheus metrics for the security-relevant paths."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

http_requests = Counter(
    "soar_http_requests_total",
    "HTTP requests handled",
    ["method", "path", "status"],
)

http_duration = Histogram(
    "soar_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "path"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

alerts_ingested = Counter(
    "soar_alerts_ingested_total",
    "Alerts accepted by the ingestion pipeline",
    ["source", "severity", "deduplicated"],
)

tool_executions = Counter(
    "soar_tool_executions_total",
    "MCP tool invocations",
    ["tool", "status", "dry_run"],
)

tool_duration = Histogram(
    "soar_tool_duration_seconds",
    "MCP tool execution duration",
    ["tool"],
    buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)

agent_sessions = Counter(
    "soar_agent_sessions_total",
    "Agent sessions by terminal status",
    ["status"],
)

agent_tokens = Counter(
    "soar_agent_tokens_total",
    "Tokens consumed by the agent",
    ["direction"],
)

approvals_pending = Gauge(
    "soar_approvals_pending",
    "Containment approvals awaiting a human decision",
)

integration_health = Gauge(
    "soar_integration_health",
    "Integration health (1 healthy, 0.5 degraded, 0 offline)",
    ["integration"],
)
