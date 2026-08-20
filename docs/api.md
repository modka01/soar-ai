# API

Base path `/api/v1`. Interactive documentation is served at `/docs` in
non-production environments; it is disabled in production.

## Authentication

```bash
# Bearer token
curl -X POST https://soar.quantnexa.com/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"analyst@quantnexa.com","password":"..."}'

curl https://soar.quantnexa.com/api/v1/alerts \
  -H "authorization: Bearer $ACCESS_TOKEN"

# API key
curl https://soar.quantnexa.com/api/v1/alerts -H "x-api-key: qntx_sk_..."
```

## Error envelope

Every error shares one shape, so the console renders them uniformly:

```json
{
  "error": {
    "code": "forbidden",
    "message": "Role 'soc_l1' is missing required permission(s): approval:decide.",
    "details": {},
    "request_id": "8f3a2b1c9d4e5f60"
  }
}
```

The `request_id` also appears in the `x-request-id` response header and in every
server log line for that request.

## Pagination

List endpoints take `limit` (1–200, default 50) and `offset`, and return:

```json
{ "items": [...], "total": 284, "limit": 50, "offset": 0 }
```

## Ingesting alerts

Detection sources post to `/alerts/ingest` with an HMAC signature. There is no
user credential involved.

```python
import hmac, hashlib, json, requests

body = json.dumps({
    "title": "Suspected C2 beacon — DNS tunneling",
    "severity": "critical",
    "source": "Splunk",
    "asset": "ws-finance-04",
    "description": "847 queries per minute to a .xyz domain.",
    "indicators": ["185.220.101.47"],
    "mitre_techniques": ["T1071.004"],
}).encode()

signature = "sha256=" + hmac.new(HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()

requests.post(
    "https://soar.quantnexa.com/api/v1/alerts/ingest",
    data=body,
    headers={"content-type": "application/json", "x-signature": signature},
)
```

Alerts are deduplicated within a 15-minute window. Repeat detections increment
`duplicate_count` on the existing alert rather than creating new rows — but only
when the asset matches exactly.

## Running the agent

Creating a task and streaming it are separate calls, so a dropped connection
never loses the work:

```bash
SESSION=$(curl -sX POST .../api/v1/agent/tasks \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"task":"Investigate the critical alert queue"}' | jq -r .id)

curl -N ".../api/v1/agent/sessions/$SESSION/stream" \
  -H "authorization: Bearer $TOKEN" -H 'accept: text/event-stream'
```

Stream events: `context`, `iteration`, `plan`, `thought`, `message`,
`tool_result`, `approval_required`, `final`, `exhausted`, `stopped`, `error`,
`done`.

When `approval_required` arrives the stream ends and the session parks. Decide,
then re-attach with `?follow=true`:

```bash
curl -X POST ".../api/v1/agent/approvals/$APPROVAL_ID/decide" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"approved": true, "note": "Confirmed C2 on the host."}'
```

## Permissions

| Permission | Roles |
|---|---|
| `read` | all |
| `alert:triage` | soc_l1+ |
| `agent:run` | soc_l1+ |
| `incident:write` | soc_l2+ |
| `playbook:run` | soc_l2+ |
| `approval:decide` | soc_l3, ir_manager, admin |
| `sigma:write` | soc_l3+ |
| `sigma:deploy` | ir_manager, admin |
| `containment:execute` | ir_manager, admin |
| `settings:write` | admin |
| `user:manage` | admin |
| `audit:read` | admin |

## Endpoint summary

| Module | Endpoints |
|---|---|
| Auth | `/auth/login`, `/auth/refresh`, `/auth/me`, `/auth/password`, `/users`, `/api-keys` |
| Agent | `/agent/tasks`, `/agent/sessions`, `/agent/sessions/{id}/stream`, `/agent/approvals` |
| Alerts | `/alerts`, `/alerts/ingest`, `/alerts/{id}/triage`, `/alerts/triage/bulk`, `/alerts/{id}/escalate` |
| Incidents | `/incidents`, `/incidents/{id}`, `/incidents/{id}/events`, `/incidents/{id}/summary` |
| MCP | `/mcp/tools`, `/mcp/tools/{name}/invoke`, `/mcp/executions`, `/mcp/stats` |
| RAG | `/rag/chunks`, `/rag/retrieve`, `/rag/documents`, `/rag/stats` |
| Sigma | `/sigma/rules`, `/sigma/generate`, `/sigma/validate`, `/sigma/convert`, `/sigma/rules/{id}/deploy` |
| AWS | `/aws/overview`, `/aws/findings`, `/aws/sync`, `/aws/iam-risks`, `/aws/remediate` |
| Playbooks | `/playbooks`, `/playbooks/{id}/run`, `/playbook-runs`, `/n8n/callback` |
| Threats | `/threats/feed`, `/threats/enrich`, `/threats/stats` |
| Platform | `/dashboard`, `/integrations`, `/settings`, `/audit` |
| Health | `/health/live`, `/health/ready`, `/metrics` (unauthenticated) |
