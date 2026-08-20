# Architecture

## Shape of the system

Three deployable units share one image for the Python side:

- **API** (`entrypoint api`) — FastAPI under gunicorn/uvicorn. Serves the REST
  surface and the agent's SSE stream. Horizontally scaled.
- **Worker** (`entrypoint worker`) — the maintenance scheduler: integration
  health probing, approval expiry, cloud finding sync, retention. Exactly one
  replica.
- **Migration job** (`entrypoint migrate`) — a Helm pre-upgrade hook that applies
  Alembic migrations and seeds baseline content before any new pod serves traffic.

The console is a static React bundle served by nginx, which also proxies `/api`
to the backend service so the browser only ever talks to one origin.

## Request path

```
browser → ingress (TLS) → nginx (SPA + proxy) → API pods → PostgreSQL / Redis
                                                     │
                                                     ├─→ Anthropic (agent)
                                                     ├─→ SIEM / EDR / firewall
                                                     ├─→ AWS security services
                                                     └─→ n8n (playbooks)
```

## The agentic loop

`app/services/agent.py` owns one operator task from start to finish:

1. **Retrieve.** The task is embedded and matched against the knowledge base;
   the top chunks are injected into the system prompt.
2. **Plan.** The model returns a JSON object with its reasoning, an ordered plan,
   the tool calls it wants, and a status message for the operator.
3. **Gate.** If any requested tool is high or critical risk, the loop creates an
   approval request and **returns** — the session parks in
   `awaiting_approval` until a human decides. This check runs against the tool
   registry, not only the model's `needs_approval` flag, so a model that forgets
   to ask is still gated.
4. **Execute.** Approved (or read-only) tools run through the registry, which
   records every invocation with redacted parameters, the result, duration and
   dry-run status.
5. **Observe.** Results are fed back as the next user turn, and the loop
   continues until the model sets `final_answer` or the iteration cap is hit.

Every step is persisted. A pod restart mid-run loses the stream, not the work:
the transcript, plan cursor and tool executions are all in the database, and the
session can be resumed.

Progress is published to an event bus (Redis pub/sub, with an in-process
fallback) so an operator connected to replica B sees events produced by replica A.

## RAG

`app/services/rag.py`. Documents are split on sentence boundaries into
overlapping chunks, embedded, and stored. Retrieval combines cosine similarity
with a lexical bonus, so an exact identifier — `CVE-2024-3400`, `T1021.002`, a
file hash — reliably surfaces even under a weak embedding provider.

Embedding providers are pluggable. The default `hashing` provider is a
deterministic in-process projection requiring no external service, which keeps
the platform fully functional in an air-gapped SOC. Connected deployments should
use `voyage` or `openai` for semantic quality.

## MCP tool layer

`app/services/mcp/`. Each tool declares its schema, category, risk level and
whether it mutates state. The registry sits in front of every invocation and
applies two rails:

- **Approval** — `RiskLevel.HIGH` and `CRITICAL` require a human decision.
- **Dry run** — when `allow_destructive_actions` is false, mutating tools
  describe their intent and change nothing.

Tools talk to real integrations when credentials exist and report
`not_configured` when they do not. A SOC console that fabricates enrichment is
worse than one that admits it cannot reach VirusTotal.

## Data model

`app/db/models/`. The notable shapes:

- `Alert` carries a `dedup_key` that collapses numeric variance in the *title*
  only — two hosts with the same alert stay two alerts, because folding them
  would hide a second compromised machine behind the first one's ticket.
- `Incident` correlates alerts by asset within a short window, with a full
  response timeline in `IncidentEvent`.
- `AgentSession` / `AgentMessage` / `ToolExecution` / `ApprovalRequest` make the
  loop resumable and fully auditable.
- `AuditLog` is append-only. Retention archives it; nothing in the platform
  deletes it.

`ensure_utc()` in `app/db/base.py` normalises datetimes read back from drivers
that drop the timezone, so a stored timestamp can always be compared against
`now()`.

## Frontend

Vite + React + TypeScript. Each of the twelve modules is a lazily-loaded route,
so an analyst who only opens the Agent Console never downloads the Sigma editor.

State splits three ways:
- **Server state** — react-query, with a retry policy that never retries an auth
  or permission failure.
- **Session state** — a small zustand store for the authenticated principal.
- **Stream state** — the agent console's reducer in `useAgentStream.ts`, which
  is the one place that knows how each SSE event changes the view.

The design tokens in `src/styles/tokens.css` are ported verbatim from the
approved prototype, so the production console is visually identical to the design
that was signed off.
