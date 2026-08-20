# QuantNexa SOAR·AI Platform

Production implementation of the QuantNexa security orchestration, automation and
response console — an agentic SOC platform with RAG-grounded analysis, an audited
MCP tool layer, and human approval gates in front of every destructive action.

```
┌──────────────┐    ┌─────────────────┐    ┌──────────────────┐
│  Detection   │───▶│  Alert pipeline │───▶│    Incidents     │
│ SIEM/EDR/AWS │    │ dedup + scoring │    │   correlation    │
└──────────────┘    └─────────────────┘    └────────┬─────────┘
                                                    │
                    ┌───────────────────────────────▼─────────┐
                    │            Agentic loop                 │
                    │  analyse → plan → tools → observe → act │
                    │  RAG context · approval gate · audit    │
                    └──────┬──────────────────────┬───────────┘
                           │                      │
                  ┌────────▼────────┐   ┌─────────▼─────────┐
                  │   MCP tools     │   │  n8n playbooks    │
                  │ SIEM · EDR · FW │   │ multi-step response│
                  │ cloud · tickets │   └───────────────────┘
                  └─────────────────┘
```

## What is here

| Path | Contents |
|---|---|
| `backend/` | FastAPI services — agent loop, RAG, MCP registry, integrations, API |
| `frontend/` | React + TypeScript operator console (12 modules) |
| `deploy/helm/` | Helm chart with HPA, PDB, network policies, TLS, migration hook |
| `deploy/scripts/` | Preflight, deploy, rollback and migration scripts |
| `deploy/docker/` | Local development stack |
| `.github/workflows/` | CI for each component, security scanning, CD to staging and production |
| `docs/` | Architecture, operations and security notes |

## Modules

**Agent Console** — assign a security task and watch the loop work: retrieved
knowledge, its plan, each tool call and result, and an inline approval gate
before anything destructive runs. Streamed over SSE, resumable across restarts.

**Dashboard** · **Incidents** · **Alert Queue** — live operational metrics,
case timelines with AI summaries, and a triage queue with AI risk scoring.

**RAG Knowledge** — MITRE ATT&CK, CVE, IR playbook and detection-engineering
context, chunked and embedded. Retrieval is testable from the UI, so you can see
exactly what the agent will be told.

**MCP Tools** — ten audited capabilities across SIEM, EDR, firewall, cloud,
ticketing and vulnerability management. Every call is recorded with its
parameters, result, duration and whether it was a dry run.

**Sigma Builder** — AI rule generation with validation and conversion to Splunk
SPL, Elastic, Sentinel KQL and QRadar AQL.

**AWS Security** · **Playbooks** · **n8n Workflows** · **Threat Intel** ·
**Settings** — cloud posture with guarded remediation, multi-step response
through n8n, IOC enrichment, and 14 namespaces of platform configuration with an
append-only audit log.

## Safety model

The platform is built so that a wrong AI decision cannot quietly damage your
estate:

1. **Dry run by default.** `SOAR_ALLOW_DESTRUCTIVE_ACTIONS` is `false` out of
   the box. Every mutating tool reports what it *would* do and changes nothing.
2. **Approval gates.** High and critical-risk tools (`isolate_host`, `block_ip`,
   `aws_remediate`, `run_playbook`) park the loop until a human with the
   `approval:decide` permission approves. The registry enforces this even when
   the model forgets to ask.
3. **Guard rails in the tools themselves.** `block_ip` refuses non-routable
   ranges and anything broader than a /24 without an explicit override.
4. **No fabrication.** An unconfigured integration reports that it is
   unconfigured. The platform never invents enrichment results.
5. **Everything is audited.** Append-only, with the actor, the request id and
   the parameters — credentials redacted.

## Quick start

```bash
cp .env.example .env          # fill in SOAR_SECRET_KEY and SOAR_ANTHROPIC_API_KEY
docker compose -f deploy/docker/docker-compose.yml up -d
```

Console at http://localhost:8080, API docs at http://localhost:8000/docs.

Set `SOAR_BOOTSTRAP_ADMIN_PASSWORD` before the first start to create the initial
administrator; without it the platform starts with no users rather than shipping
a default credential.

### Developing

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
alembic upgrade head
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev                   # proxies /api to localhost:8000
```

## Building

Each component builds itself, gated on its own quality checks:

```bash
./backend/scripts/build.sh              # lint, typecheck, test, migration check
./backend/scripts/build.sh --image      # plus the container image
./frontend/scripts/build.sh --image --push
```

## Deploying

```bash
./deploy/scripts/preflight.sh production            # verify before touching anything
./deploy/scripts/deploy.sh production --tag 4f2a1b9 # deploy a pinned image
./deploy/scripts/deploy.sh production --tag 4f2a1b9 --dry-run
./deploy/scripts/rollback.sh production             # back to the previous revision
```

`deploy.sh` runs preflight, renders and diffs, applies with `--atomic`, verifies
each rollout, health-checks through the service, and rolls back automatically if
anything fails. Production requires a pinned image tag — `latest` makes a
rollback ambiguous.

See [`docs/deployment.md`](docs/deployment.md) for cluster prerequisites,
secret management and the upgrade runbook.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — how the pieces fit together
- [`docs/deployment.md`](docs/deployment.md) — cluster setup and the deploy runbook
- [`docs/security.md`](docs/security.md) — threat model and hardening
- [`docs/api.md`](docs/api.md) — API surface and integration points

## Licence

Proprietary — © QuantNexa Technologies.
