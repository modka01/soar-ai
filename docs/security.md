# Security

## Authentication and authorisation

Two credential types, both resolved in `app/api/deps.py`:

- **Bearer tokens** — short-lived JWTs from `POST /auth/login`, with a refresh
  token for rotation. Token type is enforced, so a refresh token cannot be
  presented where an access token is required.
- **API keys** — for detection sources and automation. Only the SHA-256 digest
  is stored; the clear-text key is shown once at creation and never again.

Roles carry fixed permission sets (`app/core/security.py`). An API key may narrow
its owner's permissions through scopes but can never widen them — a read-scoped
key on an administrator account cannot reach an admin route.

Failed logins increment a counter and lock the account after five attempts.
Login runs a password hash comparison even when the account does not exist, so
response timing does not enumerate valid addresses.

## Webhook authentication

Alert ingestion and the n8n callback are authenticated by HMAC-SHA256 signature
rather than a bearer token, so detection sources need no user credential.
Verification is constant-time. In production an unsigned request is rejected
outright.

## Guarding destructive action

Layered, because any single layer can be bypassed by a sufficiently confused
model:

1. `SOAR_ALLOW_DESTRUCTIVE_ACTIONS=false` by default — mutating tools run as dry
   runs everywhere, including production, until deliberately enabled.
2. The registry gates high and critical-risk tools on a human approval, checked
   against the tool's declared risk rather than the model's self-assessment.
3. Individual tools refuse obviously wrong input: `block_ip` rejects
   non-routable ranges and anything broader than a /24 without an explicit
   override flag.
4. Manual invocation from the MCP screen forces a dry run for any gated tool
   unless the caller holds `containment:execute`.
5. Approvals expire. An unattended request is swept by the worker rather than
   sitting open indefinitely.

## Secrets

No secret is ever written to a manifest, a values file, or a log line.

- Kubernetes: values come from a Secret referenced by `secretKeyRef`, sourced
  either from a pre-created Secret or synced by the External Secrets Operator.
  The chart **fails the render** if `secrets.create` is used with
  `config.environment=production`.
- Settings UI: secret-valued settings are stored write-only. Reading them back
  returns a mask, and saving the mask leaves the stored value untouched — so an
  operator editing an unrelated field cannot blank a credential.
- Logging: `app/core/logging.py` redacts any field whose key looks
  credential-shaped before it reaches the sink.
- Tool audit: parameters are redacted the same way before persistence.
- Config export: every secret is replaced with `***redacted***`.

## Container and cluster hardening

- Non-root (uid 10001 backend, 101 frontend), read-only root filesystem, all
  capabilities dropped, no privilege escalation, `RuntimeDefault` seccomp.
- The only writable path is a memory-backed `/tmp`, which is what gunicorn's
  worker heartbeat and nginx's temp paths need.
- Network policies restrict ingress to the console and the ingress controller,
  and egress to DNS, the datastores and HTTPS. **Link-local (169.254.169.254) is
  explicitly excluded from egress**, so a compromised pod cannot reach the cloud
  instance metadata service and steal node credentials.
- The service account mounts no API token — the workload needs no cluster access.
- AWS access uses IRSA rather than static keys.

## HTTP hardening

`app/core/middleware.py` and the nginx server block set `X-Content-Type-Options`,
`X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, HSTS in
production, and a Content-Security-Policy that allows only same-origin script
and connect, with Google Fonts as the single external origin.

Rate limiting is per-identity (API key, bearer subject, or client IP), Redis-
backed so it holds across replicas. It fails **open** when Redis is unreachable —
a Redis outage must not stop a SOC from responding to an incident.

## Output handling

Agent and tool output is model- and third-party-generated, so it is escaped
before any formatting is applied (`renderMarkdown` in `src/lib/format.ts`). The
application has exactly one `dangerouslySetInnerHTML`, and it is fed only by that
function. Both the escaping and the nesting case are covered by tests.

## Auditing

Every privileged action is written to an append-only log with the actor, action,
resource, outcome, source IP and request id. The request id propagates from the
HTTP header through every log line and into the audit record, so an incident can
be traced end to end across API, agent and worker.

## Reporting a vulnerability

Email security@quantnexa.com. Do not open a public issue.
