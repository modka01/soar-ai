# Deployment

## Prerequisites

- Kubernetes 1.27+ with an ingress controller and cert-manager
- PostgreSQL 15+ and Redis 7+ (managed instances; the chart does not run them)
- Helm 3.14+, kubectl
- A container registry the cluster can pull from
- Optional but recommended: the External Secrets Operator, and Prometheus with
  the Prometheus Operator CRDs for the ServiceMonitor

## Secrets

The API will not start without `secret-key`, `webhook-hmac-secret`,
`database-url` and `redis-url`. Everything else is optional and simply leaves the
corresponding integration unconfigured.

### Option 1 — External Secrets (recommended)

Store the keys in your vault under `soar-ai/production/<key>` and enable syncing:

```yaml
externalSecrets:
  enabled: true
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  remoteKeyPrefix: soar-ai/production
```

### Option 2 — a pre-created Secret

```bash
kubectl create namespace soar-production

kubectl create secret generic soar-ai-secrets \
  --namespace soar-production \
  --from-literal=secret-key="$(openssl rand -hex 32)" \
  --from-literal=webhook-hmac-secret="$(openssl rand -hex 32)" \
  --from-literal=database-url='postgresql+asyncpg://user:pass@host:5432/soar' \
  --from-literal=redis-url='redis://host:6379/0' \
  --from-literal=anthropic-api-key='sk-ant-...'
```

Then set `secrets.existingSecret: soar-ai-secrets`.

`secrets.create` exists only for throwaway environments — the chart refuses to
render if it is used with `config.environment=production`.

## First deployment

```bash
./deploy/scripts/preflight.sh production
./deploy/scripts/deploy.sh production --tag 4f2a1b9 --dry-run   # review
./deploy/scripts/deploy.sh production --tag 4f2a1b9
```

`deploy.sh` will:

1. Run preflight (tooling, cluster, secrets, chart, image pinning, release state)
2. Create the namespace with the `restricted` pod-security profile if needed
3. Render, and diff against the live release when `helm-diff` is installed
4. Apply with `--atomic --wait --wait-for-jobs`
5. Verify each rollout, then health-check through the service
6. Roll back automatically if any step fails

Production requires `--tag`. A `latest` tag makes a rollback ambiguous — you
cannot say which build you are returning to.

## Bootstrap the first administrator

The platform ships with no default credential. Set
`SOAR_BOOTSTRAP_ADMIN_PASSWORD` in the secret before the first migration job
runs; the seeder creates the admin only when the user table is empty. Rotate the
password immediately after the first sign-in and remove the key from the vault.

## Upgrades

```bash
./deploy/scripts/deploy.sh production --tag <new-sha>
```

The migration job runs as a `pre-upgrade` hook, so the schema is applied before
any new pod serves traffic. Rollouts use `maxUnavailable: 0`, so capacity never
dips during a deploy.

For a long backfill you want to run ahead of the deploy window:

```bash
./deploy/scripts/migrate.sh production
```

## Rollback

```bash
./deploy/scripts/rollback.sh production --list   # see the history
./deploy/scripts/rollback.sh production          # previous revision
./deploy/scripts/rollback.sh production 7        # a specific revision
```

Production rollback asks you to type the release name to confirm. Set
`FORCE=true` only in automation (the CD pipeline does this for its post-deploy
smoke-test failure path).

**Schema note:** Helm rolls back manifests, not data. A rollback across a
destructive migration needs a database restore too — write migrations to be
backward compatible for at least one release, so the previous version can still
run against the new schema.

## Enabling destructive actions

The platform deploys with containment in dry-run mode. Before turning it on:

1. Run staging with `allowDestructiveActions: false` and confirm the agent's
   proposals are the ones you would have made.
2. Exercise the approval workflow end to end — check the gate appears, the
   decision is audited, and rejection makes the agent find another path.
3. Confirm every integration credential is scoped to least privilege. The
   firewall credential should be able to add to the SOAR block group and nothing
   else.
4. Then, deliberately:

```bash
helm upgrade soar-ai deploy/helm/soar-ai \
  -f deploy/helm/soar-ai/values-production.yaml \
  --set config.safety.allowDestructiveActions=true \
  --reuse-values
```

Leave `requireApprovalForContainment: true`. Turning both off means the agent can
isolate a host with no human in the loop.

## Scaling

The backend autoscales on CPU and memory, 4–20 replicas in production. The
scale-down window is deliberately long (5 minutes) so an agent session in flight
finishes on the pod that started it rather than being evicted mid-investigation.

The worker is intentionally a single replica with a `Recreate` strategy — its
tasks are idempotent, but a second scheduler would double every health probe and
cloud sync for no benefit.

## Observability

Prometheus scrapes `/metrics` on the backend. Useful series:

| Metric | Meaning |
|---|---|
| `soar_http_requests_total` | Request volume by route and status |
| `soar_http_request_duration_seconds` | Latency histogram |
| `soar_tool_executions_total` | Tool calls by tool, status and dry-run |
| `soar_agent_sessions_total` | Agent sessions by terminal status |
| `soar_approvals_pending` | **Alert on this** — approvals waiting on a human |
| `soar_integration_health` | 1 healthy, 0.5 degraded, 0 offline |

`soar_approvals_pending` staying above zero means the agent is blocked waiting
for a decision that nobody is making — worth paging on during an incident.

## Troubleshooting

**Pods crash-loop on start.** Check the secret has all four required keys:
`kubectl get secret soar-ai-secrets -o jsonpath='{.data}' | jq keys`.

**Migration job fails.** `kubectl logs job/soar-ai-migrate-<revision>`. The job
retries up to `migrations.backoffLimit`; a persistent failure usually means the
database user lacks DDL permission.

**The agent stream shows nothing.** Buffering. Confirm the ingress has
`nginx.ingress.kubernetes.io/proxy-buffering: "off"` and that any proxy in front
of it is not buffering the response either.

**Integrations all show offline.** Network policy egress. The backend needs 443
outbound; check `networkPolicy.allowedEgressPorts` and that DNS is reachable.
