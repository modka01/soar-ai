#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Run database migrations out of band.
#
# The chart applies migrations automatically as a pre-upgrade hook, so this
# is for the exceptions: a long backfill you want to run before the deploy
# window, or re-running the seeder after a restore.
#
#   ./deploy/scripts/migrate.sh <environment> [--seed-only]
# ─────────────────────────────────────────────────────────────
set -euo pipefail

ENVIRONMENT="${1:-}"
MODE="${2:-migrate}"
RELEASE="${RELEASE:-soar-ai}"
NAMESPACE="${NAMESPACE:-soar-${ENVIRONMENT}}"
TIMEOUT="${TIMEOUT:-900}"

GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
step() { printf '\n%s▸ %s%s\n' "$BLUE" "$1" "$RESET"; }
die()  { printf '%s  ✗ %s%s\n' "$RED" "$1" "$RESET" >&2; exit 1; }

[[ -z "$ENVIRONMENT" ]] && { sed -n '2,12p' "$0"; exit 2; }

# Reuse the running deployment's pod spec so the job gets exactly the same
# image, secrets and service account as the API.
DEPLOYMENT="${RELEASE}-backend"
kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" >/dev/null 2>&1 \
  || die "Deployment ${DEPLOYMENT} not found in ${NAMESPACE}."

JOB_NAME="${RELEASE}-migrate-manual-$(date +%s)"
COMMAND="migrate"
[[ "$MODE" == "--seed-only" ]] && COMMAND="python -m app.workers.bootstrap"

step "Creating job ${JOB_NAME}"
kubectl create job "$JOB_NAME" \
  --namespace "$NAMESPACE" \
  --from="deployment/${DEPLOYMENT}" \
  || die "Could not create the migration job."

# create --from copies the deployment's args, which start the API server;
# override them so the job runs migrations and exits.
kubectl patch job "$JOB_NAME" -n "$NAMESPACE" --type=json -p "$(cat <<PATCH
[
  {"op": "replace", "path": "/spec/template/spec/containers/0/args", "value": ["${COMMAND}"]},
  {"op": "replace", "path": "/spec/template/spec/restartPolicy", "value": "Never"},
  {"op": "remove", "path": "/spec/template/spec/containers/0/livenessProbe"},
  {"op": "remove", "path": "/spec/template/spec/containers/0/readinessProbe"},
  {"op": "remove", "path": "/spec/template/spec/containers/0/startupProbe"}
]
PATCH
)" 2>/dev/null || die "Could not patch the job spec."

step "Waiting for completion"
if kubectl wait --for=condition=complete "job/${JOB_NAME}" -n "$NAMESPACE" --timeout="${TIMEOUT}s"; then
  printf '%s  ✓ migrations applied%s\n' "$GREEN" "$RESET"
  kubectl logs "job/${JOB_NAME}" -n "$NAMESPACE" --tail=50
  kubectl delete job "$JOB_NAME" -n "$NAMESPACE" --wait=false
else
  printf '\n%sJob logs:%s\n' "$RED" "$RESET"
  kubectl logs "job/${JOB_NAME}" -n "$NAMESPACE" --tail=100 || true
  die "Migration job did not complete. The job was left in place for inspection: ${JOB_NAME}"
fi

printf '\n%s✓ Migration complete.%s\n\n' "$GREEN" "$RESET"
