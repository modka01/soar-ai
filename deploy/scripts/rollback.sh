#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Roll a release back to a previous revision.
#
#   ./deploy/scripts/rollback.sh <environment> [revision]
#
#   ./deploy/scripts/rollback.sh production        # previous revision
#   ./deploy/scripts/rollback.sh production 7      # a specific revision
#   ./deploy/scripts/rollback.sh production --list # show history and exit
# ─────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ENVIRONMENT="${1:-}"
TARGET="${2:-}"
RELEASE="${RELEASE:-soar-ai}"
NAMESPACE="${NAMESPACE:-soar-${ENVIRONMENT}}"
TIMEOUT="${TIMEOUT:-10m}"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
step() { printf '\n%s▸ %s%s\n' "$BLUE" "$1" "$RESET"; }
ok()   { printf '%s  ✓ %s%s\n' "$GREEN" "$1" "$RESET"; }
warn() { printf '%s  ! %s%s\n' "$YELLOW" "$1" "$RESET"; }
die()  { printf '%s  ✗ %s%s\n' "$RED" "$1" "$RESET" >&2; exit 1; }

[[ -z "$ENVIRONMENT" ]] && { sed -n '2,12p' "$0"; exit 2; }

helm status "$RELEASE" -n "$NAMESPACE" >/dev/null 2>&1 \
  || die "No release '${RELEASE}' in namespace '${NAMESPACE}'."

step "Release history"
helm history "$RELEASE" -n "$NAMESPACE" --max 15

if [[ "$TARGET" == "--list" ]]; then
  exit 0
fi

CURRENT="$(helm history "$RELEASE" -n "$NAMESPACE" --max 1 -o json \
  | grep -o '"revision":[0-9]*' | head -1 | cut -d: -f2)"

if [[ -z "$TARGET" ]]; then
  TARGET=$((CURRENT - 1))
  [[ "$TARGET" -lt 1 ]] && die "Revision ${CURRENT} is the only one; there is nothing to roll back to."
fi

step "Rollback plan"
printf '  current : revision %s\n' "$CURRENT"
printf '  target  : revision %s\n' "$TARGET"

# Rolling back production reverts live security tooling; make the operator
# type it rather than confirming with a keystroke.
if [[ "$ENVIRONMENT" == "production" && "${FORCE:-false}" != "true" ]]; then
  printf '\n%sThis rolls back PRODUCTION. Type the release name to confirm: %s' "$YELLOW" "$RESET"
  read -r CONFIRMATION
  [[ "$CONFIRMATION" == "$RELEASE" ]] || die "Confirmation did not match. Nothing was changed."
fi

step "Rolling back"
if helm rollback "$RELEASE" "$TARGET" \
  --namespace "$NAMESPACE" \
  --wait --wait-for-jobs \
  --timeout "$TIMEOUT"; then
  ok "rolled back to revision ${TARGET}"
else
  die "Rollback failed. Inspect: kubectl get pods -n ${NAMESPACE}"
fi

step "Verifying"
for component in backend frontend; do
  kubectl rollout status "deployment/${RELEASE}-${component}" -n "$NAMESPACE" --timeout="$TIMEOUT" \
    && ok "${component} healthy" \
    || warn "${component} did not report healthy"
done

printf '\n'
kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/instance=${RELEASE}"
printf '\n%s✓ Rollback complete — now at revision %s.%s\n\n' "$GREEN" "$TARGET" "$RESET"
