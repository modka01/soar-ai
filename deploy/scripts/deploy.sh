#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Production deployment for the whole platform.
#
#   ./deploy/scripts/deploy.sh <environment> [options]
#
#   ./deploy/scripts/deploy.sh staging
#   ./deploy/scripts/deploy.sh production --tag 4f2a1b9
#   ./deploy/scripts/deploy.sh production --tag 4f2a1b9 --dry-run
#
# Options:
#   --tag <sha>      Image tag to deploy (required for production)
#   --dry-run        Render and diff without applying
#   --skip-preflight Skip the preflight checks (not for production)
#   --timeout <dur>  Rollout timeout, default 10m
#   --no-wait        Return without waiting for the rollout
#
# On any failure after the apply, the release is rolled back to the
# previous revision automatically.
# ─────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ENVIRONMENT="${1:-}"
shift || true

if [[ -z "$ENVIRONMENT" ]]; then
  sed -n '2,20p' "$0"
  exit 2
fi

CHART_DIR="deploy/helm/soar-ai"
RELEASE="${RELEASE:-soar-ai}"
NAMESPACE="${NAMESPACE:-soar-${ENVIRONMENT}}"
IMAGE_TAG="${IMAGE_TAG:-}"
TIMEOUT="10m"
DRY_RUN=false
SKIP_PREFLIGHT=false
WAIT=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) IMAGE_TAG="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --skip-preflight) SKIP_PREFLIGHT=true; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --no-wait) WAIT=false; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
step() { printf '\n%s▸ %s%s\n' "$BLUE" "$1" "$RESET"; }
ok()   { printf '%s  ✓ %s%s\n' "$GREEN" "$1" "$RESET"; }
warn() { printf '%s  ! %s%s\n' "$YELLOW" "$1" "$RESET"; }
die()  { printf '%s  ✗ %s%s\n' "$RED" "$1" "$RESET" >&2; exit 1; }

case "$ENVIRONMENT" in
  staging|production) ;;
  *) die "Unknown environment '${ENVIRONMENT}'. Use staging or production." ;;
esac

# An immutable tag is what makes a rollback meaningful — without it you cannot
# say which build you are returning to.
if [[ "$ENVIRONMENT" == "production" && -z "$IMAGE_TAG" ]]; then
  die "--tag is required for production. Pass the git SHA that CI built."
fi

VALUES_ARGS=(-f "${CHART_DIR}/values.yaml")
if [[ -f "${CHART_DIR}/values-${ENVIRONMENT}.yaml" ]]; then
  VALUES_ARGS+=(-f "${CHART_DIR}/values-${ENVIRONMENT}.yaml")
fi

SET_ARGS=()
if [[ -n "$IMAGE_TAG" ]]; then
  SET_ARGS+=(--set "image.backend.tag=${IMAGE_TAG}" --set "image.frontend.tag=${IMAGE_TAG}")
fi

printf '\n%s══════════════════════════════════════════════════%s\n' "$BLUE" "$RESET"
printf '%s  QuantNexa SOAR·AI deployment%s\n' "$BLUE" "$RESET"
printf '%s══════════════════════════════════════════════════%s\n' "$BLUE" "$RESET"
printf '  environment : %s\n' "$ENVIRONMENT"
printf '  namespace   : %s\n' "$NAMESPACE"
printf '  release     : %s\n' "$RELEASE"
printf '  image tag   : %s\n' "${IMAGE_TAG:-<chart appVersion>}"
printf '  dry run     : %s\n' "$DRY_RUN"

# ── Preflight ────────────────────────────────────────────────
if [[ "$SKIP_PREFLIGHT" == false ]]; then
  step "Preflight"
  IMAGE_TAG="$IMAGE_TAG" NAMESPACE="$NAMESPACE" RELEASE="$RELEASE" \
    ./deploy/scripts/preflight.sh "$ENVIRONMENT" || die "Preflight failed. Fix the issues above, or pass --skip-preflight for a non-production environment."
else
  [[ "$ENVIRONMENT" == "production" ]] && die "--skip-preflight is not permitted for production."
  warn "preflight skipped"
fi

# ── Namespace ────────────────────────────────────────────────
step "Namespace"
if kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
  ok "${NAMESPACE} exists"
else
  if [[ "$DRY_RUN" == true ]]; then
    warn "${NAMESPACE} would be created"
  else
    kubectl create namespace "$NAMESPACE"
    kubectl label namespace "$NAMESPACE" \
      "app.kubernetes.io/part-of=soar-ai" \
      "pod-security.kubernetes.io/enforce=restricted" \
      --overwrite
    ok "created ${NAMESPACE} with the restricted pod-security profile"
  fi
fi

# ── Diff ─────────────────────────────────────────────────────
step "Rendering manifests"
RENDERED="$(mktemp)"
trap 'rm -f "$RENDERED"' EXIT
helm template "$RELEASE" "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  "${VALUES_ARGS[@]}" "${SET_ARGS[@]}" > "$RENDERED" || die "Chart failed to render."
ok "$(grep -c '^kind:' "$RENDERED") resources rendered"

if helm plugin list 2>/dev/null | grep -q diff; then
  step "Diff against the live release"
  helm diff upgrade "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" \
    "${VALUES_ARGS[@]}" "${SET_ARGS[@]}" \
    --no-color 2>/dev/null || warn "no previous release to diff against"
fi

if [[ "$DRY_RUN" == true ]]; then
  step "Dry run"
  helm upgrade --install "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" \
    "${VALUES_ARGS[@]}" "${SET_ARGS[@]}" \
    --dry-run >/dev/null || die "Dry run failed."
  ok "dry run succeeded — nothing was applied"
  printf '\n%s✓ Dry run complete.%s\n\n' "$GREEN" "$RESET"
  exit 0
fi

# ── Record the current revision so a failure can be undone ───
PREVIOUS_REVISION=""
if helm status "$RELEASE" -n "$NAMESPACE" >/dev/null 2>&1; then
  PREVIOUS_REVISION="$(helm history "$RELEASE" -n "$NAMESPACE" --max 1 -o json 2>/dev/null \
    | grep -o '"revision":[0-9]*' | head -1 | cut -d: -f2)"
  ok "current revision: ${PREVIOUS_REVISION}"
fi

rollback_on_failure() {
  printf '\n%s✗ Deployment failed.%s\n' "$RED" "$RESET"
  if [[ -n "$PREVIOUS_REVISION" ]]; then
    printf '%s▸ Rolling back to revision %s%s\n' "$YELLOW" "$PREVIOUS_REVISION" "$RESET"
    if helm rollback "$RELEASE" "$PREVIOUS_REVISION" -n "$NAMESPACE" --wait --timeout "$TIMEOUT"; then
      printf '%s  ✓ Rolled back to revision %s%s\n' "$GREEN" "$PREVIOUS_REVISION" "$RESET"
    else
      printf '%s  ✗ Rollback also failed — manual intervention required.%s\n' "$RED" "$RESET"
      printf '    kubectl get pods -n %s\n' "$NAMESPACE"
      printf '    helm history %s -n %s\n' "$RELEASE" "$NAMESPACE"
    fi
  else
    printf '%s  This was a fresh install; nothing to roll back to.%s\n' "$YELLOW" "$RESET"
    printf '    Inspect with: kubectl get pods -n %s\n' "$NAMESPACE"
  fi
  exit 1
}

# ── Apply ────────────────────────────────────────────────────
step "Applying release"
HELM_ARGS=(
  upgrade --install "$RELEASE" "$CHART_DIR"
  --namespace "$NAMESPACE"
  "${VALUES_ARGS[@]}" "${SET_ARGS[@]}"
  --timeout "$TIMEOUT"
  # Atomic makes Helm undo its own partial apply; the trap below covers the
  # cases Helm cannot see, such as a rollout that goes unhealthy afterwards.
  --atomic
  --history-max 10
)
[[ "$WAIT" == true ]] && HELM_ARGS+=(--wait --wait-for-jobs)

trap rollback_on_failure ERR
helm "${HELM_ARGS[@]}"
trap - ERR
ok "release applied"

# ── Verify ───────────────────────────────────────────────────
if [[ "$WAIT" == true ]]; then
  step "Verifying rollout"
  for component in backend frontend; do
    DEPLOY="${RELEASE}-${component}"
    if ! kubectl rollout status "deployment/${DEPLOY}" -n "$NAMESPACE" --timeout="$TIMEOUT"; then
      rollback_on_failure
    fi
    ok "${component} rolled out"
  done

  if kubectl get deployment "${RELEASE}-worker" -n "$NAMESPACE" >/dev/null 2>&1; then
    kubectl rollout status "deployment/${RELEASE}-worker" -n "$NAMESPACE" --timeout="$TIMEOUT" \
      || warn "worker rollout did not complete — scheduled maintenance may lag"
  fi

  step "Health check"
  # Query readiness through the service rather than a pod, so this exercises
  # the same path real traffic takes.
  if kubectl run "soar-healthcheck-$$" \
      --namespace "$NAMESPACE" \
      --image=curlimages/curl:8.11.0 \
      --restart=Never --rm -i --quiet \
      --command -- curl -fsS --max-time 10 \
      "http://${RELEASE}-backend:8000/health/ready" >/dev/null 2>&1; then
    ok "API reports ready"
  else
    warn "health check did not pass — inspect: kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/component=backend"
  fi
fi

# ── Summary ──────────────────────────────────────────────────
step "Summary"
helm status "$RELEASE" -n "$NAMESPACE" --show-desc 2>/dev/null | head -20 || true
printf '\n'
kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/instance=${RELEASE}" 2>/dev/null || true

printf '\n%s✓ Deployment complete.%s\n' "$GREEN" "$RESET"
printf '  Roll back with: ./deploy/scripts/rollback.sh %s\n\n' "$ENVIRONMENT"
