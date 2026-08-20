#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Pre-deployment checks. Run before deploy.sh — it refuses to
# proceed if any of these fail.
#
#   ./deploy/scripts/preflight.sh <environment>
# ─────────────────────────────────────────────────────────────
set -euo pipefail

ENVIRONMENT="${1:-staging}"
NAMESPACE="${NAMESPACE:-soar-${ENVIRONMENT}}"
RELEASE="${RELEASE:-soar-ai}"
CHART_DIR="${CHART_DIR:-deploy/helm/soar-ai}"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
FAILURES=0

check()  { printf '%s▸%s %s ... ' "$BLUE" "$RESET" "$1"; }
pass()   { printf '%s✓%s\n' "$GREEN" "$RESET"; }
warn()   { printf '%s! %s%s\n' "$YELLOW" "$1" "$RESET"; }
failed() { printf '%s✗ %s%s\n' "$RED" "$1" "$RESET"; FAILURES=$((FAILURES + 1)); }

printf '\n%s═══ Preflight: %s ═══%s\n\n' "$BLUE" "$ENVIRONMENT" "$RESET"

# ── Tooling ──────────────────────────────────────────────────
for tool in kubectl helm; do
  check "$tool is installed"
  if command -v "$tool" >/dev/null 2>&1; then pass; else failed "$tool not found on PATH"; fi
done

# ── Cluster ──────────────────────────────────────────────────
check "cluster is reachable"
if kubectl cluster-info >/dev/null 2>&1; then
  pass
  printf '    context: %s\n' "$(kubectl config current-context)"
else
  failed "cannot reach the cluster — check your kubeconfig"
fi

check "namespace ${NAMESPACE} exists"
if kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
  pass
else
  warn "missing — deploy.sh will create it"
fi

# ── Secrets ──────────────────────────────────────────────────
# The API cannot start without these; catching it here beats a CrashLoopBackOff.
check "required secrets are present"
SECRET_NAME="${SECRET_NAME:-${RELEASE}-secrets}"
if kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
  MISSING=""
  for key in secret-key webhook-hmac-secret database-url redis-url; do
    if ! kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath="{.data.$key}" 2>/dev/null | grep -q .; then
      MISSING="${MISSING} ${key}"
    fi
  done
  if [[ -z "$MISSING" ]]; then pass; else failed "secret is missing key(s):${MISSING}"; fi
else
  if [[ "$ENVIRONMENT" == "production" ]]; then
    failed "secret ${SECRET_NAME} not found in ${NAMESPACE}"
  else
    warn "secret ${SECRET_NAME} not found — External Secrets may create it"
  fi
fi

# ── Chart ────────────────────────────────────────────────────
check "chart lints"
if helm lint "$CHART_DIR" >/dev/null 2>&1; then pass; else failed "helm lint failed"; fi

check "chart renders for ${ENVIRONMENT}"
VALUES_ARGS=(-f "${CHART_DIR}/values.yaml")
if [[ -f "${CHART_DIR}/values-${ENVIRONMENT}.yaml" ]]; then
  VALUES_ARGS+=(-f "${CHART_DIR}/values-${ENVIRONMENT}.yaml")
fi
if helm template "$RELEASE" "$CHART_DIR" "${VALUES_ARGS[@]}" >/dev/null 2>&1; then
  pass
else
  failed "chart does not render — run: helm template $RELEASE $CHART_DIR ${VALUES_ARGS[*]}"
fi

# ── Images ───────────────────────────────────────────────────
check "image tag is pinned"
if [[ -n "${IMAGE_TAG:-}" && "$IMAGE_TAG" != "latest" ]]; then
  pass
  printf '    tag: %s\n' "$IMAGE_TAG"
elif [[ "$ENVIRONMENT" == "production" ]]; then
  # 'latest' makes a rollback ambiguous — you cannot say which build you
  # are going back to.
  failed "IMAGE_TAG must be an immutable tag in production, not 'latest'"
else
  warn "IMAGE_TAG unset — the chart's appVersion will be used"
fi

# ── Capacity ─────────────────────────────────────────────────
check "cluster has schedulable nodes"
NODE_COUNT="$(kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready ' || echo 0)"
if [[ "$NODE_COUNT" -gt 0 ]]; then
  pass
  printf '    ready nodes: %s\n' "$NODE_COUNT"
else
  failed "no Ready nodes found"
fi

# ── Existing release ─────────────────────────────────────────
check "previous release state"
if helm status "$RELEASE" -n "$NAMESPACE" >/dev/null 2>&1; then
  STATUS="$(helm status "$RELEASE" -n "$NAMESPACE" -o json 2>/dev/null | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)"
  if [[ "$STATUS" == "deployed" ]]; then
    pass
    printf '    current revision: %s\n' "$(helm history "$RELEASE" -n "$NAMESPACE" --max 1 -o json 2>/dev/null | grep -o '"revision":[0-9]*' | head -1 | cut -d: -f2)"
  else
    # A stuck pending-* release blocks the next upgrade until it is resolved.
    failed "release is in state '${STATUS}' — resolve it before deploying"
  fi
else
  warn "no existing release — this will be a fresh install"
fi

# ── Production-only gates ────────────────────────────────────
if [[ "$ENVIRONMENT" == "production" ]]; then
  check "destructive actions setting"
  DESTRUCTIVE="$(helm template "$RELEASE" "$CHART_DIR" "${VALUES_ARGS[@]}" 2>/dev/null \
    | grep -A1 'SOAR_ALLOW_DESTRUCTIVE_ACTIONS' | grep 'value:' | head -1 | awk '{print $2}' | tr -d '"')"
  if [[ "$DESTRUCTIVE" == "true" ]]; then
    warn "destructive actions are ENABLED — the agent can change live systems"
  else
    pass
    printf '    dry-run mode (containment tools change nothing)\n'
  fi

  check "TLS is configured"
  if helm template "$RELEASE" "$CHART_DIR" "${VALUES_ARGS[@]}" 2>/dev/null | grep -q 'secretName:.*tls'; then
    pass
  else
    failed "no TLS secret in the ingress — production must not serve plaintext"
  fi
fi

printf '\n'
if [[ "$FAILURES" -gt 0 ]]; then
  printf '%s✗ Preflight failed: %d check(s) did not pass.%s\n\n' "$RED" "$FAILURES" "$RESET"
  exit 1
fi
printf '%s✓ Preflight passed.%s\n\n' "$GREEN" "$RESET"
