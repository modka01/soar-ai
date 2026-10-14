#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Prepare the repository-root .env for the local docker compose stack.
#
# Creates .env from .env.example if it does not exist, then fills in any
# secret still holding a placeholder: SOAR_SECRET_KEY,
# SOAR_WEBHOOK_HMAC_SECRET and SOAR_BOOTSTRAP_ADMIN_PASSWORD. Values that
# are already set are never touched, so it is safe to re-run.
#
#   ./deploy/scripts/init-env.sh
#   ADMIN_EMAIL=you@example.com ADMIN_PASSWORD="$YOUR_PASSWORD" ./deploy/scripts/init-env.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="$ROOT/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$ROOT/.env.example" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "✓ created .env from .env.example"
fi

random_hex() { openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))'; }

# 20 random alphanumerics plus a fixed suffix, so the password always meets the
# app's policy (12+ chars, three of lower/upper/digit/symbol).
random_password() {
  local body
  body="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
  printf '%s-Aa1' "$body"
}

current_value() { grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2- | sed -E 's/[[:space:]]+#.*$//' || true; }

# Replace KEY's line in .env, or append it when absent. Uses a temp file
# rather than sed -i so it behaves the same on GNU and BSD/macOS.
set_value() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  if grep -qE "^$key=" "$ENV_FILE"; then
    awk -v k="$key" -v v="$value" 'index($0, k "=") == 1 { print k "=" v; next } { print }' "$ENV_FILE" >"$tmp"
  else
    cat "$ENV_FILE" >"$tmp"
    printf '%s=%s\n' "$key" "$value" >>"$tmp"
  fi
  cat "$tmp" >"$ENV_FILE"
  rm -f "$tmp"
}

is_placeholder() { [[ -z "$1" || "$1" == change-me* ]]; }

for key in SOAR_SECRET_KEY SOAR_WEBHOOK_HMAC_SECRET; do
  if is_placeholder "$(current_value "$key")"; then
    set_value "$key" "$(random_hex)"
    echo "✓ generated $key"
  fi
done

if [[ -n "${ADMIN_EMAIL:-}" ]]; then
  set_value SOAR_BOOTSTRAP_ADMIN_EMAIL "$ADMIN_EMAIL"
elif [[ -z "$(current_value SOAR_BOOTSTRAP_ADMIN_EMAIL)" ]]; then
  set_value SOAR_BOOTSTRAP_ADMIN_EMAIL "admin@quantnexa.io"
fi

if [[ -n "${ADMIN_PASSWORD:-}" ]]; then
  if [[ "${#ADMIN_PASSWORD}" -lt 12 ]]; then
    echo "✗ ADMIN_PASSWORD must be at least 12 characters" >&2
    exit 1
  fi
  set_value SOAR_BOOTSTRAP_ADMIN_PASSWORD "$ADMIN_PASSWORD"
  echo "✓ set SOAR_BOOTSTRAP_ADMIN_PASSWORD"
elif [[ -z "$(current_value SOAR_BOOTSTRAP_ADMIN_PASSWORD)" ]]; then
  password="$(random_password)"
  set_value SOAR_BOOTSTRAP_ADMIN_PASSWORD "$password"
  cat <<EOF

  First administrator (created on the next migrate, only if no users exist yet):
    email:    $(current_value SOAR_BOOTSTRAP_ADMIN_EMAIL)
    password: $password

  It is also stored in .env. Change it after the first sign-in.

EOF
fi
