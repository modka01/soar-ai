#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Backend build: lint → typecheck → test → container image.
#
#   ./scripts/build.sh                 lint, typecheck and test
#   ./scripts/build.sh --image         also build the container image
#   ./scripts/build.sh --image --push  build and push to the registry
#   ./scripts/build.sh --skip-tests    image only (CI already tested)
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"
cd "$BACKEND_DIR"

REGISTRY="${REGISTRY:-ghcr.io/quantnexa}"
IMAGE_NAME="${IMAGE_NAME:-soar-ai-backend}"
VERSION="${VERSION:-$(grep -m1 '^version' pyproject.toml | cut -d'"' -f2)}"
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PLATFORMS="${PLATFORMS:-linux/amd64}"

BUILD_IMAGE=false
PUSH_IMAGE=false
RUN_TESTS=true

for arg in "$@"; do
  case "$arg" in
    --image) BUILD_IMAGE=true ;;
    --push)  BUILD_IMAGE=true; PUSH_IMAGE=true ;;
    --skip-tests) RUN_TESTS=false ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1;34m▸ %s\033[0m\n' "$1"; }
ok()   { printf '\033[0;32m  ✓ %s\033[0m\n' "$1"; }
fail() { printf '\033[0;31m  ✗ %s\033[0m\n' "$1" >&2; exit 1; }

# Prefer the project venv when one exists, so the script behaves the same
# locally and in CI.
if [[ -x ".venv/bin/python" ]]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

step "Environment"
echo "  python : $($PY --version 2>&1)"
echo "  version: ${VERSION}"
echo "  git    : ${GIT_SHA}"

step "Lint (ruff)"
$PY -m ruff check app tests || fail "Lint failed. Run: ruff check app tests --fix"
$PY -m ruff format --check app tests || fail "Formatting drift. Run: ruff format app tests"
ok "lint clean"

step "Type check (mypy)"
if $PY -m mypy app 2>/dev/null; then
  ok "types clean"
else
  # mypy is advisory here: the codebase is progressively typed, and a new
  # inference edge case must not block a security patch from shipping.
  printf '\033[0;33m  ! mypy reported issues (advisory, not blocking)\033[0m\n'
fi

if [[ "$RUN_TESTS" == true ]]; then
  step "Tests (pytest)"
  $PY -m pytest -q --cov=app --cov-report=term-missing:skip-covered \
    || fail "Tests failed."
  ok "tests passed"
fi

step "Migration check"
# A model change without a matching migration is a deploy-time failure; catch
# it here instead.
if SOAR_DATABASE_URL="sqlite+aiosqlite:///./.build-check.db" $PY -m alembic upgrade head >/dev/null 2>&1; then
  ok "migrations apply cleanly"
  rm -f .build-check.db
else
  rm -f .build-check.db
  fail "Migrations do not apply. Run: alembic upgrade head"
fi

if [[ "$BUILD_IMAGE" == true ]]; then
  step "Container image"
  IMAGE="${REGISTRY}/${IMAGE_NAME}"
  TAGS=(--tag "${IMAGE}:${VERSION}" --tag "${IMAGE}:${GIT_SHA}" --tag "${IMAGE}:latest")

  BUILD_ARGS=(
    --build-arg "VERSION=${VERSION}"
    --build-arg "GIT_SHA=${GIT_SHA}"
    --build-arg "BUILD_DATE=${BUILD_DATE}"
  )

  if docker buildx version >/dev/null 2>&1; then
    PUSH_FLAG="--load"
    [[ "$PUSH_IMAGE" == true ]] && PUSH_FLAG="--push"
    docker buildx build \
      --platform "$PLATFORMS" \
      "${BUILD_ARGS[@]}" "${TAGS[@]}" \
      $PUSH_FLAG \
      --file Dockerfile . || fail "Image build failed."
  else
    docker build "${BUILD_ARGS[@]}" "${TAGS[@]}" --file Dockerfile . \
      || fail "Image build failed."
    if [[ "$PUSH_IMAGE" == true ]]; then
      for tag in "${IMAGE}:${VERSION}" "${IMAGE}:${GIT_SHA}" "${IMAGE}:latest"; do
        docker push "$tag" || fail "Push failed for $tag"
      done
    fi
  fi
  ok "image ${IMAGE}:${VERSION}"

  # Record what was built so the deploy script can pin the exact tag.
  cat > .build-meta.json <<META
{
  "component": "backend",
  "image": "${IMAGE}",
  "version": "${VERSION}",
  "git_sha": "${GIT_SHA}",
  "built_at": "${BUILD_DATE}"
}
META
  ok "wrote .build-meta.json"
fi

printf '\n\033[1;32m✓ Backend build complete\033[0m\n'
