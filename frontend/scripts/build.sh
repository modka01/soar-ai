#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Frontend build: lint → typecheck → test → bundle → image.
#
#   ./scripts/build.sh                 lint, typecheck, test, bundle
#   ./scripts/build.sh --image         also build the container image
#   ./scripts/build.sh --image --push  build and push to the registry
#   ./scripts/build.sh --skip-tests    bundle only (CI already tested)
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$(dirname "$SCRIPT_DIR")"
cd "$FRONTEND_DIR"

REGISTRY="${REGISTRY:-ghcr.io/quantnexa}"
IMAGE_NAME="${IMAGE_NAME:-soar-ai-frontend}"
VERSION="${VERSION:-$(node -p "require('./package.json').version")}"
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PLATFORMS="${PLATFORMS:-linux/amd64}"
# Empty means "call same-origin", which is what nginx expects in production.
VITE_API_BASE_URL="${VITE_API_BASE_URL:-}"

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

step "Environment"
echo "  node    : $(node --version)"
echo "  npm     : $(npm --version)"
echo "  version : ${VERSION}"
echo "  git     : ${GIT_SHA}"

step "Dependencies"
if [[ -f package-lock.json ]]; then
  # ci installs strictly from the lockfile — a build must never silently
  # resolve a different dependency tree than the one that was reviewed.
  npm ci --no-audit --no-fund || fail "npm ci failed."
else
  npm install --no-audit --no-fund || fail "npm install failed."
fi
ok "dependencies installed"

step "Lint (eslint)"
npm run lint || fail "Lint failed. Run: npm run lint:fix"
ok "lint clean"

step "Format check (prettier)"
npm run format:check || fail "Formatting drift. Run: npm run format"
ok "formatting clean"

step "Type check (tsc)"
npm run typecheck || fail "Type check failed."
ok "types clean"

if [[ "$RUN_TESTS" == true ]]; then
  step "Tests (vitest)"
  npm run test || fail "Tests failed."
  ok "tests passed"
fi

step "Bundle (vite)"
VITE_API_BASE_URL="$VITE_API_BASE_URL" npm run build || fail "Bundle failed."
BUNDLE_SIZE="$(du -sh dist | cut -f1)"
ok "bundle built (${BUNDLE_SIZE})"

if [[ "$BUILD_IMAGE" == true ]]; then
  step "Container image"
  IMAGE="${REGISTRY}/${IMAGE_NAME}"
  TAGS=(--tag "${IMAGE}:${VERSION}" --tag "${IMAGE}:${GIT_SHA}" --tag "${IMAGE}:latest")

  BUILD_ARGS=(
    --build-arg "VERSION=${VERSION}"
    --build-arg "GIT_SHA=${GIT_SHA}"
    --build-arg "BUILD_DATE=${BUILD_DATE}"
    --build-arg "VITE_API_BASE_URL=${VITE_API_BASE_URL}"
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

  cat > .build-meta.json <<META
{
  "component": "frontend",
  "image": "${IMAGE}",
  "version": "${VERSION}",
  "git_sha": "${GIT_SHA}",
  "built_at": "${BUILD_DATE}"
}
META
  ok "wrote .build-meta.json"
fi

printf '\n\033[1;32m✓ Frontend build complete\033[0m\n'
