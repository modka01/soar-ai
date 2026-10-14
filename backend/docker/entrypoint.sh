#!/usr/bin/env bash
# Container entrypoint. The first argument selects the process role, so one
# image serves the API, the worker and the migration job.
set -euo pipefail

ROLE="${1:-api}"
WORKERS="${SOAR_WEB_CONCURRENCY:-4}"
BIND="${SOAR_BIND:-0.0.0.0:8000}"
TIMEOUT="${SOAR_WORKER_TIMEOUT:-120}"

log() { printf '{"event":"entrypoint","role":"%s","message":"%s"}\n' "$ROLE" "$1"; }

wait_for_database() {
  local attempts="${SOAR_DB_WAIT_ATTEMPTS:-30}"
  local last_error=""
  log "waiting for the database"
  for ((i = 1; i <= attempts; i++)); do
    if last_error="$(python -c "
import asyncio, sys
from sqlalchemy import text
from app.db.session import get_engine

async def check():
    async with get_engine().connect() as connection:
        await connection.execute(text('SELECT 1'))

try:
    asyncio.run(check())
except Exception as exc:
    print(exc, file=sys.stderr)
    sys.exit(1)
" 2>&1)"; then
      log "database is reachable"
      return 0
    fi
    sleep 2
  done
  log "database did not become reachable in time"
  # Surface the last failure; a config error looks identical to a down database otherwise.
  printf '%s\n' "$last_error" >&2
  return 1
}

case "$ROLE" in
  api)
    wait_for_database
    log "starting the API on ${BIND} with ${WORKERS} worker(s)"
    # Uvicorn workers under gunicorn: gunicorn supervises and recycles them,
    # uvicorn serves ASGI. max-requests recycles workers to bound memory drift.
    exec gunicorn app.main:app \
      --worker-class uvicorn.workers.UvicornWorker \
      --workers "$WORKERS" \
      --bind "$BIND" \
      --timeout "$TIMEOUT" \
      --graceful-timeout 30 \
      --keep-alive 65 \
      --max-requests 2000 \
      --max-requests-jitter 200 \
      --access-logfile - \
      --error-logfile - \
      --log-level "${SOAR_LOG_LEVEL:-info}"
    ;;

  worker)
    wait_for_database
    log "starting the maintenance scheduler"
    exec python -m app.workers.scheduler
    ;;

  migrate)
    wait_for_database
    log "applying database migrations"
    alembic upgrade head
    log "seeding baseline content"
    exec python -m app.workers.bootstrap
    ;;

  shell)
    exec python
    ;;

  *)
    log "running a custom command"
    exec "$@"
    ;;
esac
