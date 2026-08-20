# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────
# QuantNexa SOAR·AI — backend image
# Multi-stage: dependencies are built once against a compiler
# toolchain, then copied into a slim runtime that carries none.
# ─────────────────────────────────────────────────────────────

ARG PYTHON_VERSION=3.12

# ── Stage 1: build the virtualenv ────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only the dependency manifest first so the layer caches across code edits.
COPY pyproject.toml ./
COPY app/__init__.py ./app/
RUN pip install --upgrade pip setuptools wheel && pip install .

# ── Stage 2: runtime ─────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG VERSION=1.0.0
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="QuantNexa SOAR·AI Backend" \
      org.opencontainers.image.vendor="QuantNexa Technologies" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="Proprietary"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PATH="/opt/venv/bin:$PATH" \
    SOAR_ENVIRONMENT=production

# libpq is needed at runtime; the compiler toolchain is not.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 soar \
    && useradd --uid 10001 --gid soar --no-create-home --shell /usr/sbin/nologin soar

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=soar:soar app ./app
COPY --chown=soar:soar alembic ./alembic
COPY --chown=soar:soar alembic.ini ./
COPY --chown=soar:soar docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Runs unprivileged with a read-only root filesystem in Kubernetes; /tmp is the
# only writable path the process needs.
USER soar:soar

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health/live || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["api"]
