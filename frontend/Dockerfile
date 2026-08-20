# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────
# QuantNexa SOAR·AI — frontend image
# Builds the SPA, then serves it from nginx-unprivileged so the
# container can run as a non-root user on port 8080.
# ─────────────────────────────────────────────────────────────

ARG NODE_VERSION=22
ARG NGINX_VERSION=1.27-alpine

# ── Stage 1: build the bundle ────────────────────────────────
FROM node:${NODE_VERSION}-alpine AS builder

WORKDIR /build

# Install from the lockfile only, so the image is reproducible.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY tsconfig*.json vite.config.ts index.html ./
COPY public ./public
COPY src ./src

# The API base is baked in at build time; leaving it empty makes the SPA call
# same-origin paths, which nginx proxies to the backend service.
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

RUN npm run build

# ── Stage 2: serve ───────────────────────────────────────────
FROM nginxinc/nginx-unprivileged:${NGINX_VERSION} AS runtime

ARG VERSION=1.0.0
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="QuantNexa SOAR·AI Frontend" \
      org.opencontainers.image.vendor="QuantNexa Technologies" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="Proprietary"

USER root
RUN rm -rf /usr/share/nginx/html/* \
    && apk add --no-cache curl

COPY --from=builder /build/dist /usr/share/nginx/html
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template

RUN chown -R 101:101 /usr/share/nginx/html /etc/nginx
USER 101

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8080/healthz || exit 1
