# ─────────────────────────────────────────────────────────────
# QuantNexa SOAR·AI — developer entry points.
# Run `make help` for the full list.
# ─────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
.PHONY: help install dev-backend dev-frontend up down logs \
        lint test build check migrate seed clean \
        deploy-staging deploy-production rollback helm-lint

COMPOSE := docker compose -f deploy/docker/docker-compose.yml
BACKEND := backend
FRONTEND := frontend
PY := $(BACKEND)/.venv/bin/python

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

## ── Setup ──────────────────────────────────────────────────

install: ## Install backend and frontend dependencies
	cd $(BACKEND) && python3 -m venv .venv && .venv/bin/pip install -q -e ".[dev]"
	cd $(FRONTEND) && npm install --no-audit --no-fund
	@echo "✓ dependencies installed"

## ── Local development ──────────────────────────────────────

dev-backend: ## Run the API with reload
	cd $(BACKEND) && .venv/bin/uvicorn app.main:app --reload --port 8000

dev-frontend: ## Run the console with hot reload
	cd $(FRONTEND) && npm run dev

up: ## Start the full local stack
	$(COMPOSE) up -d
	@echo "console: http://localhost:8080  ·  api: http://localhost:8000/docs"

down: ## Stop the local stack
	$(COMPOSE) down

logs: ## Follow the stack logs
	$(COMPOSE) logs -f --tail=100

## ── Quality ────────────────────────────────────────────────

lint: ## Lint both components
	cd $(BACKEND) && .venv/bin/ruff check app tests && .venv/bin/ruff format --check app tests
	cd $(FRONTEND) && npm run lint && npm run format:check

test: ## Run both test suites
	cd $(BACKEND) && .venv/bin/pytest -q
	cd $(FRONTEND) && npm run test

check: lint test helm-lint ## Everything CI runs
	@echo "✓ all checks passed"

## ── Build ──────────────────────────────────────────────────

build: ## Build both components including images
	./$(BACKEND)/scripts/build.sh --image
	./$(FRONTEND)/scripts/build.sh --image

## ── Database ───────────────────────────────────────────────

migrate: ## Apply migrations locally
	cd $(BACKEND) && .venv/bin/alembic upgrade head

seed: ## Seed baseline knowledge and playbooks
	cd $(BACKEND) && .venv/bin/python -m app.workers.bootstrap

## ── Deployment ─────────────────────────────────────────────

helm-lint: ## Lint and render the Helm chart
	helm lint deploy/helm/soar-ai
	helm template soar-ai deploy/helm/soar-ai --set secrets.existingSecret=x > /dev/null
	helm template soar-ai deploy/helm/soar-ai -f deploy/helm/soar-ai/values-production.yaml > /dev/null
	@echo "✓ chart renders for both value sets"

deploy-staging: ## Deploy to staging (TAG=<sha>)
	./deploy/scripts/deploy.sh staging $(if $(TAG),--tag $(TAG))

deploy-production: ## Deploy to production (TAG required)
	@test -n "$(TAG)" || (echo "TAG is required: make deploy-production TAG=4f2a1b9" && exit 1)
	./deploy/scripts/deploy.sh production --tag $(TAG)

rollback: ## Roll back (ENV=staging|production)
	./deploy/scripts/rollback.sh $(or $(ENV),staging)

## ── Housekeeping ───────────────────────────────────────────

clean: ## Remove build artefacts and caches
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf $(FRONTEND)/dist $(FRONTEND)/coverage $(BACKEND)/coverage.xml $(BACKEND)/htmlcov
	rm -f $(BACKEND)/.build-meta.json $(FRONTEND)/.build-meta.json
	@echo "✓ cleaned"
