.PHONY: help \
        up down build ps \
        ingest ingest-full ingest-geoip enrich config-import resync \
        logs-agent logs-config-viz logs-superset \
        test lint fmt-check \
        test-ingester test-agent test-config-viz test-frontend \
        build-ingester \
        clean

DC         := cd docker && DOCKER_CLI_HINTS=false docker compose
GEOIP_CITY ?= /data/geoip/GeoLite2-City.mmdb
GEOIP_ASN  ?= /data/geoip/GeoLite2-ASN.mmdb

# ── サービス管理 ──────────────────────────────────────────
up:              ## Start all services
	$(DC) up -d --build
	@echo ""
	@echo "  🚀 \033[1mSenrigan is up and running!\033[0m"
	@echo ""
	@echo "  🔍  \033[36mhttp://localhost:8501\033[0m  — Built-in queries and AI Chat"
	@echo "  📊  \033[36mhttp://localhost:8088\033[0m  — Dashboard  \033[2m(admin / admin)\033[0m"
	@echo ""

down:            ## Stop all services
	$(DC) down

clean:           ## Stop containers, remove volumes + images + build cache
	$(DC) down -v --rmi all
	docker builder prune -f

build:           ## Build all Docker images (no start)
	$(DC) build

ps:              ## Show container status
	$(DC) ps

# ── Ingest ───────────────────────────────────────────────
ingest:          ## Ingest CloudTrail logs (strip-raw-event, lean DB)
	$(DC) --profile ingest run --rm ingester ingest \
	    --path /data/logs --strip-raw-event --strip-fields

ingest-full:     ## Ingest CloudTrail logs (keep raw_event column)
	$(DC) --profile ingest run --rm ingester ingest \
	    --path /data/logs --strip-fields

ingest-geoip:    ## Ingest CloudTrail logs with GeoIP enrichment
	$(DC) --profile ingest run --rm ingester ingest \
	    --path /data/logs \
	    --geoip-city $(GEOIP_CITY) \
	    --geoip-asn $(GEOIP_ASN) \
	    --strip-raw-event --strip-fields

enrich:          ## Back-fill GeoIP on existing DB rows
	$(DC) --profile ingest run --rm ingester enrich \
	    --geoip-country /data/geoip

config-import:   ## Import AWS Config snapshots
	$(DC) --profile ingest run --rm ingester config-import \
	    --path /data/config

resync:          ## Re-sync Superset dataset metadata after re-ingestion
	$(DC) --profile resync run --rm superset-resync

# ── ログ ─────────────────────────────────────────────────
logs-agent:      ## Tail agent logs
	$(DC) logs -f agent

logs-config-viz: ## Tail config-viz logs
	$(DC) logs -f config-viz

logs-superset:   ## Tail superset logs
	$(DC) logs -f superset

# ── 開発: テスト ─────────────────────────────────────────
test: test-ingester test-agent test-config-viz test-frontend  ## Run all tests

test-ingester:   ## Run ingester (Rust) tests
	cd ingester && cargo test --all

test-agent:      ## Run agent (Python) tests
	cd agent && pytest -v --tb=short

test-config-viz: ## Run config_viz (Python) tests
	cd config_viz && pytest -v --tb=short

test-frontend:   ## Run config_viz frontend (Vitest) tests
	cd config_viz/frontend && npm test

# ── Lint / Format ──────────────────────────────────
lint:            ## Run all linters (clippy + ruff)
	cd ingester && cargo clippy --all-targets --all-features -- -D warnings
	cd agent && ruff check .
	cd config_viz && ruff check .

fmt-check:       ## Check formatting (rustfmt + black)
	cd ingester && cargo fmt --all -- --check
	cd agent && black --check .
	cd config_viz && black --check .

build-ingester:  ## Build ingester release binary
	cd ingester && cargo build --release

# ── Help ─────────────────────────────────────────────────
help:            ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	    | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
