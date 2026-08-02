.PHONY: help help-all \
        up down logs reset status build ps ensure-secret \
        ingest ingest-full ingest-geoip enrich ingest-config config-import resync \
        logs-agent logs-config-viz logs-superset \
        check test lint fmt-check \
        test-ingester test-agent test-config-viz test-dashboard test-frontend test-repo \
        build-ingester \
        clean

# Running `make` with no arguments must explain the tool, not act on it.
.DEFAULT_GOAL := help

DC            := cd docker && DOCKER_CLI_HINTS=false docker compose

# Container-side paths to the GeoLite2 databases (docker/data/geoip is mounted
# at /data/geoip). These are file paths, not a directory: the ingester passes
# each straight to maxminddb and performs no directory lookup.
GEOIP_CITY    ?= /data/geoip/GeoLite2-City.mmdb
GEOIP_COUNTRY ?= /data/geoip/GeoLite2-Country.mmdb
GEOIP_ASN     ?= /data/geoip/GeoLite2-ASN.mmdb

# ── Option detection ─────────────────────────────────────
# `make ingest` takes no flags. Instead it looks at the directories the user
# was already told to populate, and enables the matching ingester options.
# The filesystem is the configuration.
#
# These two variables mirror docker-compose.yml's bind mounts, defaults
# included, so an override moves the mount and the detection together.
GEOIP_HOST_PATH  ?= ./data/geoip
CONFIG_HOST_PATH ?= ./data/config-snapshots
DUCKDB_HOST_PATH ?= ./data/db

# Compose resolves host paths relative to docker/; make runs from the repo
# root. Absolute paths are passed through untouched.
host_dir = $(if $(filter /%,$(1)),$(1),docker/$(patsubst ./%,%,$(1)))

GEOIP_HOST_DIR   := $(call host_dir,$(GEOIP_HOST_PATH))
CONFIG_HOST_DIR  := $(call host_dir,$(CONFIG_HOST_PATH))
DB_HOST_DIR      := $(call host_dir,$(DUCKDB_HOST_PATH))
DB_FILE          := $(DB_HOST_DIR)/threat_hunting.db

# docker-compose.yml mounts ./logs read-only at /data/logs and offers no
# override, so this path is fixed.
LOG_HOST_DIR     := docker/logs

CITY_MMDB        := $(wildcard $(GEOIP_HOST_DIR)/GeoLite2-City.mmdb)
COUNTRY_MMDB     := $(wildcard $(GEOIP_HOST_DIR)/GeoLite2-Country.mmdb)
ASN_MMDB         := $(wildcard $(GEOIP_HOST_DIR)/GeoLite2-ASN.mmdb)
CONFIG_SNAPSHOTS := $(wildcard $(CONFIG_HOST_DIR)/*)

# Suzaku (https://github.com/Yamato-Security/suzaku) writes .duckdb files that
# the analyst copies in by hand. Senrigan reads them as-is, so there is nothing
# to run — `status` just reports what it can see. The names are arbitrary: the
# agent and superset-init both detect the producing command from the schema.
#
# The extension is the analyst's choice too, so `.db` counts; Senrigan's own
# database is filtered out by name (agent/suzaku_db.py does the same).
SUZAKU_DBS       := $(filter-out $(DB_FILE),$(wildcard $(DB_HOST_DIR)/*.duckdb) $(wildcard $(DB_HOST_DIR)/*.db))

# The image carrying the detection module. `status` and `up` ask it which file
# each dashboard actually selected; without it they can only list file names.
SUPERSET_IMAGE   := senrigan-dashboard:latest

# One-shot container that prints the selection: which file serves each Suzaku
# command, which candidates it beat, and which were rejected and why.
SUZAKU_REPORT    = $(DC) run --rm --entrypoint python3 superset-init \
                       /app/register_suzaku_dbs.py --report 2>/dev/null

# City supersedes Country: the ingester ignores the country database whenever
# the city one is set, so never pass both. $(strip) matters — a line
# continuation inside $(if) leaves a space behind, and a lone space would read
# as "enrichment enabled" to the ifneq below.
GEOIP_FLAGS := $(strip \
    $(if $(CITY_MMDB),--geoip-city $(GEOIP_CITY),$(if $(COUNTRY_MMDB),--geoip-country $(GEOIP_COUNTRY))) \
    $(if $(ASN_MMDB),--geoip-asn $(GEOIP_ASN)))

##@ Getting started

ingest: ensure-secret          ## Load CloudTrail logs from docker/logs/ into DuckDB
	@if [ -z "$$(find $(LOG_HOST_DIR) \( -name '*.json' -o -name '*.json.gz' \) -print -quit 2>/dev/null)" ]; then \
	    printf '\n  No CloudTrail logs found in %s/\n\n' '$(LOG_HOST_DIR)'; \
	    printf '  Export them from S3 first:\n'; \
	    printf '    aws s3 cp s3://<your-bucket-prefix> %s/ --recursive --include "*.json.gz"\n\n' '$(LOG_HOST_DIR)'; \
	    exit 1; \
	fi
	@printf '\n'
ifneq ($(GEOIP_FLAGS),)
	@printf '  ✓ GeoIP database found in %s/ — IP enrichment enabled\n' '$(GEOIP_HOST_DIR)'
else
	@printf '  · No GeoIP database in %s/ — IP enrichment skipped\n' '$(GEOIP_HOST_DIR)'
endif
ifneq ($(CONFIG_SNAPSHOTS),)
	@printf '  ✓ AWS Config snapshots found in %s/ — importing after CloudTrail\n' '$(CONFIG_HOST_DIR)'
else
	@printf '  · No AWS Config snapshots in %s/ — resource graph will be empty\n' '$(CONFIG_HOST_DIR)'
endif
	@printf '\n'
	$(DC) --profile ingest run --rm ingester ingest \
	    --path /data/logs $(GEOIP_FLAGS) --strip-raw-event --strip-fields
ifneq ($(CONFIG_SNAPSHOTS),)
	$(DC) --profile ingest run --rm ingester config-import \
	    --path /data/config
endif
	@printf '\n  Next: \033[36mmake up\033[0m\n'
	@printf '  Dashboards blank after a re-ingest? \033[36mmake resync\033[0m\n\n'

up: ensure-secret              ## Start the UI, dashboard, and resource graph
	@test -f $(DB_FILE) || printf '\n  ⚠️  No database at %s — dashboards will be empty. Run: make ingest\n' '$(DB_FILE)'
	$(DC) up -d --build
	@echo ""
	@echo "  🚀 \033[1mSenrigan is up and running!\033[0m"
	@echo ""
	@echo "  🔍  \033[36mhttp://localhost:8501\033[0m  — Built-in queries and AI Chat"
	@echo "  📊  \033[36mhttp://localhost:8088/dashboard/list\033[0m  — Dashboard  \033[2m(admin / admin)\033[0m"
ifneq ($(SUZAKU_DBS),)
	@echo ""
	@echo "  🕒  \033[1mSuzaku output detected\033[0m — see the Suzaku pages in both UIs."
	@echo ""
	@$(SUZAKU_REPORT) | tail -n +2 | sed 's/^  /      /' || true
endif
	@echo ""

down: ensure-secret            ## Stop all services
	$(DC) down

# SERVICE narrows `logs` to one container; empty means every container.
SERVICE ?=

logs: ensure-secret            ## Tail service logs (one only: SERVICE=agent)
	$(DC) logs -f $(SERVICE)

# Replaces the hand-copied `rm -f data/db/...` recipe that used to live in the
# docs. Only the two DuckDB files are ever removed, always by explicit name —
# never a directory, so a bad DUCKDB_HOST_PATH cannot take a tree with it.
reset: ensure-secret           ## Delete the database and start over
ifneq ($(FORCE),1)
	@printf '\n  This deletes:\n'
	@printf '    %s\n'     '$(DB_FILE)'
	@printf '    %s.wal\n' '$(DB_FILE)'
	@printf '\n  Your logs in $(LOG_HOST_DIR)/ are left untouched.\n'
	@printf '  Continue? [y/N] '
	@read -r reply; case "$$reply" in [yY]*) ;; *) printf '\n  Aborted — nothing was deleted.\n\n'; exit 1;; esac
endif
	$(DC) down
	rm -f $(DB_FILE) $(DB_FILE).wal
	@printf '\n  Database deleted. Next: \033[36mmake ingest\033[0m\n\n'

##@ Advanced ingest

ingest-full: ensure-secret     ## Force: keep raw_event, skip option detection
	$(DC) --profile ingest run --rm ingester ingest \
	    --path /data/logs --strip-fields

ingest-geoip: ensure-secret    ## Force: GeoIP enrichment (City + ASN), ignoring detection
	$(DC) --profile ingest run --rm ingester ingest \
	    --path /data/logs \
	    --geoip-city $(GEOIP_CITY) \
	    --geoip-asn $(GEOIP_ASN) \
	    --strip-raw-event --strip-fields

ingest-config: ensure-secret   ## Import AWS Config snapshots only
	$(DC) --profile ingest run --rm ingester config-import \
	    --path /data/config

# Kept for compatibility: `config-import` was the original target name.
config-import: ingest-config

enrich: ensure-secret          ## Back-fill GeoIP on existing DB rows
	$(DC) --profile ingest run --rm ingester enrich \
	    --geoip-city $(GEOIP_CITY) \
	    --geoip-asn $(GEOIP_ASN)

##@ Operations

status: ensure-secret          ## Show container, database, and detection status
	$(DC) ps
	@printf '\n'
	@if [ -f $(DB_FILE) ]; then \
	    printf '  Database  %s  (%s)\n' '$(DB_FILE)' "$$(du -h '$(DB_FILE)' | cut -f1)"; \
	else \
	    printf '  Database  not found at %s — run: make ingest\n' '$(DB_FILE)'; \
	fi
	@printf '  GeoIP     %s\n' '$(if $(GEOIP_FLAGS),enabled from $(GEOIP_HOST_DIR)/,no database in $(GEOIP_HOST_DIR)/)'
	@printf '  Config    %s\n' '$(if $(CONFIG_SNAPSHOTS),$(words $(CONFIG_SNAPSHOTS)) snapshot file(s) in $(CONFIG_HOST_DIR)/,none in $(CONFIG_HOST_DIR)/)'
ifneq ($(SUZAKU_DBS),)
	@printf '  Suzaku    %s file(s) in %s/\n' '$(words $(SUZAKU_DBS))' '$(DB_HOST_DIR)'
	@if docker image inspect $(SUPERSET_IMAGE) >/dev/null 2>&1; then \
	    $(SUZAKU_REPORT) | tail -n +2 | sed 's/^  /            /'; \
	else \
	    for db in $(SUZAKU_DBS); do printf '              %s\n' "$$db"; done; \
	    printf '            run make up once to see which file each dashboard uses\n'; \
	fi
else
	@printf '  Suzaku    no *.duckdb in %s/ — copy Suzaku output there to visualize it\n' '$(DB_HOST_DIR)'
endif
	@printf '\n'

# Kept for compatibility: `ps` predates `status`.
ps: status

build: ensure-secret           ## Build all Docker images (no start)
	$(DC) build

resync: ensure-secret          ## Re-sync Superset dataset metadata after re-ingestion
	$(DC) --profile resync run --rm superset-resync

clean: ensure-secret           ## Stop containers, remove volumes + images + build cache
	$(DC) down -v --rmi all
	docker builder prune -f

# Kept for compatibility: the per-service targets predate `logs SERVICE=`.
# Target-specific variables propagate to prerequisites, so each simply pins
# SERVICE and defers to `logs`.
logs-agent:      SERVICE := agent
logs-config-viz: SERVICE := config-viz
logs-superset:   SERVICE := superset
logs-agent logs-config-viz logs-superset: logs

##@ Development

check: test lint fmt-check  ## Run everything CI enforces (tests + lint + format)

test: test-ingester test-agent test-config-viz test-dashboard test-frontend test-repo  ## Run all tests

test-ingester:   ## Run ingester (Rust) tests
	cd ingester && cargo test --all

test-agent:      ## Run agent (Python) tests
	cd agent && pytest -v --tb=short

test-config-viz: ## Run config_viz (Python) tests
	cd config_viz && pytest -v --tb=short

test-dashboard:  ## Run dashboard asset-validation tests
	cd dashboard && pytest -v --tb=short

test-frontend:   ## Run config_viz frontend (Vitest) tests
	cd config_viz/frontend && npm test

test-repo:       ## Run repository consistency tests (Makefile / compose / docs)
	pytest -v --tb=short

lint:            ## Run all linters (clippy + ruff)
	cd ingester && cargo clippy --all-targets --all-features -- -D warnings
	cd agent && ruff check .
	cd config_viz && ruff check .
	cd dashboard && ruff check .
	ruff check tests sample

fmt-check:       ## Check formatting (rustfmt + black)
	cd ingester && cargo fmt --all -- --check
	cd agent && black --check .
	cd config_viz && black --check .
	cd dashboard && black --check .
	black --check tests sample

build-ingester:  ## Build ingester release binary
	cd ingester && cargo build --release

##@ Help

help:            ## Show the handful of commands you need
	@printf '\n  \033[1mSenrigan\033[0m — offline AWS CloudTrail threat hunting\n\n'
	@printf '  1.  \033[36mmake ingest\033[0m     Load CloudTrail logs from docker/logs/ into DuckDB\n'
	@printf '  2.  \033[36mmake up\033[0m         Start the UI, dashboard, and resource graph\n'
	@printf '  3.  \033[36mmake down\033[0m       Stop everything\n'
	@printf '      \033[36mmake logs\033[0m       Tail logs from the running services\n'
	@printf '      \033[36mmake reset\033[0m      Delete the database and start over\n'
	@printf '\n  More:  \033[36mmake help-all\033[0m   every target, grouped\n\n'

help-all:        ## List every target, grouped by section
	@awk 'BEGIN {FS = ":.*## "} \
	     /^##@/ { printf "\n  \033[1m%s\033[0m\n", substr($$0, 5); next } \
	     /^[a-zA-Z0-9][a-zA-Z0-9_-]*:.*## / { printf "    \033[36m%-16s\033[0m %s\n", $$1, $$2 }' \
	     $(MAKEFILE_LIST)
	@echo ""

# ── Internal ─────────────────────────────────────────────
# Deliberately undocumented (no ## comment): plumbing, not a user command.
#
# docker-compose.yml interpolates ${SUPERSET_SECRET_KEY:?} at parse time, so
# every compose invocation needs the key present in docker/.env — hence the
# ensure-secret prerequisite on all $(DC) targets.
ensure-secret:
	@touch docker/.env
	@if ! grep -q '^SUPERSET_SECRET_KEY=..*' docker/.env; then \
	    key=$$(head -c 42 /dev/urandom | base64 | tr -d '\n'); \
	    if grep -q '^SUPERSET_SECRET_KEY=' docker/.env; then \
	        sed -i.bak "s|^SUPERSET_SECRET_KEY=.*|SUPERSET_SECRET_KEY=$$key|" docker/.env && rm -f docker/.env.bak; \
	    else \
	        echo "SUPERSET_SECRET_KEY=$$key" >> docker/.env; \
	    fi; \
	    echo "  🔑 Generated SUPERSET_SECRET_KEY in docker/.env"; \
	fi
