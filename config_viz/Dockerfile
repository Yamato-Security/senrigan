# Stage 1: frontend-builder — builds the React/Vite SPA → /app/static/
# Stage 2: runtime          — Python 3.14 + FastAPI + built static files
#
# icons/ is populated at build time; if the download fails (no network, TLS proxy),
# extract_icons.py creates default.png and exits 0 — the frontend falls back to it.

# Pinned by digest for supply chain integrity.
# To update: docker pull node:22-slim && docker inspect --format '{{index .RepoDigests 0}}'
FROM node:22-slim@sha256:7af03b14a13c8cdd38e45058fd957bf00a72bbe17feac43b1c15a689c029c732 AS frontend-builder

ARG CUSTOM_CA_CERT_BASE64=""
RUN if [ -n "$CUSTOM_CA_CERT_BASE64" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends ca-certificates \
        && printf '%s' "$CUSTOM_CA_CERT_BASE64" | base64 -d \
             > /usr/local/share/ca-certificates/custom-ca.crt \
        && update-ca-certificates \
        && rm -rf /var/lib/apt/lists/*; \
    fi
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json frontend/.npmrc ./
RUN npm ci

RUN npx --yes @cyclonedx/cyclonedx-npm \
      --output-format JSON \
      --output-file /tmp/sbom-frontend.json \
      --mc-type application 2>/dev/null \
    && echo "SBOM generated: $(wc -c < /tmp/sbom-frontend.json) bytes"

# vite.config.ts sets outDir = path.resolve(__dirname, "../static") → /app/static/
COPY frontend/ ./
RUN npm run build

FROM python:3.14-slim AS runtime

ARG CUSTOM_CA_CERT_BASE64=""
RUN if [ -n "$CUSTOM_CA_CERT_BASE64" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends ca-certificates \
        && printf '%s' "$CUSTOM_CA_CERT_BASE64" | base64 -d \
             > /usr/local/share/ca-certificates/custom-ca.crt \
        && update-ca-certificates \
        && rm -rf /var/lib/apt/lists/*; \
    fi
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ ./backend/
COPY --from=frontend-builder /app/static ./static
COPY --from=frontend-builder /tmp/sbom-frontend.json ./sbom-frontend.json

RUN python backend/scripts/extract_icons.py /app/static/icons || true

EXPOSE 8502

ENV DUCKDB_PATH=/data/db/threat_hunting.db

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8502/api/snapshots || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8502"]
