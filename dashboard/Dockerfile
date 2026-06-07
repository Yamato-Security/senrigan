FROM apache/superset:6.1.0

USER root

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

# Superset 6.x uses uv to manage /app/.venv (no pip in the venv by default).
# --break-system-packages is not needed because uv targets the isolated venv, not system Python.
RUN uv pip install --python /app/.venv --no-cache-dir \
    "duckdb-engine>=0.14.0"

# Verify dialect is importable at build time to catch missing-module errors early.
RUN python3 -c 'import duckdb_engine'

USER superset
