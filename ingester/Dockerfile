# INGESTER_VERSION: release tag used to download a pre-built binary (prebuilt-runtime target).
# Set INGESTER_BUILD_TARGET=prebuilt-runtime in docker-compose to use a pre-built binary instead of compiling from source.
# ARG INGESTER_VERSION="v1.0.0"

# Global ARG — must be redeclared in each stage that requires network access.
ARG CUSTOM_CA_CERT_BASE64=""

FROM rust:1.98.0-slim AS builder

ARG CUSTOM_CA_CERT_BASE64
RUN if [ -n "$CUSTOM_CA_CERT_BASE64" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends ca-certificates \
        && printf '%s' "$CUSTOM_CA_CERT_BASE64" | base64 -d \
             > /usr/local/share/ca-certificates/custom-ca.crt \
        && update-ca-certificates \
        && rm -rf /var/lib/apt/lists/*; \
    fi
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt

# DuckDB's bundled feature compiles C++, requiring these build deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    cmake \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Limit to 2 parallel C++ jobs to prevent OOM in memory-constrained envs (e.g. WSL2 ~2 GB RAM).
ENV CARGO_BUILD_JOBS=2

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
# Dummy main.rs lets cargo fetch and compile dependencies before copying real source.
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release --locked || true

COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

# Shared base for runtime and prebuilt-runtime targets.
FROM debian:trixie-slim AS base-runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libstdc++6 \
    libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENTRYPOINT ["ingester"]
CMD ["--help"]

FROM base-runtime AS runtime
COPY --from=builder /app/target/release/ingester /usr/local/bin/ingester

FROM debian:trixie-slim AS downloader
ARG INGESTER_VERSION
# TARGETARCH is set automatically by Docker BuildKit (amd64 / arm64).
ARG TARGETARCH

ARG CUSTOM_CA_CERT_BASE64
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN if [ -n "$CUSTOM_CA_CERT_BASE64" ]; then \
        printf '%s' "$CUSTOM_CA_CERT_BASE64" | base64 -d \
            > /usr/local/share/ca-certificates/custom-ca.crt \
        && update-ca-certificates; \
    fi
RUN test -n "$INGESTER_VERSION" || { echo "Error: INGESTER_VERSION build arg must be set"; exit 1; } \
    && case "$TARGETARCH" in \
        amd64) BINARY="ingester-x86_64-linux"  ;; \
        arm64) BINARY="ingester-aarch64-linux" ;; \
        *)     echo "Error: unsupported architecture: $TARGETARCH"; exit 1 ;; \
    esac \
    && BASE_URL="https://github.com/Yamato-Security/senrigan/releases/download/${INGESTER_VERSION}" \
    && curl -fsSL -o /tmp/${BINARY}          "${BASE_URL}/${BINARY}" \
    && curl -fsSL -o /tmp/${BINARY}.sha256   "${BASE_URL}/${BINARY}.sha256" \
    && (cd /tmp && sha256sum -c ${BINARY}.sha256) \
    && install -m 755 /tmp/${BINARY} /usr/local/bin/ingester \
    && rm /tmp/${BINARY} /tmp/${BINARY}.sha256

# prebuilt-runtime: uses the downloader binary; BuildKit skips the builder stage entirely.
FROM base-runtime AS prebuilt-runtime
COPY --from=downloader /usr/local/bin/ingester /usr/local/bin/ingester
