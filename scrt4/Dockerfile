# scrt4 — Hardware-Bound Secret Manager
# Multi-stage build: Rust compile → minimal runtime image
#
# Build:   docker build -t scrt4 .
# Run:     docker run -it -v scrt4-vault:/home/scrt/.scrt4 scrt4 status
# Daemon:  docker run -d -v scrt4-vault:/home/scrt/.scrt4 --name scrt4 scrt4 daemon

# ── Stage 1: Build the Rust daemon ──────────────────────────────────
FROM rust:latest AS builder

WORKDIR /build/daemon
COPY daemon/Cargo.toml daemon/Cargo.lock ./
COPY daemon/src ./src

# Build release binary (strip debug symbols for smaller image)
RUN cargo build --release --bin scrt4-daemon \
    && strip /build/daemon/target/release/scrt4-daemon

# ── Stage 2: Runtime image ──────────────────────────────────────────
# Use the same Debian version as the Rust build stage to match glibc
FROM debian:trixie-slim

# System dependencies for CLI + daemon
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        curl \
        ca-certificates \
        jq \
        socat \
        python3-minimal \
        python3-cryptography \
        magic-wormhole \
        qrencode \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash scrt \
    && mkdir -p /home/scrt/.scrt4 \
    && chown -R scrt:scrt /home/scrt

# Copy daemon binary from builder
COPY --from=builder /build/daemon/target/release/scrt4-daemon /usr/local/bin/scrt4-daemon

# Copy CLI script
COPY daemon/bin/scrt4 /usr/local/bin/scrt4
RUN chmod +x /usr/local/bin/scrt4 /usr/local/bin/scrt4-daemon

# Set runtime directory for Unix socket
ENV XDG_RUNTIME_DIR=/tmp/scrt4-runtime
RUN mkdir -p /tmp/scrt4-runtime && chown scrt:scrt /tmp/scrt4-runtime

# Switch to non-root user
USER scrt
WORKDIR /home/scrt

# Vault data persists via volume
VOLUME /home/scrt/.scrt4

# Healthcheck via daemon socket
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD scrt4 status 2>/dev/null | grep -q "active" || exit 1

# Default: show help
ENTRYPOINT ["scrt4"]
CMD ["help"]
