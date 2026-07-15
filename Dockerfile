# syntax=docker/dockerfile:1.7
ARG RUST_VERSION=1.97.0

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home bridge

COPY --from=builder \
    /app/target/release/hikvision-unifi-fire-bridge \
    /usr/local/bin/hikvision-unifi-fire-bridge

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/hikvision-unifi-fire-bridge", "--healthcheck"]

LABEL org.opencontainers.image.title="hikvision-unifi-fire-bridge" \
      org.opencontainers.image.description="Bridge Hikvision ISAPI fire events into UniFi Protect Alarm Manager" \
      org.opencontainers.image.source="https://github.com/Gasmanc/hikvision-unifi-fire-bridge" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENTRYPOINT ["/usr/local/bin/hikvision-unifi-fire-bridge"]
