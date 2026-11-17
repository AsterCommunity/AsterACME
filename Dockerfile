# Build the release CLI binary against musl for a fully static binary.
# TLS is rustls backed by AWS-LC-RS: its bindings are pregenerated for musl
# targets and the C sources build through the cc builder, so build-base
# (gcc + musl-dev) is the only extra requirement.
FROM rust:1-alpine AS builder

RUN apk add --no-cache build-base

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Cache mounts keep the dependency build across source-only changes; the binary
# is copied out of the private target mount in the same step.
RUN --mount=type=cache,id=asteracme-cargo-registry,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=asteracme-cargo-target,sharing=private,target=/build/target \
    cargo build --release --locked -p aster_acme_cli \
    && cp target/release/aster-acme /build/aster-acme

FROM alpine:3.24

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 aster \
    && adduser -S -D -H -u 10001 -G aster -s /sbin/nologin aster \
    && mkdir -p /data \
    && chown aster:aster /data

LABEL maintainer="AptS:1547 <apts-1547@esaps.net>"
LABEL org.opencontainers.image.title="AsterACME"
LABEL org.opencontainers.image.description="Embeddable Rust ACME client and CLI for automated certificate issuance"
LABEL org.opencontainers.image.source="https://github.com/AsterCommunity/AsterACME"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

VOLUME ["/data"]
# Matches the CLI's documented storage flag (--data-dir); defaults all state to
# the mounted volume.
ENV ASTER_ACME_DATA_DIR=/data

COPY --from=builder /build/aster-acme /usr/local/bin/aster-acme
COPY --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh

USER aster
ENTRYPOINT ["entrypoint.sh"]
