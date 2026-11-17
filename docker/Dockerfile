# Build the release CLI binary against musl for a fully static binary.
# TLS is rustls backed by AWS-LC-RS: its bindings are pregenerated for musl
# targets and the C sources build through the cc builder, so build-base
# (gcc + musl-dev) is the only extra requirement.
# The build context stays the repository root: run
# `docker build -f docker/Dockerfile .` from the checkout.
FROM rust:1-alpine AS builder

RUN apk add --no-cache build-base

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Cache mounts keep the dependency build across source-only changes; the binary
# is copied out of the private target mount in the same step. The release
# workflow passes ASTER_BUILD_REVISION so published images report the tag
# commit; the CLI build script accepts "unknown" or a 7-64 character
# hexadecimal revision, which is also the local-build default.
ARG ASTER_BUILD_REVISION=unknown
RUN --mount=type=cache,id=asteracme-cargo-registry,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=asteracme-cargo-target,sharing=private,target=/build/target \
    ASTER_BUILD_REVISION=${ASTER_BUILD_REVISION} cargo build --release --locked -p aster_acme_cli \
    && cp target/release/aster-acme /build/aster-acme

FROM alpine:3.24

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 aster \
    && adduser -S -D -H -u 10001 -G aster -s /sbin/nologin aster \
    && mkdir -p /data \
    && chown aster:aster /data

# `docker exec` bypasses ENTRYPOINT, so every top-level CLI subcommand is also
# exposed as a shim that prepends itself: `docker exec aster-acme version` and
# `docker exec aster-acme cert list` work like the acme.sh container. Keep this
# list in sync with the top-level `Command` enum in
# crates/aster_acme_cli/src/app.rs.
RUN for cmd in account cert daemon help provider version; do \
        printf '#!/bin/sh\nexec aster-acme %s "$@"\n' "$cmd" > "/usr/local/bin/$cmd" \
        && chmod 0755 "/usr/local/bin/$cmd" \
        || exit 1; \
    done

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
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh

USER aster
ENTRYPOINT ["entrypoint.sh"]
