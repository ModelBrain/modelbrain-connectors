# Builds modelbrain_connectors as a musl binary in a small Alpine image.
# Built on the deploy box by infra/deploy.sh, the same way the relay is.

# syntax=docker/dockerfile:1
FROM rust:1-alpine AS builder
# gcc + musl-dev: rusqlite's bundled SQLite and ring (rustls) compile C.
RUN apk add --no-cache musl-dev gcc
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Two jobs keep peak memory low on the shared box.
RUN cargo build --release --locked -j 2

FROM alpine:3.20
# wget is only for the HEALTHCHECK below.
RUN apk add --no-cache wget \
 && adduser -D -H -s /sbin/nologin connector \
 && mkdir -p /data && chown connector /data
COPY --from=builder /build/target/release/modelbrain_connectors /usr/local/bin/modelbrain_connectors
USER connector
ENV BIND=0.0.0.0:8787 DB_PATH=/data/connectors.db
EXPOSE 8787
# A new named volume copies /data's ownership from the image, so the
# non-root user can write the database.
VOLUME ["/data"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8787/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/modelbrain_connectors"]
