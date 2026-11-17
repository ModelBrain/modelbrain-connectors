FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release --locked || cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data connector \
 && mkdir -p /data && chown connector /data
COPY --from=build /src/target/release/modelbrain_connectors /usr/local/bin/modelbrain_connectors
USER connector
ENV BIND=0.0.0.0:8787 DB_PATH=/data/connectors.db
EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s CMD ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8787 || exit 1"]
ENTRYPOINT ["/usr/local/bin/modelbrain_connectors"]
