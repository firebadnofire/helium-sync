# syntax=docker/dockerfile:1
FROM rust:1.94-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p helium-sync-server

FROM debian:bookworm-slim AS runtime
RUN groupadd --system --gid 65532 helium-sync \
    && useradd --system --uid 65532 --gid helium-sync --home-dir /nonexistent --shell /usr/sbin/nologin helium-sync \
    && install -d -o helium-sync -g helium-sync -m 0750 /var/lib/helium-sync /run/helium-sync /opt/helium-sync/dev-tls
COPY --from=builder /src/target/release/helium-sync-server /usr/local/bin/helium-sync-server
RUN helium-sync-server generate-dev-cert \
      --output-dir /opt/helium-sync/dev-tls \
      --hostname localhost \
      --hostname 127.0.0.1 \
      --hostname helium-sync-server \
    && chown -R helium-sync:helium-sync /opt/helium-sync/dev-tls \
    && chmod 0444 /opt/helium-sync/dev-tls/server.crt \
    && chmod 0400 /opt/helium-sync/dev-tls/server.key

ENV HELIUM_SYNC_LISTEN=0.0.0.0:7500 \
    HELIUM_SYNC_DATA_DIR=/var/lib/helium-sync \
    HELIUM_SYNC_DATABASE=/var/lib/helium-sync/server.sqlite3 \
    HELIUM_SYNC_UNIX_SOCKET=/run/helium-sync/server.sock \
    HELIUM_SYNC_UNIX_SOCKET_MODE=0660 \
    HELIUM_SYNC_TLS_CERTIFICATE=/opt/helium-sync/dev-tls/server.crt \
    HELIUM_SYNC_TLS_PRIVATE_KEY=/opt/helium-sync/dev-tls/server.key

USER helium-sync:helium-sync
VOLUME ["/var/lib/helium-sync", "/run/helium-sync"]
EXPOSE 7500
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["helium-sync-server", "healthcheck"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["helium-sync-server"]
CMD ["serve"]
