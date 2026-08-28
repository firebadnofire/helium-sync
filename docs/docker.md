# Docker deployment

The image is multi-stage, runs as UID/GID 65532, drops all Linux capabilities in Compose, and exposes only TLS port 7500. Its binary health check authenticates and validates TLS.

```sh
export HELIUM_SYNC_TOKEN=$(openssl rand -base64 48)
docker compose -f docker/compose.yml up --build
```

Set `HELIUM_SYNC_PORT` to remap the host port. The included certificate is self-signed, limited to development hostnames, and intentionally selected by Compose. Do not expose it as production trust. Mount a CA-issued certificate and key read-only and replace the two TLS environment paths.

The named runtime volume makes the Unix socket available to another container. Host SSH access requires a Linux bind mount at `/run/helium-sync`, group ownership matching `HELIUM_SYNC_UNIX_SOCKET_GROUP`, and membership of the SSH login user in that group. A Docker named volume alone does not expose the socket in the host filesystem.

Before using a host bind mount, create a dedicated group, add only the required SSH user, and set the directory group/mode. Never make the socket world-writable.
