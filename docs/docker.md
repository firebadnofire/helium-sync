# Docker deployment

Choose either Docker or the systemd installation for a host, not both. They use
independent token and database sources by default. A token from `docker/.env`
authenticates the Compose container only; it does not authenticate a separate
systemd service reading `/etc/helium-sync/token`.

The image is multi-stage, runs as UID/GID 65532, drops all Linux capabilities in Compose, and exposes only TLS port 7500. Its binary health check authenticates and validates TLS.

```sh
export HELIUM_SYNC_TOKEN=$(openssl rand -base64 48)
docker compose -f docker/compose.yml up --build
```

Set `HELIUM_SYNC_PORT` to remap the host port. The included certificate is self-signed, limited to development hostnames, and intentionally selected by Compose. Do not expose it as production trust. Mount a CA-issued certificate and key read-only and replace the two TLS environment paths.

The named runtime volume makes the Unix socket available to another container. Host SSH access requires a Linux bind mount at `/run/helium-sync`, group ownership matching `HELIUM_SYNC_UNIX_SOCKET_GROUP`, and membership of the SSH login user in that group. A Docker named volume alone does not expose the socket in the host filesystem.

Do not point an SSH client at a host socket owned by another Helium Sync
process. Verify ownership before selecting a token:

```sh
sudo ss -lxnp | grep /run/helium-sync/server.sock
sudo docker inspect helium-sync-server --format '{{range .Mounts}}{{.Type}} {{.Destination}}{{println}}{{end}}'
```

If Compose reports a named volume for `/run/helium-sync`, use HTTPS to the
Compose port or deliberately configure the documented host bind mount. Do not
reuse a systemd-owned host socket with the Docker token.

Before using a host bind mount, create a dedicated group, add only the required SSH user, and set the directory group/mode. Never make the socket world-writable.
