# Binary installation

Choose either this systemd installation or Docker Compose for a host, not both.
The systemd Unix socket and HTTPS listener must be served by the same process,
and clients using `/run/helium-sync/server.sock` must use the token stored in
`/etc/helium-sync/token`, not a token from `docker/.env`.

Build the Linux server with `cargo build --locked --release -p helium-sync-server`, install it as `/usr/local/bin/helium-sync-server`, and create a locked `helium-sync` system user/group.

Install [the sample configuration](../config/server.example.toml) at `/etc/helium-sync/server.toml`, the bearer token at `/etc/helium-sync/token` mode `0400`, and certificate/key material under `/etc/helium-sync/tls`. The private key should be readable only by the service account.

Copy [the systemd unit](../contrib/systemd/helium-sync-server.service), then validate before enabling:

```sh
sudo -u helium-sync /usr/local/bin/helium-sync-server check \
  --config /etc/helium-sync/server.toml \
  --token-file /etc/helium-sync/token
sudo systemctl daemon-reload
sudo systemctl enable --now helium-sync-server
```

The unit creates state/runtime directories, grants no capabilities, uses `NoNewPrivileges`, and restricts networking to IPv4, IPv6, and Unix sockets.

Verify that one PID owns both listeners after startup:

```sh
systemctl show helium-sync-server -p MainPID
sudo ss -ltnp 'sport = :7500'
sudo ss -lxnp | grep /run/helium-sync/server.sock
```
