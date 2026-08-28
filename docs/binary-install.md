# Binary installation

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
