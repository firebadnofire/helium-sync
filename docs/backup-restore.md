# Backup and restore

The server database contains opaque encrypted objects, device registrations, tombstones, and change cursors. It does not contain the master key or bearer token.

For a consistent backup, use SQLite's online backup command while the service runs:

```sh
sqlite3 /var/lib/helium-sync/server.sqlite3 ".backup '/secure-backup/server.sqlite3'"
```

Back up certificate configuration and the token through the secret-management system separately. Every client owner must separately protect the `hsync1:` recovery code; a server database backup cannot recover plaintext without it.

To restore, stop the service, preserve the current database as a rollback copy, place the restored database with service ownership and mode `0600`, run `helium-sync-server check`, then start the service. Never mix the restored main database with stale `-wal` or `-shm` files. Verify `/v1/status` and a client synthetic round trip before deleting the rollback copy.
