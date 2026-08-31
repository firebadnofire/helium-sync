CREATE TABLE sync_bases (
    server_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    local_key TEXT NOT NULL,
    snapshot_json BLOB NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (server_id, namespace, local_key)
);
