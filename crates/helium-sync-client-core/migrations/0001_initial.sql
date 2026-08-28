CREATE TABLE client_metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE server_cursors (
    server_id TEXT PRIMARY KEY NOT NULL,
    cursor INTEGER NOT NULL CHECK (cursor >= 0)
);

CREATE TABLE server_connections (
    server_id TEXT PRIMARY KEY NOT NULL,
    transport TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE object_mappings (
    server_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    local_key TEXT NOT NULL,
    object_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    PRIMARY KEY (server_id, namespace, local_key)
);
