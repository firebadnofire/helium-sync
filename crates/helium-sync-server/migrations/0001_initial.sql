PRAGMA foreign_keys = ON;

CREATE TABLE devices (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE objects (
    id TEXT PRIMARY KEY NOT NULL,
    namespace TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    cursor INTEGER NOT NULL CHECK (cursor > 0),
    device_id TEXT NOT NULL REFERENCES devices(id),
    modified_at TEXT NOT NULL,
    deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    envelope_json TEXT
);

CREATE TABLE changes (
    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    revision INTEGER NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    modified_at TEXT NOT NULL,
    deleted INTEGER NOT NULL CHECK (deleted IN (0, 1))
);

CREATE INDEX changes_object_id ON changes(object_id);
CREATE INDEX changes_namespace_cursor ON changes(namespace, cursor);
