CREATE TABLE profile_archives (
    id TEXT PRIMARY KEY NOT NULL,
    directory_name TEXT NOT NULL UNIQUE,
    archive_directory TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) > 0),
    archived_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
