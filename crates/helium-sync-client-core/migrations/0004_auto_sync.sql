ALTER TABLE profile_preferences
    ADD COLUMN auto_sync INTEGER NOT NULL DEFAULT 1 CHECK (auto_sync IN (0, 1));
