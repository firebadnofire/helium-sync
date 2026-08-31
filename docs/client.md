# Desktop client

The desktop client provides HTTPS and SSH sign-in, native secret storage, selectable and locally namable Helium profiles, a default profile, and encrypted bookmark Save/Load actions.

## Recommended sequence

1. Discover the local profiles on the Profiles screen and select one.
2. Rename it in Helium Sync if desired; this alias does not modify Helium's own profile metadata.
3. Choose **Use at sign-in** for the profile that should be synchronized automatically.
4. Open Connection, choose HTTPS or SSH, select the appropriate certificate/host-key verification, and enter the bearer token. The token is saved through the OS credential service, never the client SQLite database.
5. **Sign in and sync** saves the default profile the first time. Later sign-ins load its server copy.
6. Use **Save** to encrypt the selected local bookmarks to the server or **Load** to restore the saved copy. Load first creates a Zstandard-compressed ZIP backup in the operating system Downloads folder and only then replaces the local `Bookmarks` file.

The first run generates a 256-bit master key. Exporting an `hsync1:` recovery code is an explicit action. Store it like a password; anyone with it and server access can decrypt synchronized objects. Import the exact code on an additional trusted device.

Save reads the live profile. Load is the explicit write operation: close Helium first so it cannot race the replacement. Profile names, default selection, and server object mappings are stored in the client-local SQLite state. Authorization, passphrases, recovery codes, plaintext, and ciphertext bodies do not appear in diagnostics.
