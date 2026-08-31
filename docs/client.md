# Desktop client

The desktop client provides HTTPS and SSH sign-in, native secret storage, selectable and locally namable Helium profiles, and encrypted multi-device bookmark synchronization.

## Recommended sequence

1. Discover the local profiles on the Profiles screen and select one.
2. Rename it in Helium Sync if desired; this alias does not modify Helium's own profile metadata.
3. Choose **Use at sign-in** for the profile that should reconcile during sign-in.
4. Open Connection, choose HTTPS or SSH, select the appropriate certificate/host-key verification, and enter the bearer token. The token is saved through the OS credential service, never the client SQLite database.
5. **Sign in and sync** reconciles the default profile. On a new device, the client discovers an existing encrypted object for the same profile directory instead of creating an unrelated copy.
6. Leave **Automatic** enabled to reconcile the profile every 30 seconds while the desktop client remains open and signed in, or choose **Sync now**.
7. Use **Replace server copy** and **Restore server copy** under **Recovery** only for deliberate one-way recovery. A restore creates a Zstandard-compressed ZIP backup in Downloads before replacing local bookmarks.

The first run generates a 256-bit master key. Exporting an `hsync1:` recovery code is an explicit action. Store it like a password; anyone with it and server access can decrypt synchronized objects. Import the exact code on an additional trusted device.

Every trusted device must import the same recovery code before it can decrypt shared data. Profiles are matched by Helium profile-directory name, such as `Default` or `Profile 2`.

Local bookmark changes may upload while Helium is open. If a reconciliation would change the local `Bookmarks` file, Helium Sync requires Helium to be closed and returns an actionable error while it is running. This avoids Chromium overwriting an externally replaced file at exit.

Profile names, automatic-sync settings, default selection, server object mappings, and an encrypted three-way merge base are stored in client-local SQLite state. Authorization, passphrases, recovery codes, plaintext bookmark bases, and ciphertext bodies do not appear in diagnostics.

This release synchronizes bookmarks only. Open tabs, browsing history, passwords, extensions, and preferences require future browser integration.
