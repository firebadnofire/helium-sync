# Desktop client

The desktop client provides HTTPS and SSH sign-in, native secret storage, MultiMC-style profile creation and launching, and encrypted multi-device synchronization for bookmarks, installed extensions, and extension-owned data.

## Recommended sequence

1. Close every Helium window. The first local profile is presented as **You**.
2. Choose **Add profile** to reserve the next Chromium `Profile N` directory, or rename an existing local alias. Aliases do not modify Helium's own profile metadata.
3. Choose **Launch** on a profile card to open Helium with exactly that `--profile-directory`. Close Helium before launching a different profile.
4. Choose **Archive** to move a closed-browser profile into Helium Sync's local archive area. An archived profile can be restored, or permanently deleted only from the archive after explicit confirmation.
5. Choose **Use at sign-in** for the profile that should reconcile during sign-in.
6. Open Connection, choose HTTPS or SSH, select the appropriate certificate/host-key verification, and enter the bearer token. After authentication succeeds, the complete versioned connection form is saved through the OS credential service, never the client SQLite database. Invalid attempts do not replace the last working settings.
7. **Sign in and sync** reconciles the default profile. On a new device, the client discovers existing encrypted objects for the same profile directory instead of creating unrelated copies.
8. Leave **Automatic** enabled to reconcile the profile every 30 seconds while Helium is closed and the desktop client remains signed in, or choose **Sync now**.
9. Use **Replace server copy** and **Restore server copy** under **Recovery** only for deliberate one-way recovery. A restore creates Zstandard-compressed ZIP backups in Downloads before replacing local data.

The first run generates a 256-bit master key. Exporting an `hsync1:` recovery code is an explicit action. Store it like a password; anyone with it and server access can decrypt synchronized objects. Import the exact code on an additional trusted device.

Every trusted device must import the same recovery code before it can decrypt shared data. Profiles are matched by Helium profile-directory name, such as `Default` or `Profile 2`.

Helium must be closed for create, launch, Save, Load, Sync Now, and sign-in reconciliation. This keeps bookmark and extension databases from changing during capture and prevents Chromium from overwriting restored files at exit.

On Linux, the client resolves the official `helium` launcher from `PATH`, then checks the Helium user-data singleton markers as well as running processes before mutation. AppImage or extracted-tar installations whose launcher is not on `PATH` must set `HELIUM_SYNC_HELIUM_PATH` to the executable. Windows and macOS standard installations are discovered automatically; the same override is available for nonstandard locations. SSH private-key paths beginning with `~/` are expanded against the operating-system home directory on every platform; macOS paths normally begin with `/Users/`, not `/User/`.

Extension snapshots include `Extensions`, Chromium extension-state/settings/rules/scripts directories, extension-owned IndexedDB directories, and only the `extensions` sections of `Preferences` and `Secure Preferences`. Website IndexedDB, unrelated preferences, passwords, history, tabs, and website storage are excluded. Symbolic links are rejected rather than followed.

Profile names, automatic-sync settings, default selection, server object mappings, and encrypted bookmark/extension bases are stored in client-local SQLite state. Extension archives are split into independently encrypted, SHA-256-verified chunks below the server's 4 MiB object limit. A new manifest is published only after every chunk is verified. Concurrent local and remote extension changes stop with an explicit recovery choice; they are never silently merged or overwritten.

Discovery can encounter objects left by another recovery key on the same server. Authentication failures from such unmapped candidates are skipped while searching for the requested profile; an already-mapped object that fails authentication still stops sync rather than being overwritten.
