# Desktop client

The client provides HTTPS and SSH connection forms, native secret storage, profile discovery, redacted diagnostics, a synthetic encrypted round trip, and a bookmark export verification.

## Recommended sequence

1. Choose HTTPS or SSH and enter non-secret connection fields.
2. Select system trust, a custom CA PEM, or an inspected certificate/SPKI pin for HTTPS.
3. Enter the bearer token; it is saved through the OS credential service, never the client SQLite database.
4. Connect and inspect every diagnostic stage.
5. Run the synthetic proof.
6. Refresh profiles, select one whose bookmarks are readable, and run bookmark verification.

The first run generates a 256-bit master key. Exporting an `hsync1:` recovery code is an explicit action. Store it like a password; anyone with it and server access can decrypt synchronized objects. Import the exact code on an additional trusted device.

Profile paths and state may appear in diagnostics, but authorization, passphrases, recovery codes, plaintext, and ciphertext bodies do not. No retrieved bookmark data is written to Helium.
