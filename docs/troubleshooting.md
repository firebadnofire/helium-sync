# Troubleshooting

Always begin with `helium-sync-server check` using the same config/token source and service user as production.

| Failure | Verification and safe fix |
| --- | --- |
| Certificate/key | Check paths, dates, SAN hostname, and pair consistency; renew or mount the intended pair. Never disable validation. |
| Missing/wrong token | Confirm the service and client secret sources without printing them; rotate to a random 32+ character token if uncertain. |
| SSH host key | Compare the displayed fingerprint over a trusted channel. Unknown keys need explicit confirmation; changed keys require investigation. |
| Unix socket | Check that the path is a socket, server process owns it, mode is `0660`, and SSH user is in its group. The server refuses to replace a non-socket path. |
| Protocol incompatible | Upgrade the older client or server. Every route except `/v1/version` requires the negotiated protocol header. |
| Profile absent | Verify the Helium installation/user-data override and `Local State`; profile discovery reports installation and profile state separately. |
| Bookmarks busy | Close or pause Helium writes and retry. The reader detects metadata changes and never copies live databases. |
| Malformed bookmarks | Validate the `Bookmarks` JSON and node types; preserve the original and let Helium repair it. |
| Migration/database | Preserve the database, inspect permissions/disk space/log request ID, and restore a known backup if migration cannot complete. Do not edit migration metadata manually. |

Diagnostics and structured API errors include request IDs but redact authorization and content bodies.
