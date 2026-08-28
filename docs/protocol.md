# Protocol 1

All wire data is JSON. IDs are UUIDs, revisions and global change cursors are unsigned 64-bit integers, timestamps are UTC RFC 3339, and binary fields are unpadded base64url.

The client first authenticates `GET /v1/version`, intersects the advertised range with its supported range, and selects protocol 1. Every other call sends `x-helium-sync-protocol: 1`; unsupported/missing versions return a structured `426 protocol_incompatible` error.

Routes include status, devices, changes, object CRUD, and atomic batch mutation. New objects have no base revision. Updates and deletes require the exact current revision and transactionally create revision `base + 1`; conflicts return HTTP 409 and the current revision. Deletes retain tombstones. Change cursors are globally increasing SQLite row IDs.

Batches are atomic and limited to 100 operations. Request bodies are limited to approximately 4 MiB. Encrypted envelope v1 identifies its algorithm, key version, nonce, ciphertext, and authenticated metadata inputs. Bookmark canonical-format versioning remains inside encrypted client data; the server treats it as opaque.
