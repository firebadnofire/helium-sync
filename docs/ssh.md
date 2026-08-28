# SSH transport

SSH mode authenticates using an OpenSSH private-key file and optional passphrase, opens `direct-streamlocal@openssh.com` to the configured remote Unix socket, and sends the ordinary authenticated HTTP/1.1 protocol inside that channel.

The client checks both system and app-owned known-host records. An unknown key produces a fingerprint that the user must verify through an independent trusted channel before confirming it. A changed key always fails closed; deleting known-host data is not a fix until the server key change is independently explained.

The SSH account needs no shell privilege beyond opening the socket. Give it membership in the socket's dedicated group, keep mode `0660`, and avoid root login. The server's bearer token is still required inside SSH.

Typical failures:

- Unknown key: compare the displayed SHA-256 fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on a trusted console.
- Changed key: stop, investigate the host or DNS/IP change, then deliberately update the known-host record.
- Stream-local denied: enable `AllowStreamLocalForwarding yes` for the account and verify socket group access.
- Missing socket: verify the server is running and the configured remote path is exact.
