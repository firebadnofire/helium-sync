# TLS

The server accepts TLS 1.3 only and has no plaintext TCP listener. HTTPS responses include `Strict-Transport-Security: max-age=31536000`.

Use a certificate issued by a trusted internal or public CA when possible. The private key and certificate must match, be currently valid, and include every hostname clients use. Run `helium-sync-server check` before restart; startup performs the same checks before binding either listener.

Client modes are:

- System trust for normal CA-issued certificates.
- Custom CA PEM for a private CA.
- Certificate/SPKI pinning: the supplied certificate becomes a trust anchor and its SPKI hash must match; normal hostname and validity checks still apply.

`http://`, hostname mismatch, expired/not-yet-valid certificates, untrusted chains, and pin mismatch are rejected. Do not fix these failures by disabling validation. Correct the URL/hostname, install the intended CA, renew the certificate, or confirm and configure the intended pin.
