# dig-gossip fork of `native-tls` 0.2.18

Vendored from crates.io with an **OpenSSL-only** inbound change for **CON-009** (Chia-style mTLS).

See the `TlsAcceptor::new` block in `src/imp/openssl.rs` marked **dig-gossip vendor patch**. `chia_ca.crt` is copied from the matching `chia-ssl` release.

Platform notes: OpenSSL backend is used on Linux/Android; macOS (SecureTransport) and Windows (SChannel) paths are unchanged from upstream.
