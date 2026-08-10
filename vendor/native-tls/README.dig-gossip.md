# `native-tls` — the dig-gossip fork delta

Vendored via `[patch.crates-io]` in the workspace `Cargo.toml`. The tree is an unpacked
**crates.io `native-tls` 0.2.18** tarball, so the pristine crate of the same version is the exact
baseline and everything the diff reports is DIG's.

## Regenerate this delta — do not hand-maintain it

```sh
vendor/fork-delta.sh native-tls --summary   # the file list
vendor/fork-delta.sh native-tls             # the full unified diff
```

The compiler and the diff are the record; this file is a summary of them and must be regenerated
when either changes.

## What the fork changes — one file, one block

`--summary` reports exactly one differing file, `src/imp/openssl.rs`:

**`TlsAcceptor::new` OpenSSL initialization** — adds Chia-style mTLS setup (CON-009): loads
`chia_ca.crt` as the peer CA and sets the certificate verify mode to require a client certificate.
The patch block is marked **dig-gossip vendor patch**. See the comment at that site for detail.

`chia_ca.crt` is copied from the matching `chia-ssl` release (the Chia Network's vendored CA
bundle).

## Why upstream cannot replace this

`native-tls` is dig-gossip's **default** feature, and `connection::listener::native_tls_acceptor` is
compiled under `all(feature = "native-tls", not(feature = "rustls"))` — so a stock `cargo build` runs
through this patched acceptor. Upstream's `TlsAcceptorBuilder` exposes only `min_protocol_version`,
`max_protocol_version`, `accept_alpn` and `build`; it offers no way to request or require a client
certificate. Dropping the patch would therefore not fail to compile — it would silently accept inbound
peers presenting **no client certificate at all**, defeating CON-009 mTLS.

Only a consumer that opts out reaches a different path: dig-node takes dig-gossip with
`default-features = false, features = ["rustls", "relay"]` and uses the rustls inbound acceptor
instead.

## Platform scope

OpenSSL backend is used on Linux/Android; macOS (SecureTransport) and Windows (SChannel) paths are
unchanged from upstream — the fork touches ONLY the OpenSSL implementation.
