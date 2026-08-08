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

## Platform scope

OpenSSL backend is used on Linux/Android; macOS (SecureTransport) and Windows (SChannel) paths are
unchanged from upstream — the fork touches ONLY the OpenSSL implementation.
