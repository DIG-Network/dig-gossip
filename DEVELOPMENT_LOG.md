# dig-gossip — Development Log

Durable, high-signal realizations (not a change diary).

## Inbound mTLS: `[patch.crates-io]` does not cross a git dependency (#1371)

- **Root cause of "strangers cannot connect on Linux" (#1062).** dig-gossip's inbound acceptor used
  `native_tls::TlsAcceptor`. The "require + capture the client cert" behaviour on OpenSSL/Linux lived
  in a **vendored `native-tls` fork** applied via `[patch.crates-io]`. A `[patch]` only applies to the
  crate that declares it — it does **not** propagate when dig-gossip is consumed as a *git*
  dependency. dig-node patches `chia-protocol` + `chia-sdk-client` (same git rev) but NOT `native-tls`,
  so the stock `native-tls` shipped, the server never sent a CertificateRequest, `peer_certificate()`
  returned `None` on OpenSSL, `peer_id` was underivable, and every inbound gossip connection was
  dropped. Windows (SChannel) / macOS (SecureTransport) masked it via the `peer_id_for_addr` fallback,
  which is why CI (and Windows dev) stayed green.
- **Fix = rustls inbound acceptor (Option A, CA-agnostic).** rustls configures the client-cert request
  in pure Rust (a custom `ClientCertVerifier`), so it needs no `[patch]` to propagate and behaves
  identically on every platform. The verifier **requests + requires + captures** the peer cert but
  does NOT validate a CA chain (DIG peers are self-signed / chia-ssl — a CA check would reject them);
  proof-of-possession is still enforced via the TLS CertificateVerify signature. `peer_id` reuses the
  shared `spki_der_from_leaf_cert_der` + `peer_id_from_tls_spki_der` helpers → byte-identical.
- **`MaybeTlsStream` is `#[non_exhaustive]` and only types the CLIENT rustls stream.** A server-side
  `tokio_rustls::server::TlsStream` cannot inhabit it, so `Peer::from_websocket` is unusable inbound.
  The vendored `chia-sdk-client` boxes `PeerInner`'s split sink/stream and exposes
  `Peer::from_server_websocket(ws, addr, opts)` (generic over the transport, `Peer` stays non-generic).
- **aws-lc-sys on Windows.** The rustls `aws_lc_rs` backend fails to C-compile in a deep worktree
  (CMake `tlog` path exceeds Windows MAX_PATH). Build/test the rustls features with a short
  `CARGO_TARGET_DIR` (e.g. `/c/t/...`); CI (Linux) is unaffected.

## Relay peer discovery + connect-leg (#870 / #924)

- **`connected_peers` root cause (#870).** dig-gossip's old ephemeral open→register→get_peers→close
  relay discovery reconnected every maintenance pass, so two nodes' sub-second registration windows
  never overlapped and neither appeared in the other's `get_peers` — `connected_peers` stuck at 0.
  Fix: read `dig-nat`'s ONE persistent-reservation `RelayStatus::known_peers()` instead.
- **B1 dialable fold (#924).** The relay OBSERVES each peer's reflexive address on registration but
  the reflexive source port is the outbound WebSocket's ephemeral port, NOT the gossip listener. So
  the node advertises its gossip `listen_addrs` in RLY-001 `Register`; the relay substitutes the
  observed reflexive IP for any unspecified/loopback/private advertised host (keeping the port) and
  returns it as `RelayPeerInfo.addresses`. dig-gossip folds a non-empty `addresses` into a
  `Via::Direct` dialable `PeerRecord` (IPv6-first) so it survives the dialable-only merge and the pool
  direct-dials it. Empty `addresses` = legacy identity-only `Via::Relay`.
- **Self-filter id-form trap (#924 round-3 finding 4).** A relay can echo this node's own `peer_id`
  in a different spelling than `Bytes32::Display` renders it (`hex::encode` = lowercase, no `0x`). A
  byte-exact self-compare then missed the match and counted self, inflating `relay_peer_count` by 1.
  Fix: normalize both sides (strip optional `0x`, lowercase) before comparing.
- **B2 relay-transport = a NatSlot (#924).** `dig-nat`'s `connect()` runs the whole traversal ladder;
  its last tier is the relayed transport (`TraversalKind::Relayed`, tunnelled through the relay's
  RLY-002 forwarder). A peer connected that way arrives as a `NatPeerConnection` and is adopted as a
  `NatSlot` — already counted in `connected_peers`. WU4 records the tier on the slot so it is tallied
  distinctly (`relay_transport_peer_count`) and reported `Via::Relay`.
- **NC-1 at the relay boundary.** The RLY-002 `payload` is an opaque `Vec<u8>` — dig-gossip never
  hands the relay structured plaintext. Directed-gossip payload sealing to the recipient key is NOT
  yet implemented in dig-gossip (the gossip-over-nat message loop lands with dig-node integration);
  the relayed route carries the SAME frame the direct nat path carries, so no plaintext-to-relay path
  exists to leak.
