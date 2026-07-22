# dig-gossip — Development Log

Durable, high-signal realizations (not a change diary).

## Pool auto-dial dropped the discovered `peer_id` and never tried the relay circuit (#1517)

- **The two #1062 Leg-B blockers after #1422's SPKI dialer landed both lived HERE, in dig-gossip's
  pool auto-dial — NOT in dig-nat or dig-node.** dig-nat's `PeerTarget`/strategy API already accepts a
  pin and ranks the relay tier last; dig-node's DHT path threads `peer_id` correctly. The auto-dial
  that fed the pool (`HandleDialer` in `gossip_handle.rs`) was the drop point.
- **Defect 1 — all-zeros SPKI pin.** The relay introducer / dig-nat reservation resolves a peer's
  reflexive candidate ADDRESS *and* its `peer_id` together (RLY-005), and the `Via::Direct` fold
  (#924 B1) placed the address in the Chia address book. But the address book stores ONLY `host:port`
  (`TimestampedPeerInfo` has no id — node peer-exchange never carries one), so `gather_pool_candidates`
  rebuilt every candidate with `PoolCandidate::from_addr` → `peer_id: None`, and `HandleDialer` dialed
  with `PeerId::from([0u8; 32])`. The (now-working, #1422) mTLS verifier correctly rejected
  `expected 0000… got <real>`. **Fix:** a side map (address → `peer_id`) folded alongside the dialable
  record in `fold_relay_known_peers`, threaded into `PoolCandidate::with_id`. An address-only candidate
  (no discovered id) is now SKIPPED rather than dialed with a guaranteed-reject zero pin.
- **Defect 2 — no relay-circuit fallback.** `HandleDialer` enabled `&[TraversalKind::Direct]` and dialed
  via `dig_nat::connect` (a DEFAULT `NatRuntime` with no relay dialer), so even had Relayed been enabled
  the tier would be composed-away. After Direct failed the strategy logged `falling through kind=Direct`
  and stopped. **Fix:** dial the full ladder (`pool_auto_dial_traversal_methods`) via
  `connect_with_runtime` over a `NatRuntime` built from the attached reservation `RelayStatus`
  (`ReservationRelayedTransport`) + local port, so the relay circuit is actually attempted.
- **Cascade note.** No dig-nat change was needed. Bumping the dig-nat dep 0.8→0.10 (to get #1422's SPKI
  dialer + the runtime/relay API) also required bumping the dig-tls dep 0.1→0.3 — dig-nat 0.10 exposes
  `dig_nat::NodeCert = dig_tls 0.3 NodeCert`, so a stale dig-tls 0.1 pin caused a "multiple versions of
  dig_tls" type mismatch on `nat_node_cert()`.
- **Local build gotcha (Windows).** dig-nat pulls rustls → aws-lc-sys, whose CMake build fails under
  MSBuild's file-tracker (MSB6003) in a bare shell. Build with a VS dev env + `CMAKE_GENERATOR=Ninja`
  (delete a stale `target/debug/build/aws-lc-sys-*` CMakeCache first, since it records the prior
  generator) and NASM on PATH.

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
