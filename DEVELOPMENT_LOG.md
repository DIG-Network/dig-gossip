# dig-gossip — Development Log

Durable, high-signal realizations (not a change diary).

## tungstenite's 64 MiB default message cap sits ABOVE every app cap — bound it at the transport (#10)

`tokio_tungstenite::accept_async` / `connect_async_tls_with_config(_, None, ..)` use tungstenite's
DEFAULT `WebSocketConfig`: `max_message_size = 64 MiB`, `max_frame_size = 16 MiB`. Both of DIG's
application caps are SMALLER — the reassembler's per-stream buffer (`MAX_BUFFERED_BYTES` = 4 MiB)
and the dig-message envelope ceiling (~16 MiB) — and they only apply AFTER tungstenite has already
buffered the whole message. So a hostile peer could make the transport allocate up to 64 MiB per
message before any app-level cap said no. Fix: one shared `connection::ws_config()` with
`max_message_size = 32 MiB` / `max_frame_size = 16 MiB`, wired into ALL FOUR handshake sites (two
inbound `accept_async_with_config`, the outbound peer dial `connect_async_tls_with_config`, and the
relay-discovery dial `nat::discovery::relay_get_peers` `connect_async_with_config` — the last is the
highest-risk since the relay is explicitly untrusted, and it was easy to miss because it lives
outside the `connection` module). Note tungstenite
0.24's `WebSocketConfig` is NOT `#[non_exhaustive]` (a later version is), so `WebSocketConfig {
max_message_size: .., max_frame_size: .., ..Default::default() }` is the clippy-clean constructor —
avoids `field_reassign_with_default`. A socket-level "send an over-cap message" test cannot
DETERMINISTICALLY isolate a transport-layer rejection from an application-layer one (both surface
to the client as a connection close), so the regression is pinned by asserting the bounded-cap
contract (`ws_config()` values + exported consts bounded below 64 MiB, above the 4 MiB app cap).

## The per-message WS cap is bounded in aggregate by the accept-loop admission gates — tighten it anyway (#34)

The #10 residual note ('32 MiB × N concurrent = no aggregate ceiling') is stale. Inbound concurrency is bounded
by TWO accept-loop gates: `max_connections` (default 50, `listener.rs` registered-peer cap) and the audit-#179
`max_inflight_handshakes` Semaphore (default 200, permit taken BEFORE the handshake task spawns, `listener.rs`),
so the aggregate in-flight WS-buffer ceiling was already bounded at `(50+200) × 32 MiB ≈ 8 GiB` — not unbounded.
#34 tightened `WS_MAX_MESSAGE_BYTES` 32→8 MiB (and frame 16→8 MiB), still 2× the 4 MiB `MAX_BUFFERED_BYTES`
legit-payload ceiling, cutting the aggregate 4× → ≈ 2 GiB with zero effect on legit traffic. Lesson: a 'no
aggregate bound' worry on a per-connection cap is only real if concurrent-connection count is itself unbounded —
check the accept-loop admission gates first.

## Where the REAL outbound dialer lives — `parallel_connect_batch` was never it (#1715)

- `node_discovery::parallel_connect_batch` (a DSC-009 "Phase 3" stub) was removed in v0.17.6: it never
  dialed anything — it selected address-manager candidates and FAKED `ConnectResult::Success`, calling
  `mark_good()` directly. No production code ever called it (only its own DSC-009/PRF-004 tests did).
- The LIVE outbound auto-dialer is the pool-maintenance path: pool maintenance → `HandleDialer::dial`
  → `connect_via_nat_full_ladder` → `adopt_nat_connection` (with the INT-006/007 diversity caps and the
  relayed-tier bound, see #1710/#1716). Manual dials go through `GossipHandle::connect_to` →
  `connection::outbound::connect_outbound_peer` (CON-001). Parallel/batched outbound (DSC-009) remains a
  future roadmap item with no code — do NOT resurrect the simulation stub as if it were the dialer.

## The /16+AS eclipse cap is meaningless on the RELAYED tier — exempt it, bound the tier instead (#1716)

- The v0.17.4 diversity gate keyed INT-006(/16) + INT-007(AS) on `conn.remote_addr()`. For a RELAYED
  `dig-nat` link that address is the RELAY ENDPOINT (dig-nat by design — the mTLS session runs over the
  relay), NOT the peer's own routable address (a NAT'd peer has none). So the cap gave ZERO eclipse
  value on that tier (all relayed peers share the relay's /16) while doing two kinds of harm: every
  relayed peer collapsed into ONE /16 group → at most ONE relayed outbound peer could be adopted (a
  self-throttle that strands NAT'd nodes on a single relayed link), AND a relayed slot's relay-IP group
  wrongly BLOCKED a direct candidate that happened to share the relay's /16.
- Fix (#1716): relayed adoptions are EXEMPT from the /16//AS cap — `outbound_diversity_conflict` takes a
  `candidate_is_relayed` flag and returns `None` for it, and the occupancy scan excludes relayed slots
  (`is_relayed` = `PeerSlot::Nat(n)` with `n.method == TraversalKind::Relayed`) so a relayed slot no
  longer counts against any group. The cap still fully applies to Direct/UPnP/NAT-PMP/PCP/HolePunch
  (real remotes).
- But a wholly-ungated relayed tier is a Sybil-flood window (relay reservations are cheap), so the tier
  gets its OWN bound: `max_relayed_outbound = target_outbound_count − max(target_outbound_count/4, 1)`
  (mirrors the #870 direct-floor derivation → 6 with the default target of 8), enforced in
  `adopt_nat_connection` under the SAME `peers`-lock hold as the insert (atomic, no TOCTOU). It reserves
  ≥2 outbound slots for the diversity-checked non-relayed tier. Rejection code: INT-006a.

## The outbound /16+AS eclipse cap must gate the AUTO-POOL adoption path, not only manual connect_to (#1710)

- The INT-006 (/16) + INT-007 (AS) outbound diversity caps shipped in v0.17.2 were enforced ONLY in
  `connect_to` (the operator-initiated dial). The live auto-peering path — pool maintenance →
  `HandleDialer::dial` → `connect_via_nat_full_ladder` → `adopt_nat_connection` — inserted peers with
  only self/ban/duplicate-`peer_id`/max_connections checks, silently skipping the caps. That auto path
  is the ACTUAL attacker-influenceable surface (its candidates come from `RespondPeers`), so gating only
  the manual dial left the eclipse caps trivially bypassable.
- Fix: `adopt_nat_connection` calls the SAME `outbound_diversity_conflict` gate under the same held
  `peers` lock, immediately before the insert (check→insert atomic, no TOCTOU).
- Key asymmetry vs `connect_to`: adoption is ALWAYS net-new occupancy, so the gate is UNCONDITIONAL
  there — no reconnect-exemption branch. `adopt_nat_connection` already refuses a duplicate `peer_id`
  outright (returns `DuplicateConnection` before the gate), so every connection that reaches the gate is
  a net-new identity. The reconnect exemption exists only in `connect_to`, which may re-dial an endpoint
  whose stale slot survives a dropped link (#1703).

## IPv4-mapped IPv6 must be canonicalized BEFORE subnet/AS grouping, or the /16 eclipse cap is dodgeable (#1709)

- `subnet_group` keys IPv6 by its first 4 bytes. An IPv4-mapped IPv6 address `::ffff:a.b.c.d` has
  zero first-four-bytes, so it collapses to group `0` and does NOT collide with the plain-v4 `a.b`
  /16 group of the SAME routable network — a theoretical dodge of the map-derived one-outbound-per-/16
  cap (INT-006, shipped v0.17.2). The AS classifier has the same seam: `ip_in_prefix`'s `(V6, V4)`
  mismatch arm returns false, so a mapped-v6 fails open as unknown against v4 BGP prefixes (INT-007).
- Fix: `util::ip_address::canonical_ip` folds `::ffff:a.b.c.d` → IPv4 (via `Ipv6Addr::to_ipv4_mapped`,
  NOT `to_ipv4` which would also fold deprecated v4-compatible `::a.b.c.d`) before both group/AS keys.
  Genuine IPv6 is untouched and still groups by /32 (§5.2 IPv6-first). One helper, reused by both paths.

## The self-connection guard must cover the OUTBOUND pool-add path, not just inbound (#1584)

- **The read-leg DATA 404 root cause.** A reader's peer pool held a SELF-ENTRY — its own
  `peer_id` @ its own external IP as an outbound peer — injected by a relay introducer advertising the
  node to itself. It was fed (via `PoolEvent::PeerAdded`, #1581) to the DHT routing table + peer
  selector as a provider, so the reader "discovered" itself, self-dialed on a `/s` content read, and
  dead-ended (`Direct` → connection refused to own IP; `Relayed` → "refusing relayed self-dial") →
  HTTP 404, never reaching the real holder.
- **Asymmetric guard was the bug.** `precheck_inbound_peer` rejected inbound self-connections
  (`peer_id == config.peer_id`), but the two OUTBOUND pool-add sites — `connect_to` (direct WSS) and
  `adopt_nat_connection` (dig-nat ladder) — guarded banned/duplicate/max but NOT self. The outbound
  half adopted self while the inbound half rejected it.
- **Address-based self-dial guard is insufficient.** `connect_to`'s `dial_targets_local_listen`
  only catches a dial to the node's OWN listen address (`[::]:port`); a relay introducer advertises the
  node at its EXTERNAL IP, which slips past it. The reliable guard is by verified `peer_id`.
- **The fix (both paths, mirrors the inbound guard):** reject `peer_id == config.peer_id` with
  `GossipError::SelfConnection` in `connect_to` (post-handshake, before pool insert / publish) and in
  `adopt_nat_connection` (before pool insert / publish). Prevents self ever entering the pool or being
  published as `PeerAdded`. dig-node should ALSO belt-and-suspenders filter local `peer_id` in its
  capsule-pull provider selection.

## The dig-nat transport identity must be the node's PERSISTENT NodeCert, not ephemeral (#1541 / #1532 Defect 1b)

- **ONE identity across ALL transports is a hard contract.** A node advertises/registers/pins ONE
  `peer_id = SHA-256(SPKI DER)`. Both transports must present it: the chia-ssl WebSocket path (`:9444`
  peer-RPC + `:9445` direct-gossip) AND the unified `dig-nat`/`DigPeer` NAT-traversal path (Leg B — the
  relayed / hole-punched connect ladder). If they differ, a remote pinning the advertised id gets
  `peer_id mismatch` on whichever transport carries the wrong identity.
- **The bug:** `ServiceState::nat_node_cert` minted a RANDOM EPHEMERAL `NodeCert` per construction
  (a per-boot BLS seed), documented distinct-from-advertised 'until #908'. dig-node injected its
  persistent NodeCert ONLY into the chia-ssl `cert_path`, never the dig-nat path — so every
  NAT/relay-traversed connection presented a different, per-boot id. That is the #1532 Leg-B blocker,
  on the exact transport the #1062 / #836 connect flywheel relies on.
- **The fix:** `GossipConfig::nat_identity: Option<Arc<dig_tls::NodeCert>>`. When `Some`,
  `nat_node_cert` resolves to THAT identity (cached); the ephemeral mint remains ONLY as the fallback
  for tests / identity-less services. Every real `dig-node` MUST inject. `NodeCert` deliberately does
  not derive `Clone` (private key in `Zeroizing`), so the field is `Arc`-wrapped to keep
  `GossipConfig: Clone`.
- **Release-first cascade:** dig-gossip ships the injection API first; dig-node then wires its
  persistent NodeCert through `nat_identity` + rev-bumps. This + dig-nat responder/glare + dig-node
  chia-ssl unification = the complete Leg-B fix.

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

## A restarted peer could never reconnect — newest-wins over a stale inbound slot (#1691)

- **Symptom.** After a peer restarted (upgrade/crash/service bounce) it redialed with the SAME
  `peer_id` (= `SHA-256(TLS SPKI DER)`, bound to its DIG identity) and was refused; every read it then
  attempted 404'd. Seen live on the #1640 step-4a EC2 fleet — the holder had the content, had served it
  2 min earlier, both nodes up; only the reader had restarted.
- **Root cause.** `precheck_inbound_peer` (src/connection/listener.rs) rejected any inbound session on
  a bare `peers.contains_key(peer_id)` with NO liveness check and NO reap. dig-gossip never removes a
  peer-map slot when the connection drops — the inbound forwarder task in `negotiate_inbound_over_ws`
  just ends when `inbound_rx` closes; it does not touch `peers`. So the stale slot lingered and blocked
  the reconnect.
- **No per-slot liveness signal exists to consult — but keepalive IS on by default.** `PeerSlot`/
  `LiveSlot` carry no `last_seen` timestamp, and the CON-004 keepalive REMOVES a slot on failure rather
  than stamping freshness on it — so "reap-then-check" has nothing to read → the fix is **newest-wins
  gated on the mTLS-proven identity**. IMPORTANT correction (an earlier draft of this fix claimed
  keepalive was "off by default" — FALSE): `keepalive_loop` does `.unwrap_or(PING_INTERVAL_SECS)` /
  `.unwrap_or(PEER_TIMEOUT_SECS)` (keepalive.rs), so `keepalive_*_secs = None` means production runs the
  keepalive at 30 s ping / 90 s timeout, and `spawn_keepalive_task` runs unconditionally per connection.
- **Why newest-wins is safe.** `peer_id` at the guard is derived from the COMPLETED, verified mTLS
  handshake (the rustls/native-tls acceptor requests+requires+captures the client cert, then SPKI→hash;
  see the #1371 entry). Only the holder of that identity's private key can complete the handshake, so
  no third party can reach the supersede path for an identity it does not own. And `HashMap::insert`
  replaces (one slot per `peer_id`), so the map stays bounded under reconnect churn.
- **The landing trap — ghost keepalive re-introduced #1691 as a timed race.** Because keepalive is
  always on, superseding S1 with S2 while leaving S1's keepalive task L1 running is a bug: ≤30 s later
  L1's probe on the dead S1 fails and `disconnect_after_keepalive_failure` did a **blind
  `peers.remove(peer_id)`** — which removes S2 (the reconnect), emptying `map[P]` and 404'ing the
  reader again. The first draft (close-socket only, no keepalive teardown) passed its <200 ms tests but
  would have failed in production at the 30 s tick.
- **The robust fix — abort + session generations (compare-and-remove).** (1) `LiveSlot` gains a
  `keepalive_task: AbortHandle`; the supersede path (and every Live-slot removal: ban-disconnect,
  handle `disconnect`, service `stop`) `.abort()`s it so the stale keepalive stops immediately. (2)
  `LiveSlot` gains a monotonic `generation` drawn from `ServiceState::next_peer_generation()` at
  insert; the keepalive task carries its generation and `disconnect_after_keepalive_failure` is now a
  **compare-and-remove** — it only removes/closes when `map[peer_id]` is `Live` with the SAME
  generation. A stale task therefore no-ops against a newer slot even if its abort is missed/races. The
  generation guard is the load-bearing invariant; the abort is the prompt first line of defence.
- **Ordering gotcha — spawn keepalive BEFORE inserting the slot.** The slot must own the keepalive
  `AbortHandle`, but the handle only exists after `tokio::spawn`. Spawn first (the loop sleeps a full
  interval before its first probe, so it cannot touch the map before the insert lands), capture the
  `AbortHandle`, then build+insert the `LiveSlot` with it. Applied at both insert sites (inbound
  `negotiate_inbound_over_ws`, outbound `connect_to`).
- **Gotcha — std `MutexGuard` is not `Send`.** The inbound future is `tokio::spawn`ed, so it must be
  `Send`. Closing the displaced peer is an `.await`; scope the `peers` guard in a `{ … }` block that
  returns the superseded slot (an explicit `drop(peers)` before the await did NOT satisfy the auto-Send
  analysis — the block scope did).

## Outbound reconnect symmetry — the coupled diversity-filter self-block (#1703, mirror of #1691)

- The DuplicateConnection reject was NOT the only thing blocking an outbound re-dial. `connect_to` has
  TWO stale-slot blockers, and both fire before the newest-wins insert can supersede: (1) the
  pre-dial address-level `DuplicateConnection` reject, and (2) the INT-006 /16 + INT-007 AS diversity
  filters. On a dropped outbound link the stale slot survives AND its /16+AS stay registered in the
  filters (an abrupt drop never calls `remove_outbound`), so even after removing the duplicate reject a
  same-`/16` re-dial (e.g. any loopback re-dial — `subnet_group(127.0.0.1)` has no bypass) is refused
  with `ConnectionFiltered`. Fixing only the duplicate reject leaves outbound reconnect still broken in
  production. The two are the SAME stale-slot root; both must be handled for item 1 to actually work.
- ECLIPSE-ADMISSION TRAP (caught by the adversarial+security gate — the address heuristic is unsafe):
  a first attempt keyed the diversity bypass on address (`peers.values().any(|s| s.remote()==addr)`).
  That is exploitable. The outbound diversity budget is populated ONLY by outbound `add_outbound`; an
  INBOUND Live slot or a Nat slot (whose `remote` comes from attacker-influenced `RespondPeers`) sits
  in the peer map at an address WITHOUT consuming that budget. So "a slot exists at addr" does NOT imply
  "addr already consumes a diversity slot": with an outbound already filling /16 5.6, a Nat slot at
  5.6.7.8, a dial to 5.6.7.8 would be treated as a reconnect, bypass INT-006, handshake to a NET-NEW
  peer_id, and `insert` a SECOND outbound Live in /16 5.6 (supersedes nothing) — exceeding
  one-per-/16//AS and widening an eclipse. Restricting to `is_outbound() && remote()==addr` is ALSO
  insufficient (different-peer_id-same-address still inserts a net-new key → map growth + 2 outbound).
- CORRECT FIX (verified-identity gate): decide diversity on the POST-handshake verified `peer_id`, not
  the pre-handshake address. After the handshake, `is_outbound_reconnect =
  matches!(peers.get(&peer_id), Some(s) if s.is_outbound())`. If NOT an outbound reconnect (net-new
  identity, or an admission replacing a non-outbound slot at that address) → net-new outbound occupancy
  → enforce INT-006/INT-007 against the current outbound budget, else close the stream + return the
  same `ConnectionFiltered` error. If it IS an outbound reconnect → its group/AS is already counted →
  skip the check and supersede. The pre-handshake path keeps ONLY the max_connections check.
- SET-vs-MAP UNDER-COUNT TRAP (caught by the full trio re-gate — the round-4 `remove_outbound` fix was
  itself unsafe): the `SubnetGroupFilter`/`AsDiversityFilter` were refcount-free `HashSet`s. Round-4
  added `remove_outbound`-on-supersede to release a vacated group; but a plain set has no refcount, so
  removing a group entry when ANOTHER live outbound still occupies it UNDER-COUNTS — the set reports the
  group free while the map still holds an outbound there, and a later net-new dial is wrongly admitted =
  2 outbound in one /16 (the exact INT-006 cap). Exploit needs only `connect_to`s: P1→G_a, P2→G_b;
  redial P1→G_b (reconnect, gate skipped; `remove_outbound(G_a)`+`add_outbound(G_b)`); redial P2→G_c
  (`remove_outbound(G_b)` but P1 still in G_b!) → set loses G_b → net-new R dials G_b → admitted.
- FINAL FIX (single source of truth = the peer map): DELETE the side-set occupancy entirely
  (`SubnetGroupFilter`, `AsDiversityFilter`, the `subnet_filter`/`as_filter` `ServiceState` fields, and
  all `add_outbound`/`remove_outbound`/`is_allowed` calls in `connect_to`+`disconnect`). Derive
  occupancy on demand from `peers`: `state::outbound_diversity_conflict(peers, as_table, new_peer_id,
  candidate_ip)` scans OUTBOUND slots (excluding `new_peer_id`) for a same-`/16` (INT-006) or same-AS
  (INT-007) occupant. Keep only an immutable `as_table: AsLookupTable` on `ServiceState` for AS
  classification (empty by default → AS fails open, same as before). The check + insert run under ONE
  `peers`-lock hold so the check→insert is atomic (closes the concurrent-net-new-dial TOCTOU). Inserting
  / removing map slots IS the accounting — no bookkeeping on admit/supersede/disconnect. A refcount-free
  parallel set of a map's contents is an anti-pattern for security-critical caps: derive, don't mirror.
- DEFERRED (#1703 item 2): a same-`peer_id` outbound reconnect that MOVES into a DIFFERENT already-
  occupied group is not re-refused (a single verified identity reconnecting is not an eclipse-widening
  distinct identity, and map-derived accounting means a same-identity migration can't corrupt what a
  later net-new dial sees); reconciled by the departed-peer reaper.
- The `SubnetGroupFilter`/`AsDiversityFilter` structs' old unit tests (dsc_010/dsc_011/int_006/int_007)
  were repointed to the retained pure classifiers (`subnet_group`, `AsLookupTable::lookup`); the
  end-to-end map-derived enforcement is covered in `con_1703_outbound_reconnect_tests`.
- Max-connections stays ALWAYS enforced (pre-handshake, never bypassed): a supersede replaces a slot,
  so at capacity a reconnect whose stale slot occupies the last slot returns `MaxConnectionsReached` —
  acceptable; the departed-peer reaper (#1703 item 2) is the complement.
- The outbound insert ALREADY carried the #1691 generation + keepalive-AbortHandle wiring (added
  defensively by the #1691 lane), so no new generation plumbing was needed — the same
  `disconnect_after_keepalive_failure` / `apply_inbound_rate_limit_violation` compare-and-remove guards
  cover the outbound-inserted slot (same `peers` map, same `LiveSlot`). This lane only had to remove
  the two rejects and make the insert-supersede the primary path.
- Test note: restarting a `GossipService` "server" at the same `listen_addr` flakes with EADDRINUSE
  (os error 98) — the accepted inbound socket sits in TIME_WAIT on the listen port and the service does
  not set `SO_REUSEADDR`. The deterministic re-dial-to-a-live-server tests drive the identical guard
  (the surviving stale slot is indistinguishable at `connect_to` from a dropped-link slot), so a
  server-restart test adds no coverage — dropped for reliability.

<!-- #34: transport memory-ceiling hardening (tighten WS message cap 32->8 MiB; document the two-gate aggregate bound). Filled in by the harden lane. -->

- **#36 — transport Capacity rejection is classified, not socket-tested.** A socket-level "send an
  over-cap message" test cannot deterministically isolate a TRANSPORT-layer rejection from an
  APP-layer one — both surface to the client as a connection close, so the assertion passes even
  without the cap. The load-bearing fact is instead the *classification*: `ws_err` (listener.rs)
  branches on `is_transport_capacity_rejection` (matches tungstenite `Error::Capacity(_)`) to emit a
  distinct `warn!` naming `WS_MAX_MESSAGE_BYTES`/#10, and a deterministic unit test constructs the
  synthetic `Error::Capacity(CapacityError::MessageTooLong { size, max_size })` (a struct variant in
  tungstenite 0.24) and asserts it classifies while `AlreadyClosed`/`Io` do not. `ClientError` lives
  in the external `dig_peer_protocol` crate (no WS variant, cross-crate blast radius), so the
  classifier route keeps the return type `ClientError::Io` unchanged rather than adding an enum arm.

- **#9 — the pool-candidate intersection flake was randomized bucket-key COLLISION, not socket
  contention.** `gathered_pool_candidates_respect_local_stack_intersection` (+ its two siblings)
  intermittently failed at `assert_eq!(stats().known_addresses, seeded.len())` under full-parallel
  `cargo test`. The suspected cause (real-listener/accept-loop lifecycle contention) was a red
  herring: `test_gossip_config` sets `peer_pool: None` + empty DNS introducers, so `start()` spawns
  only the accept loop and NOTHING mutates the address book after seeding — the count assertion is
  not a background-loop race. The actual mechanism: `AddressManager` seeds its bucket-hash `key` from
  `rand::thread_rng().fill_bytes` (Chia `randbits(256)`), so new-table bucket placement is random per
  instance; with a small fixture set two seeded addresses occasionally hash to the same
  `(bucket, position)` slot and the later one evicts the earlier, so `size()` returns N-1. It looked
  "parallel-only" purely because a full run re-executes the test many times with fresh RNG states,
  surfacing the ~1-in-4 unlucky key. Fix (hermetic, non-masking): (1) a `#[doc(hidden)]`
  `AddressManager::__set_fixed_bucket_key_for_tests` pins a fixed key from
  `__seed_address_book_for_tests` BEFORE the first add, making seeding collision-free + reproducible
  so every exact-count assertion stays valid; (2) the three tests now exercise the seed +
  injected-stack gather over a `GossipService::__handle_without_start_for_tests()` handle instead of
  `start()`/`stop()`, binding no loopback socket and spawning no task (defense-in-depth: removes the
  unnecessary real-socket ceremony too). Verified: 25/25 green at `--test-threads=16` (was flaky
  ~1-in-4 before). Note: bucket collision is CORRECT Chia address-book behaviour under a random key —
  the bug was the test assuming a random-keyed seed of N addresses always retains exactly N.

- **CON-005 / #1720 — opcode 222 (HoldingsAnnounce) inbound rate-limit row.** 222 is reachable by any
  internet host (`rustls_inbound.rs` accepts any self-signed cert) and its P-256 signature verify
  (`verify_holdings_announce`) runs on the DECODED frame — so the expensive work was bounded only by
  the accidental `default_settings` fall-through (100 frames/min, 1 MiB) because it had no `dig_wire`
  row. Added a deliberate row: `RateLimit::new(20.0, 131_072.0, None)`. Sizing arithmetic (from the
  actual `HoldingsAnnounce::encode`): a legit full `MAX_CHANGES`=256 re-announce, each key served at a
  fat 4-address candidate set with 64-byte hosts, encodes to per-Add `1+32+2 + 4×(2+64+2) + 8 = 315`
  bytes → `256×315 = 80 640` + ~280 B framing (`peer_id 66 + spki 122 + seq 8 + announced_at 8 +
  change_count 2 + sig 74`) ≈ **79 KiB**. So `max_size = 128 KiB` leaves >60% headroom and NEVER clips
  a real provider's full-holdings frame (which would break the discovery flywheel), yet is 8× tighter
  than the 1 MiB default. `frequency = 20`/min is ~2× the 221 (STORE_MELTED) anchor of 10/min: a
  provider re-announces its WHOLE holdings in one frame so steady-state cadence is minutes apart; 20/min
  covers legit bursts (a 0→N peer transition plus a cluster of holdings-change events) while capping a
  hostile connection at 20 signature verifies/min (vs 100 under the default). This row mirrors the
  #1316 STORE_MELTED (221) precedent.
- **CON-005 / #1720 (follow-up) — the 221/222 rows were a NO-OP on the live wire; now enforced via a
  combined gate.** Enforcement-gap finding: the live inbound forwarders
  (`connection/listener.rs`, `service/gossip_handle.rs`) called ONLY `RateLimiter::handle_message`,
  which reads `default_settings`/`tx`/`other` (keyed by `ProtocolMessageTypes`) and NEVER the
  `dig_wire` map. 221/222 ARE `ProtocolMessageTypes` variants but have no `tx`/`other` row, so they
  fell through to the loose `default_settings` — meaning both the #1316 (221) and #1720 (222) rows
  were a unit-tested source of truth NOT bound at runtime (`check_dig_extension`, the only `dig_wire`
  reader, was called nowhere in `src/`). Fix: extracted ONE shared gate
  `connection::inbound_limits::inbound_gate_allows(guard, msg)` (also killing the duplicated inline
  gate — a §2.5 DRY fix) that, under the SINGLE existing `MutexGuard` (no second lock, no TOCTOU —
  the two methods count in disjoint maps `message_counts` vs `dig_message_counts`), runs
  `handle_message` AND, for opcodes `>= 220`, ALSO requires `check_dig_extension(opcode, len)`. Both
  forwarders now call it. Behaviour change to call out: this makes 221's #1316 row go LIVE for the
  first time too — safe (StoreMelted is a fixed 164 B, 25× under its 4096 B cap; 10/min ample for an
  infrequent broadcast). 222 legit max ≈79 KiB < 128 KiB and 20/min > steady re-announce cadence, so
  legit traffic is not dropped. `<220` traffic is unchanged (base bound alone). Gate order preserved:
  the limiter runs BEFORE the `tx.send` that feeds the downstream P-256 verify.
- #1720 regression-test integrity: the 220-band live-gate rate-limit regression test now pins the
  REAL `pub(crate) connection::inbound_limits::inbound_gate_allows` via an in-crate `#[cfg(test)]`
  module, NOT a hand-copied mirror. A mirror in an external test crate (`tests/con_005_tests.rs`)
  re-implements the branch it claims to guard, so it stays green even if production drops the branch —
  a false-green. RED was proven: removing the `>= DIG_WIRE_BAND_START check_dig_extension` branch makes
  the in-crate tests fail (21st/11th frame admitted via the 100/min default). Lesson: a regression test
  for a `pub(crate)` helper belongs in-crate; never mirror the code-under-test in an external test.
