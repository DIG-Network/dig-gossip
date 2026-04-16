# Discovery - Verification Matrix

> **Domain:** discovery
> **Prefix:** DSC
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| DSC-001 | verified | AddressManager with tried/new tables       | `tests/dsc_001_tests.rs` — buckets, penalty, mark_good/tried, collisions, select_peer, threading; heavy full-slot eviction `#[ignore]` |
| DSC-002 | verified | Address manager persistence (save/load)    | `tests/dsc_002_tests.rs` — round-trip empty/populated, atomic tmp+rename, corrupt file → `AddressManagerStore`, version field/mismatch, `create` reload vs fresh, async save |
| DSC-003 | verified | DNS seeding via Network::lookup_all()      | `tests/dsc_003_tests.rs` — Network clone from config; SocketAddr→TimestampedPeerInfo; merge→AddressManager; empty/unresolvable/timeout soft-fail; optional localhost resolution |
| DSC-004 | verified | Introducer query (get_peers)               | `tests/dsc_004_tests.rs` — TLS+WS mock introducer; success/empty/timeout/handshake-mismatch/connect-fail; wire `msg_type` 63/64 |
| DSC-005 | verified | Introducer registration (register_peer)    | `tests/dsc_005_tests.rs` — TLS mock introducer; success/reject/timeout/connect-fail; wire 218/219; payload round-trip; `GossipHandle` empty-endpoint guard (`api_002_tests`) |
| DSC-006 | verified | Discovery loop with DNS-first and backoff  | `tests/dsc_006_tests.rs` — cancellation stops loop, cycle sleep when peers available, exponential backoff (1s,2s,4s...), backoff cap at 300s, no panic on failures |
| DSC-007 | verified | Peer exchange (RequestPeers/RespondPeers) | `tests/dsc_007_tests.rs` — per-request cap (1000), global total cap (3000), empty list handled, both caps interact, content preserved, constants match SPEC |
| DSC-008 | verified | Feeler connections on Poisson schedule      | `tests/dsc_008_tests.rs` — Poisson mean ~240s, always positive, FEELER_INTERVAL_SECS=240, cancellation, empty new table, promotes on success |
| DSC-009 | verified | Parallel connection establishment           | `tests/dsc_009_tests.rs` — constant=8, empty manager, batch produces results, batch size limits, size=1 works, mark_good called |
| DSC-010 | verified | AS-level diversity enforcement             | `tests/dsc_010_tests.rs` — BGP lookup, longest-prefix-match, unknown fail-open, filter blocks/allows, remove re-allows, no-BGP fallback, count tracking |
| DSC-011 | verified | /16 group filter for outbound connections  | `tests/dsc_011_tests.rs` — IPv4/IPv6 grouping, same/different subnet, filter blocks/allows, remove re-allows, count tracking |
| DSC-012 | gap    | IntroducerPeers/VettedPeer tracking          | Unit test: verify vetting state transitions (unvetted, failed, success)               |
