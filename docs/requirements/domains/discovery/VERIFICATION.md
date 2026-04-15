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
| DSC-007 | gap    | Peer exchange (RequestPeers/RespondPeers)    | Unit test: mock peer responds with peer list, verify added to address manager         |
| DSC-008 | gap    | Feeler connections on Poisson schedule        | Unit test: verify Poisson timing distribution; integration test: verify promotion     |
| DSC-009 | gap    | Parallel connection establishment             | Integration test: verify batch of 8 concurrent connections via FuturesUnordered       |
| DSC-010 | gap    | AS-level diversity enforcement               | Unit test: verify one-per-AS rule; test cached BGP prefix table lookup                |
| DSC-011 | gap    | /16 group filter for outbound connections    | Unit test: verify one-per-/16 rule; test IPv4 address grouping logic                  |
| DSC-012 | gap    | IntroducerPeers/VettedPeer tracking          | Unit test: verify vetting state transitions (unvetted, failed, success)               |
