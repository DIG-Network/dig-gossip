# Discovery - Verification Matrix

> **Domain:** discovery
> **Prefix:** DSC
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| DSC-001 | verified | AddressManager with tried/new tables       | `tests/dsc_001_tests.rs` — buckets, penalty, mark_good/tried, collisions, select_peer, threading; heavy full-slot eviction `#[ignore]` |
| DSC-002 | verified | Address manager persistence (save/load)    | `tests/dsc_002_tests.rs` — round-trip empty/populated, atomic tmp+rename, corrupt file → `AddressManagerStore`, version field/mismatch, `create` reload vs fresh, async save |
| DSC-003 | gap    | DNS seeding via Network::lookup_all()        | Integration test with mock DNS; verify addresses added to address manager             |
| DSC-004 | gap    | Introducer query (get_peers)                 | Integration test with mock WebSocket introducer; verify peer list returned            |
| DSC-005 | gap    | Introducer registration (register_peer)      | Integration test with mock WebSocket introducer; verify register_ack received         |
| DSC-006 | gap    | Discovery loop with DNS-first and backoff    | Integration test verifying DNS attempted first, then introducer with backoff timing   |
| DSC-007 | gap    | Peer exchange (RequestPeers/RespondPeers)    | Unit test: mock peer responds with peer list, verify added to address manager         |
| DSC-008 | gap    | Feeler connections on Poisson schedule        | Unit test: verify Poisson timing distribution; integration test: verify promotion     |
| DSC-009 | gap    | Parallel connection establishment             | Integration test: verify batch of 8 concurrent connections via FuturesUnordered       |
| DSC-010 | gap    | AS-level diversity enforcement               | Unit test: verify one-per-AS rule; test cached BGP prefix table lookup                |
| DSC-011 | gap    | /16 group filter for outbound connections    | Unit test: verify one-per-/16 rule; test IPv4 address grouping logic                  |
| DSC-012 | gap    | IntroducerPeers/VettedPeer tracking          | Unit test: verify vetting state transitions (unvetted, failed, success)               |
