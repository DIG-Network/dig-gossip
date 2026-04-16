# Integration — Verification Matrix

> **Domain:** integration
> **Prefix:** INT
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| INT-001 | verified | Broadcast via Plumtree (eager/lazy) | `tests/int_001_tests.rs`: PlumtreeState eager push (full msg to eager_peers) + lazy push (hash to lazy_peers) + duplicate → PRUNE + GRAFT pull; broadcaster integration with 4 peers, fanout=2, message_cache lookup |
| INT-002 | verified | Broadcast via priority lanes | `tests/int_002_tests.rs`: PriorityOutbound enqueue Critical+Bulk, drain order Critical→Normal→Bulk; starvation prevention 1 bulk per PRIORITY_STARVATION_RATIO; from_chia_type classification matrix; integration broadcast_typed → per-connection lane wiring |
| INT-003 | verified | Broadcast with backpressure | `tests/int_003_tests.rs`: BackpressureConfig thresholds; tx dedup suppression at TX_DEDUP_THRESHOLD; bulk drop at BULK_DROP_THRESHOLD; normal delay at NORMAL_DELAY_THRESHOLD; integration flood past thresholds proves backpressure fires |
| INT-004 | verified | ERLAY routing for NewTransaction | `tests/int_004_tests.rs`: ErlayState flood_set selection (outbound only, capped at flood_peer_count); NewTransaction routed to flood set only; non-flood peers get reconciliation sketch; flood_set rotation; inbound peers excluded (ERL-007) |
| INT-005 | verified | Relay broadcast in Plumtree step 7 | `tests/int_005_tests.rs`: RelayMessage::Broadcast wiring; Plumtree step 7 calls relay.broadcast for relay-connected peers; relay_stats tracks messages_sent; broadcast returns count including relay peers |
| INT-006 | verified | /16 filter on connect_to | `tests/int_006_tests.rs`: SubnetGroupFilter allows first /16, rejects second same /16; connect_to returns ConnectionFiltered; filter tracks /16 groups; different /16 allowed; IPv6 passthrough |
| INT-007 | verified | AS filter on connect_to | `tests/int_007_tests.rs`: AsDiversityFilter allows first AS, rejects second same AS; connect_to returns ConnectionFiltered; cached BGP lookup; different AS allowed |
| INT-008 | verified | Discovery loop spawned in start() | `tests/int_008_tests.rs`: start() spawns discovery loop task; DNS seed resolution → AddressManager merge; introducer backoff; parallel connect batches; loop repeats on peer_connect_interval |
| INT-009 | verified | Feeler loop spawned in start() | `tests/int_009_tests.rs`: start() spawns feeler loop; Poisson 240s schedule; feeler connects, probes, disconnects; marks good peers in tried table |
| INT-010 | verified | Cleanup task spawned in start() | `tests/int_010_tests.rs`: start() spawns cleanup task; stale connections removed; expired bans pruned; address manager flush; periodic interval |
| INT-011 | verified | Dandelion stem phase on broadcast | `tests/int_011_tests.rs`: locally-originated NewTransaction enters stem phase; single relay forwarding; 10% fluff coin flip; stem timeout → force fluff; epoch rotation re-randomizes stem relay |
| INT-012 | verified | Relay reconnect task spawned | `tests/int_012_tests.rs`: start() with RelayConfig spawns reconnect task; exponential backoff on failure; max_reconnect_attempts cap; successful reconnect resets attempts |
| INT-013 | verified | Clean public API surface | `tests/int_013_tests.rs`: 7 tests — core types (GossipService, GossipHandle, GossipError), config types (GossipConfig, IntroducerConfig, RelayConfig), peer types (PeerId, PeerInfo, PeerConnection), DIG types (DigMessageType), discovery types (AddressManager, IntroducerClient), chia re-exports (Message, Peer, Network), internal types accessible but `#[doc(hidden)]` |
| INT-014 | verified | Crate-level docs with lifecycle example | `tests/int_014_tests.rs`: 2 tests — lifecycle types exist (GossipService/GossipHandle/GossipConfig importable), I/O contract types (Message input, (PeerId,Message) output, GossipStats observation); lib.rs //! docs cover what/not, lifecycle code example, I/O table, feature flags, SPEC refs |
| INT-015 | verified | End-to-end lifecycle integration test | `tests/int_015_tests.rs`: 2 tests — `test_full_lifecycle`: Config → GossipService::new() → start() → health_check() + stats() + peer_count() → stop() → verify ServiceNotStarted; `test_broadcast_no_peers`: broadcast returns 0 when no peers connected |

**Status legend:** ✅ verified · ⚠️ partial · -- gap
