# Integration — Verification Matrix

> **Domain:** integration
> **Prefix:** INT
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| INT-001 | gap | Broadcast via Plumtree (eager/lazy) | Integration test: broadcast message, verify eager peers get full msg, lazy get hash-only |
| INT-002 | gap | Broadcast via priority lanes | Integration test: enqueue Critical+Bulk, verify Critical drained first |
| INT-003 | gap | Broadcast with backpressure | Integration test: flood queue past thresholds, verify tx dedup + bulk drop |
| INT-004 | gap | ERLAY routing for NewTransaction | Integration test: NewTransaction goes to flood set only, not all peers |
| INT-005 | gap | Relay broadcast in Plumtree step 7 | Integration test: broadcast with relay connected, verify relay.broadcast called |
| INT-006 | gap | /16 filter on connect_to | Integration test: connect two peers in same /16, second rejected |
| INT-007 | gap | AS filter on connect_to | Integration test: connect two peers in same AS, second rejected |
| INT-008 | gap | Discovery loop spawned in start() | Integration test: start service, verify discovery loop running |
| INT-009 | gap | Feeler loop spawned in start() | Integration test: start service, verify feeler loop running |
| INT-010 | gap | Cleanup task spawned in start() | Integration test: add stale peer, verify cleanup removes it |
| INT-011 | gap | Dandelion stem phase on broadcast | Integration test: broadcast tx, verify enters stem not direct gossip |
| INT-012 | gap | Relay reconnect task spawned | Integration test: start with relay config, verify reconnect task |
| INT-013 | gap | Clean public API surface | Verify only user-facing types exported, internals hidden |
| INT-014 | gap | Crate-level docs with lifecycle example | Verify lib.rs has comprehensive //! docs |
| INT-015 | gap | End-to-end lifecycle integration test | Full lifecycle: config → new → start → use → stop |

**Status legend:** ✅ verified · ⚠️ partial · -- gap
