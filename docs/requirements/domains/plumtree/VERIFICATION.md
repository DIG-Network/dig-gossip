# Plumtree Gossip - Verification Matrix

> **Domain:** plumtree
> **Prefix:** PLT
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| PLT-001 | gap    | PlumtreeState structure and defaults         | Unit test constructing PlumtreeState, verify fields and default lazy_timeout_ms=500   |
| PLT-002 | gap    | Eager push sends full message                | Unit test broadcast with eager peers, verify send_raw called for each excluding origin|
| PLT-003 | gap    | Lazy push sends LazyAnnounce                 | Unit test broadcast with lazy peers, verify LazyAnnounce sent with correct hash       |
| PLT-004 | gap    | Duplicate detection demotes to lazy + PRUNE  | Unit test receiving duplicate, verify peer moved to lazy_peers and PRUNE sent         |
| PLT-005 | gap    | Lazy timeout triggers GRAFT + promote        | Unit test lazy announce timeout, verify GRAFT+RequestByHash sent and peer promoted    |
| PLT-006 | gap    | Tree self-healing on eager peer disconnect   | Integration test disconnect eager peer, verify lazy peer promoted within timeout       |
| PLT-007 | gap    | Message cache LRU with TTL                   | Unit test cache insert/get/eviction/expiry and GRAFT response serving                |
| PLT-008 | gap    | Seen set LRU deduplication                   | Unit test seen set insert/contains/capacity and duplicate message drop behavior       |
| PLT-009 | gap    | PlumtreeMessage wire types with DigMessageType IDs | Unit test enum variants exist, DigMessageType IDs 214-217, serialization round-trip |
