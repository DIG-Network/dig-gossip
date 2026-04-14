# Concurrency - Verification Matrix

> **Domain:** concurrency
> **Prefix:** CNC
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| CNC-001 | gap    | GossipService/GossipHandle Send + Sync + Clone | Compile-time static assertions for Send, Sync, Clone bounds                          |
| CNC-002 | gap    | Task architecture (listener, discovery, etc.)  | Integration test: start service, verify all tasks spawn and respond                  |
| CNC-003 | gap    | Shared state synchronization primitives        | Verify RwLock on connection/sender maps, mpsc per-connection, AtomicU64 for stats    |
| CNC-004 | gap    | Graceful shutdown                              | Integration test: start service, call stop(), verify all tasks exit and state saved  |
| CNC-005 | gap    | Address manager timestamp update on message    | Unit test: receive message from outbound peer, verify timestamp updated              |
| CNC-006 | gap    | Periodic cleanup task                          | Integration test: inject stale connections and expired bans, verify cleanup           |
