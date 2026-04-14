# Concurrency - Normative Requirements

> **Domain:** concurrency
> **Prefix:** CNC
> **Spec reference:** [SPEC.md - Section 9.1, Section 3.2, Section 3.3](../../resources/SPEC.md)

## Requirements

### CNC-001: GossipService and GossipHandle Thread Safety

GossipService and GossipHandle MUST be Send + Sync. GossipHandle MUST be Clone with an inner Arc to allow cheap sharing across tasks and threads.

**Spec reference:** SPEC Section 3.3 (GossipHandle - "Cheaply cloneable (inner Arc)")

### CNC-002: Task Architecture

GossipService::start() MUST spawn the following tasks: (a) Listener task (accepts inbound TCP/TLS connections), (b) Discovery task (connect loop ported from node_discovery.py:244), (c) Serialization task (periodic address manager save), (d) Cleanup task (stale connection removal, expired ban cleanup), (e) Relay task (if configured, auto-reconnect), (f) Per-connection tasks (one per peer for message handling). All tasks MUST be cancellable via a shared shutdown signal.

**Spec reference:** SPEC Section 9.1 (Crate Boundary), Section 3.2 (Lifecycle), Section 5.1 (Connection Lifecycle)

### CNC-003: Shared State Synchronization Primitives

Connection map and sender map MUST be protected by RwLock (read-heavy, low contention). Per-connection outbound channels MUST be lock-free mpsc. Stats counters MUST be AtomicU64.

**Spec reference:** SPEC Section 9.1 (Crate Boundary)

### CNC-004: Graceful Shutdown

GossipService::stop() MUST gracefully shut down all tasks: cancel discovery, serialization, cleanup, relay tasks. Disconnect all peers. Save address manager state. Close listener. All tasks MUST complete within a bounded timeout.

**Spec reference:** SPEC Section 3.2 (Lifecycle - "Gracefully stop: disconnect all peers, stop discovery, close relay")

### CNC-005: Address Manager Timestamp Update on Message Receipt

On every message received from an outbound peer, the address manager MUST update the peer's timestamp. This keeps the address manager's "last seen" information fresh and influences peer selection. Ported from node_discovery.py:139-154.

**Spec reference:** SPEC Section 6.4 (Discovery Loop, item 7 - "Timestamp update on message")

### CNC-006: Periodic Cleanup Task

Periodic cleanup task MUST run at a configurable interval. MUST remove connections with last_pong older than PEER_TIMEOUT_SECS. MUST clear expired bans (check ban_until against current time). MUST log removed connections and cleared bans.

**Spec reference:** SPEC Section 2.13 (Constants - PEER_TIMEOUT_SECS, BAN_DURATION_SECS)
