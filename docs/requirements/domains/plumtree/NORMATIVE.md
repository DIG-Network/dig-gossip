# Plumtree Gossip - Normative Requirements

> **Domain:** plumtree
> **Prefix:** PLT
> **Spec reference:** [SPEC.md - Section 8.1](../../resources/SPEC.md)

## Requirements

### PLT-001: PlumtreeState Structure

PlumtreeState MUST contain eager_peers(HashSet<PeerId>), lazy_peers(HashSet<PeerId>), lazy_queue(HashMap<Bytes32, Vec<(PeerId, u64)>>), and lazy_timeout_ms(u64, default 500). All newly connected peers MUST start in eager_peers.

**Spec reference:** SPEC Section 8.1 (Peer classification)

### PLT-002: Eager Push

On broadcast, full message MUST be sent to all eager_peers excluding the origin peer. Uses peer.send_raw(message) for each eager peer.

**Spec reference:** SPEC Section 8.1 (Broadcast algorithm, step 5)

### PLT-003: Lazy Push

On broadcast, LazyAnnounce{hash, msg_type} MUST be sent to all lazy_peers excluding the origin peer. hash = SHA256(msg_type || data).

**Spec reference:** SPEC Section 8.1 (Broadcast algorithm, step 6)

### PLT-004: Duplicate Detection and Pruning

On receiving a duplicate message via eager push, the sender MUST be demoted from eager_peers to lazy_peers and a PRUNE message MUST be sent to the sender. This removes redundant spanning tree edges.

**Spec reference:** SPEC Section 8.1 (On receiving a message via eager push)

### PLT-005: Lazy Timeout and GRAFT

If a hash is announced via LazyAnnounce but not received eagerly within lazy_timeout_ms, a GRAFT + RequestByHash{hash} MUST be sent to the announcer. The announcer MUST be promoted from lazy_peers to eager_peers. This repairs tree gaps.

**Spec reference:** SPEC Section 8.1 (On receiving a lazy announcement)

### PLT-006: Tree Self-Healing on Disconnect

When an eager peer disconnects, a lazy peer that has announced pending hashes MUST be promoted to eager via GRAFT. The tree MUST reconverge within one lazy_timeout_ms cycle.

**Spec reference:** SPEC Section 8.1 (Tree self-healing)

### PLT-007: Message Cache

A message cache MUST be maintained with LRU eviction, capacity 1000 entries, and TTL of 60 seconds. The cache MUST serve messages in response to GRAFT requests.

**Spec reference:** SPEC Section 8.1 (Message cache, On receiving GRAFT from peer)

### PLT-008: Seen Set

A seen set MUST be maintained as an LRU with capacity 100,000. Messages whose hash is already in the seen set MUST be dropped immediately. hash = SHA256(msg_type || data).

**Spec reference:** SPEC Section 8.1 (Broadcast algorithm, step 2)

### PLT-009: PlumtreeMessage Wire Types

PlumtreeMessage MUST be defined as an enum with variants: `LazyAnnounce { hash: Bytes32, msg_type: u16 }`, `Prune`, `Graft { hash: Bytes32 }`, `RequestByHash { hash: Bytes32 }`. Each variant MUST have a corresponding `DigMessageType` ID for wire transmission: `PlumtreeLazyAnnounce = 214`, `PlumtreePrune = 215`, `PlumtreeGraft = 216`, `PlumtreeRequestByHash = 217`. These wire types enable Plumtree protocol messages to be transmitted between peers using the DIG extension message type system.

**Spec reference:** SPEC Section 8.1 (Plumtree protocol messages: LazyAnnounce, PRUNE, GRAFT, RequestByHash)

---

## Property Tests

**Property test (tree invariant):** For any sequence of peer connect/disconnect and message broadcast events, the Plumtree state MUST maintain the invariant that `eager_peers` and `lazy_peers` are disjoint (no peer in both sets) and their union equals the full set of connected peers. After any PRUNE/GRAFT cycle, every connected peer MUST appear in exactly one of the two sets.
