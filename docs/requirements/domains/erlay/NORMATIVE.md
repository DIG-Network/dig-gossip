# ERLAY Transaction Relay - Normative Requirements

> **Domain:** erlay
> **Prefix:** ERL
> **Spec reference:** [SPEC.md - Section 8.3](../../resources/SPEC.md)

## Requirements

### ERL-001: Flood Set Selection

Flood set MUST consist of ERLAY_FLOOD_PEER_COUNT (8) randomly selected connected outbound peers. The flood set determines which peers receive immediate NewTransaction messages via low-fanout flooding.

**Spec reference:** SPEC Section 8.3 (Low-fanout flooding, Flood peer selection)

### ERL-002: Low-Fanout Flooding via NewTransaction

NewTransaction messages MUST be sent only to peers in the flood set (low-fanout). After flooding, the tx_id MUST be added to the local reconciliation sketch for subsequent set reconciliation with non-flood peers.

**Spec reference:** SPEC Section 8.3 (Low-fanout flooding steps 1-3)

### ERL-003: Minisketch Encode/Decode for tx_id Sets

Set reconciliation MUST use minisketch (via minisketch-rs) to encode and decode tx_id sets. Sketch capacity MUST be ERLAY_SKETCH_CAPACITY (20), representing the maximum decodable symmetric difference per reconciliation round. The constant `SKETCH_ELEMENT_BITS: usize = 64` MUST be defined, representing the bit width of sketch elements (tx_ids are truncated from 256 bits to 64 bits for sketch encoding; collision probability is negligible at 2^-64 per pair).

**Spec reference:** SPEC Section 8.3 (Periodic set reconciliation), SPEC Section 1.2 (minisketch-rs dependency)

### ERL-004: Periodic Set Reconciliation

Set reconciliation MUST occur every ERLAY_RECONCILIATION_INTERVAL_MS (2000) milliseconds per non-flood peer. Each reconciliation round exchanges sketches, computes the symmetric difference, and requests missing transactions.

**Spec reference:** SPEC Section 8.3 (Periodic set reconciliation steps a-g)

### ERL-005: Symmetric Difference Resolution

After decoding the symmetric difference from minisketch, the node MUST request missing tx_ids via RequestTransaction and send tx_ids the peer is missing via RespondTransaction. Both peers MUST converge to the same transaction set after a successful reconciliation round.

**Spec reference:** SPEC Section 8.3 (Periodic set reconciliation steps e-g)

### ERL-006: Flood Set Rotation

The flood set MUST be re-randomized every ERLAY_FLOOD_SET_ROTATION_SECS (60) seconds. This prevents long-lived topology patterns and improves propagation diversity.

**Spec reference:** SPEC Section 8.3 (Flood peer selection)

### ERL-007: Inbound Peer Exclusion from Flood Set

Inbound peers MUST be excluded from the flood set. Inbound peers initiate reconciliation with the local node rather than receiving flooded transactions. This matches ERLAY's design for optimal propagation latency.

**Spec reference:** SPEC Section 8.3 (Flood peer selection)

### ERL-008: ErlayConfig Struct

ErlayConfig MUST define `flood_peer_count: usize` (default 8), `reconciliation_interval_ms: u64` (default 2000), `sketch_capacity: usize` (default 20). These fields control ERLAY-style transaction relay behavior: the number of peers receiving immediate NewTransaction flooding, the interval between set reconciliation rounds, and the minisketch capacity (maximum decodable symmetric difference per round).

**Spec reference:** SPEC Section 8.3 (ErlayConfig struct)

---

## Property Tests

**Property test (convergence):** Given two nodes with arbitrary initial tx_id sets where the symmetric difference is at most `ERLAY_SKETCH_CAPACITY` (20), after one reconciliation round both nodes MUST hold the union of the two initial sets. For any pair of sets differing by more than the sketch capacity, the reconciliation MUST fail gracefully (SketchDecodeFailed) and fall back to full set exchange without data loss.
