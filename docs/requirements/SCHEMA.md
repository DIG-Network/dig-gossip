# Requirements Schema

This document defines the data model and conventions for all requirements in the
dig-gossip project.

---

## Three-Document Pattern

Each domain has exactly three files in `docs/requirements/domains/{domain}/`:

| File | Purpose |
|------|---------|
| `NORMATIVE.md` | Authoritative requirement statements with MUST/SHOULD/MAY keywords |
| `VERIFICATION.md` | QA approach and verification status per requirement |
| `TRACKING.yaml` | Machine-readable status, test references, and implementation notes |

Each requirement also has a dedicated specification file in
`docs/requirements/domains/{domain}/specs/{PREFIX-NNN}.md`.

---

## Requirement ID Format

**Pattern:** `{PREFIX}-{NNN}`

- **PREFIX**: 2-4 letter domain identifier (uppercase)
- **NNN**: Zero-padded numeric ID starting at 001

| Domain | Directory | Prefix | Description |
|--------|-----------|--------|-------------|
| Crate Structure | `crate_structure/` | `STR` | Crate folder and file layout |
| Crate API | `crate_api/` | `API` | Public types, config, errors, handles |
| Connection | `connection/` | `CON` | Connection lifecycle, handshake, TLS, rate limiting |
| Discovery | `discovery/` | `DSC` | Address manager, introducer, DNS, peer exchange |
| Relay | `relay/` | `RLY` | Relay client, NAT traversal, fallback |
| Plumtree Gossip | `plumtree/` | `PLT` | Structured gossip, eager/lazy push, tree healing |
| Compact Blocks | `compact_blocks/` | `CBK` | Compact block relay and reconstruction |
| ERLAY Tx Relay | `erlay/` | `ERL` | Transaction relay, minisketch reconciliation |
| Priority & Backpressure | `priority/` | `PRI` | Priority lanes, adaptive backpressure |
| Performance | `performance/` | `PRF` | Latency scoring, parallel connect, benchmarks |
| Concurrency | `concurrency/` | `CNC` | Thread safety, task architecture, shared state, shutdown |
| Privacy | `privacy/` | `PRV` | Dandelion++ tx origin privacy, ephemeral PeerId rotation, Tor transport |
| Integration | `integration/` | `INT` | Wiring components into live broadcast/connect/task paths |

**Immutability:** Requirement IDs are permanent. Deprecate requirements rather
than renumbering.

---

## Requirement Keywords

Per RFC 2119:

| Keyword | Meaning | Impact |
|---------|---------|--------|
| **MUST** | Absolute requirement | Blocks "done" status if not met |
| **MUST NOT** | Absolute prohibition | Blocks "done" status if violated |
| **SHOULD** | Expected behavior; may be deferred with rationale | Phase 2+ polish items |
| **SHOULD NOT** | Discouraged behavior | Phase 2+ polish items |
| **MAY** | Optional, nice-to-have | Stretch goals |

---

## Status Values

| Status | Description |
|--------|-------------|
| `gap` | Not implemented |
| `partial` | Implementation in progress or incomplete |
| `implemented` | Code complete, awaiting verification |
| `verified` | Implemented and verified per VERIFICATION.md |
| `deferred` | Explicitly postponed with rationale |

---

## TRACKING.yaml Item Schema

```yaml
- id: PREFIX-NNN           # Requirement ID (required)
  section: "Section Name"  # Logical grouping within domain (required)
  summary: "Brief title"   # Human-readable description (required)
  status: gap              # One of: gap, partial, implemented, verified, deferred
  spec_ref: "docs/requirements/domains/{domain}/specs/{PREFIX-NNN}.md"
  tests: []                # Array of test names or ["manual"]
  notes: ""                # Implementation notes, blockers, or evidence
```

---

## Testing Requirements

All dig-gossip requirements MUST be tested using:

### 1. Unit Tests (MUST)

All gossip, discovery, and connection paths MUST be tested with:

1. **Create** a `GossipService` instance with test configuration
2. **Connect** to mock peers or test harness
3. **Send/receive** messages and verify routing behavior
4. **Verify** peer state, deduplication, rate limiting, and reputation

### 2. Integration Tests (MUST for multi-domain requirements)

Tests MUST demonstrate correct interaction between domains by:
- Multi-node gossip propagation scenarios
- Introducer registration and peer discovery flows
- Relay fallback when direct P2P fails
- Plumtree tree formation and self-healing
- Compact block reconstruction from mempool
- ERLAY reconciliation convergence

### 3. Benchmark Tests (SHOULD for performance requirements)

Performance-related requirements (PRF domain) SHOULD include benchmarks:
- Plumtree vs flood bandwidth comparison
- Compact block vs full block bandwidth/latency
- ERLAY vs flood transaction relay bandwidth
- Priority lane latency under concurrent bulk transfer

### 4. Required Test Infrastructure

```toml
# Cargo.toml [dev-dependencies]
tempfile = "3"
rand = "0.8"
tokio = { version = "1", features = ["test-util", "macros"] }
```

```rust
use dig_gossip::{GossipService, GossipConfig, GossipHandle, GossipError};
use dig_gossip::{Peer, Message, ProtocolMessageTypes, Bytes32, NodeType};
```

---

## Master Spec Reference

All requirements trace back to the SPEC:
[SPEC.md](../../resources/SPEC.md)
