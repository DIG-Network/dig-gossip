# dig-gossip Requirements

This directory contains the formal requirements for the dig-gossip crate,
following the same two-tier requirements structure as dig-coinstore
with full traceability.

## Quick Links

- [SCHEMA.md](SCHEMA.md) — Data model and conventions
- [REQUIREMENTS_REGISTRY.yaml](REQUIREMENTS_REGISTRY.yaml) — Central domain registry
- [domains/](domains/) — All requirement domains

## Structure

```
requirements/
├── README.md                    # This file
├── SCHEMA.md                    # Data model and conventions
├── REQUIREMENTS_REGISTRY.yaml   # Central registry
├── IMPLEMENTATION_ORDER.md      # Phased implementation checklist
└── domains/
    ├── crate_structure/         # STR-* Crate folder and file layout
    ├── crate_api/               # API-* Public types, config, errors, handles
    ├── connection/              # CON-* Connection lifecycle, handshake, TLS, rate limiting
    ├── discovery/               # DSC-* Address manager, introducer, DNS, peer exchange
    ├── relay/                   # RLY-* Relay client, NAT traversal, fallback
    ├── plumtree/                # PLT-* Structured gossip, eager/lazy push, tree healing
    ├── compact_blocks/          # CBK-* Compact block relay, reconstruction
    ├── erlay/                   # ERL-* Transaction relay, minisketch reconciliation
    ├── priority/                # PRI-* Priority lanes, adaptive backpressure
    ├── performance/             # PRF-* Latency scoring, parallel connect, benchmarks
    ├── concurrency/             # CNC-* Thread safety, task architecture, shared state
    └── privacy/                 # PRV-* Dandelion++, ephemeral PeerId, Tor transport
```

## Three-Document Pattern

Each domain contains:

| File | Purpose |
|------|---------|
| `NORMATIVE.md` | Authoritative requirement statements (MUST/SHOULD/MAY) |
| `VERIFICATION.md` | QA approach and status per requirement |
| `TRACKING.yaml` | Machine-readable status, tests, and notes |

## Specification Files

Individual requirement specifications are in each domain's `specs/` subdirectory:

```
domains/
├── crate_structure/specs/         # STR-001.md through STR-005.md
├── crate_api/specs/               # API-001.md through API-011.md
├── connection/specs/              # CON-001.md through CON-008.md
├── discovery/specs/               # DSC-001.md through DSC-012.md
├── relay/specs/                   # RLY-001.md through RLY-008.md
├── plumtree/specs/                # PLT-001.md through PLT-008.md
├── compact_blocks/specs/          # CBK-001.md through CBK-006.md
├── erlay/specs/                   # ERL-001.md through ERL-007.md
├── priority/specs/                # PRI-001.md through PRI-008.md
├── performance/specs/             # PRF-001.md through PRF-006.md
├── concurrency/specs/             # CNC-001.md through CNC-006.md
└── privacy/specs/                 # PRV-001.md through PRV-010.md
```

## Reference Document

All requirements are derived from:
- [SPEC.md](../resources/SPEC.md) — dig-gossip specification

## Requirement Count

| Domain | Prefix | Count |
|--------|--------|-------|
| Crate Structure | STR | 5 |
| Crate API | API | 11 |
| Connection | CON | 9 |
| Discovery | DSC | 12 |
| Relay | RLY | 8 |
| Plumtree Gossip | PLT | 8 |
| Compact Blocks | CBK | 6 |
| ERLAY Tx Relay | ERL | 7 |
| Priority & Backpressure | PRI | 8 |
| Performance | PRF | 6 |
| Concurrency | CNC | 6 |
| Privacy | PRV | 10 |
| Integration | INT | 12 |
| **Total** | | **110** |
