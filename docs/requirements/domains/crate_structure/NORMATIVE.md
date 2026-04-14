# Crate Structure - Normative Requirements

> **Domain:** crate_structure
> **Prefix:** STR
> **Spec reference:** [SPEC.md - Sections 1.2, 10.1, 10.2, 10.3](../../resources/SPEC.md)

## Requirements

### STR-001: Cargo.toml Dependencies and Feature Gates

Cargo.toml MUST include chia-protocol 0.26, chia-sdk-client 0.28, chia-ssl 0.26, chia-traits 0.26, tokio, serde, bincode, serde_json, tracing, thiserror, rand, lru, siphasher, minisketch-rs. Feature gates: native-tls, rustls, relay, erlay, compact-blocks.

**Spec reference:** SPEC Section 1.2 (Crate Dependencies), Section 10.3 (Feature Flags), Section 10.4 (Cargo.toml Dependencies)

### STR-002: Module Hierarchy

Module hierarchy MUST match SPEC Section 10.1 (types/, constants.rs, error.rs, service/, connection/, discovery/, relay/, gossip/, util/).

**Spec reference:** SPEC Section 10.1 (Module Structure)

### STR-003: Public Re-exports in lib.rs

lib.rs MUST re-export chia crate types per SPEC Section 10.2 (Bytes32, Handshake, Message, NodeType, ProtocolMessageTypes, Peer, RateLimiter, V2_RATE_LIMITS, etc.) and DIG-specific types.

**Spec reference:** SPEC Section 10.2 (Public Re-exports)

### STR-004: Feature Flags

Feature flags MUST match SPEC Section 10.3: `native-tls`, `rustls`, `relay`, `erlay`, `compact-blocks`, `dandelion`, `tor`. Default features MUST be `["native-tls", "relay", "erlay", "compact-blocks", "dandelion"]`. The `dandelion` feature flag (no additional dependencies) gates Dandelion++ transaction origin privacy. The `tor` feature flag (depends on `arti-client` and `tokio-socks`) gates Tor/SOCKS5 proxy transport and is NOT included in defaults (opt-in only).

**Spec reference:** SPEC Section 10.3 (Feature Flags)

### STR-005: Test Infrastructure

Test infrastructure MUST include test helper for creating mock peers, temp directories, and test GossipConfig.

**Spec reference:** SPEC Section 11 (Testing Strategy)
