# Crate Structure - Verification Matrix

> **Domain:** crate_structure
> **Prefix:** STR
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| STR-001 | verified | Cargo.toml dependencies and feature gates    | `tests/str_001_tests.rs` parses `Cargo.toml`, asserts versions/features, and runs `cargo check` (default + `rustls`). See TRACKING.yaml notes for `minisketch-rs` omission. |
| STR-002 | verified | Module hierarchy matches SPEC Section 10.1   | `tests/str_002_tests.rs` asserts filesystem layout, `mod.rs` `pub mod` wiring, `lib.rs` mounts + feature gates, and `cargo check` (default + minimal `rustls`). See TRACKING.yaml re `privacy/` vs STR-002 scope. |
| STR-003 | verified | Public re-exports in lib.rs                  | `tests/str_003_tests.rs` asserts root symbols (Send/Sync, constants, full `use` set); optional relay/compact-blocks/erlay/dandelion covered with `cfg(feature)`. See TRACKING for introducer opcode note. |
| STR-004 | verified | Feature flags match SPEC Section 10.3        | `tests/str_004_tests.rs` parses `[features]`, asserts cfg anchors in lib/gossip/privacy, and runs `cargo check` matrix (minimal TLS, rustls, per-feature, tor, --all-features). See TRACKING for erlay/minisketch deviation. |
| STR-005 | verified | Test infrastructure with helpers           | `tests/str_005_tests.rs` exercises `tests/common` per STR-005 matrix (peer id, mock PeerConnection, temp dirs, GossipConfig, chia-ssl PEMs, load_ssl_cert, composed pair); see TRACKING for API-001/CON-* deferrals |
