# Crate Structure - Verification Matrix

> **Domain:** crate_structure
> **Prefix:** STR
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| STR-001 | verified | Cargo.toml dependencies and feature gates    | `tests/str_001_tests.rs` parses `Cargo.toml`, asserts versions/features, and runs `cargo check` (default + `rustls`). See TRACKING.yaml notes for `minisketch-rs` omission. |
| STR-002 | verified | Module hierarchy matches SPEC Section 10.1   | `tests/str_002_tests.rs` asserts filesystem layout, `mod.rs` `pub mod` wiring, `lib.rs` mounts + feature gates, and `cargo check` (default + minimal `rustls`). See TRACKING.yaml re `privacy/` vs STR-002 scope. |
| STR-003 | gap    | Public re-exports in lib.rs                  | Compile-time test that all re-exported symbols are accessible from crate root         |
| STR-004 | gap    | Feature flags match SPEC Section 10.3        | Parse Cargo.toml features section and verify flags; test conditional compilation      |
| STR-005 | gap    | Test infrastructure with helpers             | Verify test helper module exists and provides mock peers, temp dirs, test config      |
