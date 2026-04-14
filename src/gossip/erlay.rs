//! ERLAY reconciliation state — feature `erlay`.
//!
//! **Re-export:** STR-003 when `erlay` is enabled.
//! **Note:** `minisketch-rs` is intentionally absent from `Cargo.toml` (STR-001 TRACKING);
//! sketch math will use pure-Rust or an alternate crate when ERLAY specs are implemented.
//!
//! **API-003:** [`ErlayConfig`] is the `GossipConfig::erlay` payload ([`SPEC.md`](../../../docs/resources/SPEC.md) §8.3).

/// ERLAY flood/reconciliation parameters (shell — ERL-* specs add fields).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErlayConfig {}

#[derive(Debug, Default)]
pub struct ErlayState {}

#[derive(Debug, Default)]
pub struct ReconciliationSketch {}
