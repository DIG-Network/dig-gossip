//! ERLAY reconciliation state — feature `erlay`.
//!
//! **Re-export:** STR-003 when `erlay` is enabled.
//! **Note:** `minisketch-rs` is intentionally absent from `Cargo.toml` (STR-001 TRACKING);
//! sketch math will use pure-Rust or an alternate crate when ERLAY specs are implemented.

#[derive(Debug, Default)]
pub struct ErlayState {}

#[derive(Debug, Default)]
pub struct ReconciliationSketch {}
