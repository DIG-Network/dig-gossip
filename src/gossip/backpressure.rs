//! Adaptive backpressure: dedup, bulk drop, normal delay thresholds.
//!
//! **STR-002:** structural.
//! **Domain:** [`docs/requirements/domains/priority/`](../../../docs/requirements/domains/priority/) (backpressure specs).
//!
//! **API-003:** [`BackpressureConfig`] wires optional thresholds into [`crate::types::config::GossipConfig`]
//! ([`SPEC.md`](../../../docs/resources/SPEC.md) §8.5).

/// Optional adaptive backpressure thresholds (PRI-* / PRF-* will align fields with constants in
/// [`crate::constants`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackpressureConfig {}
