//! Dandelion++ stem/fluff transaction propagation.
//!
//! **Re-export:** STR-003 with `#[cfg(feature = "dandelion")]`.
//! **Behavior:** PRV-* specs.
//!
//! **Config surface:** [`DandelionConfig`] is referenced from [`crate::types::config::GossipConfig`]
//! (API-003 / [`SPEC.md`](../../../docs/resources/SPEC.md) §1.9.1). Fields expand in PRV-001+.

/// Tunables for stem/fluff epochs (placeholder — PRV-001 will add fields).
///
/// **Traceability:** API-003 acceptance — `GossipConfig::dandelion`; normative detail in
/// [`PRV-001.md`](../../../docs/requirements/domains/privacy/specs/PRV-001.md).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DandelionConfig {}

/// Transaction wrapper while in stem phase (not yet fluffed to the mempool).
#[derive(Debug, Clone, Default)]
pub struct StemTransaction {}
