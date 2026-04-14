//! Dandelion++ stem/fluff transaction propagation.
//!
//! **Re-export:** STR-003 with `#[cfg(feature = "dandelion")]`.
//! **Behavior:** PRV-* specs.

/// Transaction wrapper while in stem phase (not yet fluffed to the mempool).
#[derive(Debug, Clone, Default)]
pub struct StemTransaction {}
