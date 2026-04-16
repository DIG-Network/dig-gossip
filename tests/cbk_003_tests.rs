//! Tests for **CBK-003: Block Reconstruction from Mempool**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/compact_blocks/specs/CBK-003.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.2

#[cfg(feature = "compact-blocks")]
mod tests {
    use dig_gossip::gossip::compact_block::{classify_reconstruction, ReconstructionResult};

    /// **CBK-003: reconstruction classification -- complete.**
    ///
    /// Proves SPEC SS8.2: no missing -> Complete.
    #[test]
    fn test_reconstruction_complete() {
        let result = classify_reconstruction(vec![]);
        assert_eq!(result, ReconstructionResult::Complete);
    }
}
