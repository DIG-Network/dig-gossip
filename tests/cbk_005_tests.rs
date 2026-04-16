//! Tests for **CBK-005: Fallback to Full Block**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/compact_blocks/specs/CBK-005.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.2

#[cfg(feature = "compact-blocks")]
mod tests {
    use dig_gossip::gossip::compact_block::{classify_reconstruction, ReconstructionResult};
    use dig_gossip::COMPACT_BLOCK_MAX_MISSING_TXS;

    /// **CBK-005: reconstruction -- fallback to full block (>5 missing).**
    ///
    /// Proves SPEC SS8.2: ">5 missing -> fall back to full block."
    #[test]
    fn test_reconstruction_fallback() {
        let missing: Vec<u16> = (0..6).collect(); // 6 missing > 5
        let result = classify_reconstruction(missing);
        assert_eq!(
            result,
            ReconstructionResult::FallbackToFullBlock { missing_count: 6 }
        );
    }

    /// **CBK-005: COMPACT_BLOCK_MAX_MISSING_TXS = 5.**
    #[test]
    fn test_max_missing_constant() {
        assert_eq!(COMPACT_BLOCK_MAX_MISSING_TXS, 5);
    }

    /// **CBK-005: exactly 5 missing -> request (boundary).**
    #[test]
    fn test_reconstruction_boundary() {
        let result = classify_reconstruction(vec![1, 2, 3, 4, 5]); // exactly 5
        assert!(matches!(
            result,
            ReconstructionResult::RequestMissing { .. }
        ));

        let result = classify_reconstruction(vec![1, 2, 3, 4, 5, 6]); // 6 = too many
        assert!(matches!(
            result,
            ReconstructionResult::FallbackToFullBlock { .. }
        ));
    }
}
