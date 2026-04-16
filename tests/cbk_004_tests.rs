//! Tests for **CBK-004: Missing Transaction Request**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/compact_blocks/specs/CBK-004.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.2

#[cfg(feature = "compact-blocks")]
mod tests {
    use dig_gossip::gossip::compact_block::{
        classify_reconstruction, ReconstructionResult, RequestBlockTransactions,
        RespondBlockTransactions,
    };
    use dig_gossip::Bytes32;

    fn test_header_hash() -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[1] = 0xCD;
        Bytes32::from(bytes)
    }

    /// **CBK-004: reconstruction -- request missing (<=5).**
    ///
    /// Proves SPEC SS8.2: <=5 missing -> RequestMissing.
    #[test]
    fn test_reconstruction_request_missing() {
        let result = classify_reconstruction(vec![3, 7, 12]);
        assert_eq!(
            result,
            ReconstructionResult::RequestMissing {
                missing_indices: vec![3, 7, 12]
            }
        );
    }

    /// **CBK-004: RequestBlockTransactions / RespondBlockTransactions structs.**
    #[test]
    fn test_block_transactions_types() {
        let req = RequestBlockTransactions {
            block_hash: test_header_hash(),
            missing_indices: vec![3, 7],
        };
        assert_eq!(req.missing_indices.len(), 2);

        let resp = RespondBlockTransactions {
            block_hash: test_header_hash(),
            transactions: vec![vec![1, 2, 3], vec![4, 5, 6]],
        };
        assert_eq!(resp.transactions.len(), 2);
    }
}
