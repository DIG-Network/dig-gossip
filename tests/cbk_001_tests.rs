//! Tests for **CBK-001 through CBK-006: Compact block relay**.
//!
//! ## Requirement traceability
//!
//! - CBK-001: CompactBlock struct (SPEC §8.2)
//! - CBK-002: ShortTxId = SipHash(key, tx_id)[0..6]
//! - CBK-003: Reconstruction from mempool
//! - CBK-004: RequestBlockTransactions / RespondBlockTransactions
//! - CBK-005: Fallback to full block on >5 missing
//! - CBK-006: SipHash key derivation from header hash

#[cfg(feature = "compact-blocks")]
mod tests {
    use dig_gossip::gossip::compact_block::{
        classify_reconstruction, CompactBlock, PrefilledTransaction, ReconstructionResult,
        RequestBlockTransactions, RespondBlockTransactions, ShortTxId,
    };
    use dig_gossip::{Bytes32, COMPACT_BLOCK_MAX_MISSING_TXS, SHORT_TX_ID_BYTES};

    fn test_header_hash() -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[1] = 0xCD;
        Bytes32::from(bytes)
    }

    fn test_tx_id(n: u8) -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Bytes32::from(bytes)
    }

    /// **CBK-006: SipHash key derived from header hash (first 16 bytes).**
    ///
    /// Proves SPEC §8.2: "SipHash key MUST be derived deterministically from block header hash."
    #[test]
    fn test_sip_hash_key_derivation() {
        let header = test_header_hash();
        let key = CompactBlock::derive_sip_hash_key(&header);

        assert_eq!(key.len(), 16);
        assert_eq!(key[0], 0xAB);
        assert_eq!(key[1], 0xCD);

        // Deterministic: same header = same key
        let key2 = CompactBlock::derive_sip_hash_key(&header);
        assert_eq!(key, key2);
    }

    /// **CBK-002: ShortTxId is 6 bytes.**
    ///
    /// Proves SPEC §8.2: "SHORT_TX_ID_BYTES = 6."
    #[test]
    fn test_short_tx_id_length() {
        assert_eq!(SHORT_TX_ID_BYTES, 6);
    }

    /// **CBK-002: ShortTxId computation via SipHash.**
    ///
    /// Proves SPEC §8.2: "short_tx_id = SipHash(sip_hash_key, tx_id)[0..6]."
    #[test]
    fn test_short_tx_id_compute() {
        let key = CompactBlock::derive_sip_hash_key(&test_header_hash());
        let tx1 = test_tx_id(1);
        let tx2 = test_tx_id(2);

        let short1 = ShortTxId::compute(&key, &tx1);
        let short2 = ShortTxId::compute(&key, &tx2);

        // Different tx_ids produce different short IDs
        assert_ne!(
            short1, short2,
            "different tx_ids must produce different short IDs"
        );

        // Same tx_id produces same short ID (deterministic)
        let short1b = ShortTxId::compute(&key, &tx1);
        assert_eq!(short1, short1b, "same tx_id must produce same short ID");
    }

    /// **CBK-002: different keys produce different short IDs.**
    #[test]
    fn test_short_tx_id_key_dependent() {
        let tx = test_tx_id(1);
        let key1 = [1u8; 16];
        let key2 = [2u8; 16];

        let s1 = ShortTxId::compute(&key1, &tx);
        let s2 = ShortTxId::compute(&key2, &tx);

        assert_ne!(s1, s2, "different keys must produce different short IDs");
    }

    /// **CBK-001: CompactBlock holds all required fields.**
    #[test]
    fn test_compact_block_struct() {
        let header = test_header_hash();
        let key = CompactBlock::derive_sip_hash_key(&header);

        let block = CompactBlock {
            header_hash: header,
            height: 100,
            short_tx_ids: vec![ShortTxId::compute(&key, &test_tx_id(1))],
            prefilled_txs: vec![PrefilledTransaction {
                index: 0,
                tx: vec![0xFF],
            }],
            sip_hash_key: key,
        };

        assert_eq!(block.height, 100);
        assert_eq!(block.short_tx_ids.len(), 1);
        assert_eq!(block.prefilled_txs.len(), 1);
        assert_eq!(block.prefilled_txs[0].index, 0);
    }

    /// **CBK-003/CBK-005: reconstruction classification — complete.**
    ///
    /// Proves SPEC §8.2: no missing → Complete.
    #[test]
    fn test_reconstruction_complete() {
        let result = classify_reconstruction(vec![]);
        assert_eq!(result, ReconstructionResult::Complete);
    }

    /// **CBK-003/CBK-004: reconstruction — request missing (<=5).**
    ///
    /// Proves SPEC §8.2: <=5 missing → RequestMissing.
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

    /// **CBK-005: reconstruction — fallback to full block (>5 missing).**
    ///
    /// Proves SPEC §8.2: ">5 missing → fall back to full block."
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

    /// **CBK-005: exactly 5 missing → request (boundary).**
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
