//! Tests for **CBK-002: ShortTxId Computation**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/compact_blocks/specs/CBK-002.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.2

#[cfg(feature = "compact-blocks")]
mod tests {
    use dig_gossip::gossip::compact_block::{CompactBlock, ShortTxId};
    use dig_gossip::{Bytes32, SHORT_TX_ID_BYTES};

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

    /// **CBK-002: ShortTxId is 6 bytes.**
    ///
    /// Proves SPEC SS8.2: "SHORT_TX_ID_BYTES = 6."
    #[test]
    fn test_short_tx_id_length() {
        assert_eq!(SHORT_TX_ID_BYTES, 6);
    }

    /// **CBK-002: ShortTxId computation via SipHash.**
    ///
    /// Proves SPEC SS8.2: "short_tx_id = SipHash(sip_hash_key, tx_id)[0..6]."
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
}
