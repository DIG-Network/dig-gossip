//! Tests for **CBK-001: CompactBlock Struct**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/compact_blocks/specs/CBK-001.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.2

#[cfg(feature = "compact-blocks")]
mod tests {
    use dig_gossip::gossip::compact_block::{CompactBlock, PrefilledTransaction, ShortTxId};
    use dig_gossip::Bytes32;

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
}
