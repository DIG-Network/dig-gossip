//! Tests for **CBK-006: Deterministic SipHash Key Derivation**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/compact_blocks/specs/CBK-006.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.2

#[cfg(feature = "compact-blocks")]
mod tests {
    use dig_gossip::gossip::compact_block::CompactBlock;
    use dig_gossip::Bytes32;

    fn test_header_hash() -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[1] = 0xCD;
        Bytes32::from(bytes)
    }

    /// **CBK-006: SipHash key derived from header hash (first 16 bytes).**
    ///
    /// Proves SPEC SS8.2: "SipHash key MUST be derived deterministically from block header hash."
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
}
