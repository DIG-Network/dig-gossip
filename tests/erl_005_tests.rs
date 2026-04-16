//! Tests for **ERL-005: Symmetric Difference Resolution**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/erlay/specs/ERL-005.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.3

#[cfg(feature = "erlay")]
mod tests {
    use dig_gossip::gossip::erlay::ErlayState;
    use dig_gossip::Bytes32;

    fn test_tx_id(n: u8) -> Bytes32 {
        let mut b = [0u8; 32];
        b[31] = n;
        Bytes32::from(b)
    }

    /// **ERL-005: clear_local_txs resets for next round.**
    #[test]
    fn test_clear_local_txs() {
        let mut state = ErlayState::new();
        state.add_local_tx(test_tx_id(1));
        state.add_local_tx(test_tx_id(2));

        state.clear_local_txs();
        assert_eq!(state.local_tx_count(), 0);
    }
}
