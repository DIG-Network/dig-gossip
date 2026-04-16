//! Tests for **ERL-002: Low-Fanout Flooding via NewTransaction**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/erlay/specs/ERL-002.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.3

#[cfg(feature = "erlay")]
mod tests {
    use dig_gossip::gossip::erlay::{ErlayConfig, ErlayState};
    use dig_gossip::Bytes32;

    fn test_peer_id(n: u8) -> Bytes32 {
        let mut b = [0u8; 32];
        b[0] = n;
        Bytes32::from(b)
    }

    fn test_tx_id(n: u8) -> Bytes32 {
        let mut b = [0u8; 32];
        b[31] = n;
        Bytes32::from(b)
    }

    /// **ERL-002: is_flood_peer correctly identifies flood set members.**
    #[test]
    fn test_is_flood_peer() {
        let mut state = ErlayState::with_config(ErlayConfig {
            flood_peer_count: 2,
            ..Default::default()
        });
        let peers = vec![test_peer_id(1), test_peer_id(2), test_peer_id(3)];
        state.select_flood_set(&peers);

        let flood_count = peers.iter().filter(|p| state.is_flood_peer(p)).count();
        assert_eq!(flood_count, 2);
    }

    /// **ERL-002: add_local_tx tracks transactions.**
    #[test]
    fn test_add_local_tx() {
        let mut state = ErlayState::new();
        state.add_local_tx(test_tx_id(1));
        state.add_local_tx(test_tx_id(2));
        assert_eq!(state.local_tx_count(), 2);

        // Duplicate doesn't increase count
        state.add_local_tx(test_tx_id(1));
        assert_eq!(state.local_tx_count(), 2);
    }
}
