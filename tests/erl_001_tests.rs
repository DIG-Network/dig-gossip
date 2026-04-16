//! Tests for **ERL-001: Flood Set Selection**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/erlay/specs/ERL-001.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.3

#[cfg(feature = "erlay")]
mod tests {
    use dig_gossip::gossip::erlay::ErlayState;
    use dig_gossip::{Bytes32, ERLAY_FLOOD_PEER_COUNT};

    fn test_peer_id(n: u8) -> Bytes32 {
        let mut b = [0u8; 32];
        b[0] = n;
        Bytes32::from(b)
    }

    /// **ERL-001: flood set selects from outbound peers.**
    #[test]
    fn test_flood_set_selection() {
        let mut state = ErlayState::new();
        let peers: Vec<Bytes32> = (1..=20).map(test_peer_id).collect();

        state.select_flood_set(&peers);

        assert_eq!(state.flood_set_size(), ERLAY_FLOOD_PEER_COUNT);
        // All flood peers must be from the outbound list
        for fp in &state.flood_set {
            assert!(peers.contains(fp));
        }
    }

    /// **ERL-001: flood set capped at available peers.**
    #[test]
    fn test_flood_set_fewer_than_count() {
        let mut state = ErlayState::new();
        let peers: Vec<Bytes32> = (1..=3).map(test_peer_id).collect();

        state.select_flood_set(&peers);

        assert_eq!(state.flood_set_size(), 3); // only 3 available
    }
}
