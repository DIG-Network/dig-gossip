//! Tests for **ERL-007: Inbound Peer Exclusion from Flood Set**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/erlay/specs/ERL-007.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.3
//!
//! Placeholder: inbound exclusion is tested indirectly via ERL-001
//! (select_flood_set takes only outbound peers).

#[cfg(feature = "erlay")]
mod tests {
    use dig_gossip::gossip::erlay::ErlayState;
    use dig_gossip::{Bytes32, ERLAY_FLOOD_PEER_COUNT};

    fn test_peer_id(n: u8) -> Bytes32 {
        let mut b = [0u8; 32];
        b[0] = n;
        Bytes32::from(b)
    }

    /// **ERL-007: flood set only selects from the outbound list provided.**
    ///
    /// The caller is responsible for passing only outbound peers;
    /// select_flood_set never sees inbound peers.
    #[test]
    fn test_flood_set_only_from_provided_peers() {
        let mut state = ErlayState::new();
        let outbound_only: Vec<Bytes32> = (1..=5).map(test_peer_id).collect();

        state.select_flood_set(&outbound_only);

        // flood set size is min(ERLAY_FLOOD_PEER_COUNT, available)
        assert_eq!(state.flood_set_size(), 5.min(ERLAY_FLOOD_PEER_COUNT));
        for fp in &state.flood_set {
            assert!(outbound_only.contains(fp));
        }
    }
}
