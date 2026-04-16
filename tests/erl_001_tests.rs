//! Tests for **ERL-001 through ERL-008: ERLAY transaction relay**.
//!
//! SPEC §8.3, Naumenko et al., 2019.

#[cfg(feature = "erlay")]
mod tests {
    use dig_gossip::gossip::erlay::{ErlayConfig, ErlayState, ReconciliationSketch};
    use dig_gossip::{
        Bytes32, ERLAY_FLOOD_PEER_COUNT, ERLAY_FLOOD_SET_ROTATION_SECS,
        ERLAY_RECONCILIATION_INTERVAL_MS, ERLAY_SKETCH_CAPACITY,
    };

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

    /// **ERL-008: ErlayConfig defaults match SPEC.**
    #[test]
    fn test_config_defaults() {
        let c = ErlayConfig::default();
        assert_eq!(c.flood_peer_count, ERLAY_FLOOD_PEER_COUNT);
        assert_eq!(
            c.reconciliation_interval_ms,
            ERLAY_RECONCILIATION_INTERVAL_MS
        );
        assert_eq!(c.sketch_capacity, ERLAY_SKETCH_CAPACITY);
    }

    /// **ERL-008: constants match SPEC values.**
    #[test]
    fn test_constants() {
        assert_eq!(ERLAY_FLOOD_PEER_COUNT, 8);
        assert_eq!(ERLAY_RECONCILIATION_INTERVAL_MS, 2000);
        assert_eq!(ERLAY_SKETCH_CAPACITY, 20);
        assert_eq!(ERLAY_FLOOD_SET_ROTATION_SECS, 60);
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

    /// **ERL-003: ReconciliationSketch adds elements.**
    #[test]
    fn test_sketch_add() {
        let mut sketch = ReconciliationSketch::with_default_capacity();
        assert!(sketch.is_empty());

        sketch.add(&test_tx_id(1));
        sketch.add(&test_tx_id(2));
        assert_eq!(sketch.len(), 2);
        assert_eq!(sketch.capacity, ERLAY_SKETCH_CAPACITY);
    }

    /// **ERL-006: needs_rotation after interval.**
    #[test]
    fn test_needs_rotation_initial() {
        let state = ErlayState::new();
        // last_rotation = 0, current time > 60s → needs rotation
        assert!(state.needs_rotation());
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
