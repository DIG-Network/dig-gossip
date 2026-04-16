//! Tests for **ERL-008: ErlayConfig Struct**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/erlay/specs/ERL-008.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.3

#[cfg(feature = "erlay")]
mod tests {
    use dig_gossip::gossip::erlay::ErlayConfig;
    use dig_gossip::{
        ERLAY_FLOOD_PEER_COUNT, ERLAY_FLOOD_SET_ROTATION_SECS, ERLAY_RECONCILIATION_INTERVAL_MS,
        ERLAY_SKETCH_CAPACITY,
    };

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
}
