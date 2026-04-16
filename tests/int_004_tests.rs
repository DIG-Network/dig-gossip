//! Tests for **INT-004: ERLAY routing for NewTransaction (flood set only)**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-004.md`
//! - **Master SPEC:** SS8.3
//!
//! INT-004 is satisfied when ErlayState can classify flood vs non-flood peers,
//! so broadcast can route NewTransaction to the flood set only.

/// **INT-004: ErlayState can be created and starts with empty flood set.**
#[test]
#[cfg(feature = "erlay")]
fn test_erlay_state_new() {
    use dig_gossip::ErlayState;

    let erlay = ErlayState::new();
    assert_eq!(erlay.flood_set_size(), 0);
    assert_eq!(erlay.local_tx_count(), 0);
}

/// **INT-004: ErlayState classifies flood vs non-flood peers.**
#[test]
#[cfg(feature = "erlay")]
fn test_erlay_flood_set_classification() {
    use dig_gossip::Bytes32;
    use dig_gossip::ErlayState;

    let mut erlay = ErlayState::new();
    let peer_a = Bytes32::from([1u8; 32]);
    let peer_b = Bytes32::from([2u8; 32]);
    let peer_c = Bytes32::from([3u8; 32]);

    // Select flood set with 2 peers (peer_a, peer_b)
    erlay.select_flood_set(&[peer_a, peer_b]);

    // Both should be in flood set
    assert!(erlay.is_flood_peer(&peer_a));
    assert!(erlay.is_flood_peer(&peer_b));

    // peer_c is NOT in flood set
    assert!(!erlay.is_flood_peer(&peer_c));
}

/// **INT-004: ErlayState add_local_tx tracks transaction IDs.**
#[test]
#[cfg(feature = "erlay")]
fn test_erlay_local_tx_tracking() {
    use dig_gossip::Bytes32;
    use dig_gossip::ErlayState;

    let mut erlay = ErlayState::new();
    assert_eq!(erlay.local_tx_count(), 0);

    erlay.add_local_tx(Bytes32::from([1u8; 32]));
    assert_eq!(erlay.local_tx_count(), 1);

    // Duplicate does not increase count (HashSet)
    erlay.add_local_tx(Bytes32::from([1u8; 32]));
    assert_eq!(erlay.local_tx_count(), 1);

    erlay.add_local_tx(Bytes32::from([2u8; 32]));
    assert_eq!(erlay.local_tx_count(), 2);

    erlay.clear_local_txs();
    assert_eq!(erlay.local_tx_count(), 0);
}

/// **INT-004: ErlayConfig default values match SPEC SS8.3.**
#[test]
#[cfg(feature = "erlay")]
fn test_erlay_config_defaults() {
    use dig_gossip::gossip::erlay::ErlayConfig;

    let config = ErlayConfig::default();
    assert_eq!(config.flood_peer_count, dig_gossip::ERLAY_FLOOD_PEER_COUNT);
    assert_eq!(
        config.reconciliation_interval_ms,
        dig_gossip::ERLAY_RECONCILIATION_INTERVAL_MS
    );
    assert_eq!(config.sketch_capacity, dig_gossip::ERLAY_SKETCH_CAPACITY);
}

/// **INT-004: ErlayState flood set rotation check.**
#[test]
#[cfg(feature = "erlay")]
fn test_erlay_needs_rotation() {
    use dig_gossip::Bytes32;
    use dig_gossip::ErlayState;

    let mut erlay = ErlayState::new();
    // Initially with no peers, needs_rotation should be true (last_rotation = 0)
    assert!(erlay.needs_rotation());

    // After selecting flood set, should NOT need rotation immediately
    let peers = vec![Bytes32::from([1u8; 32])];
    erlay.select_flood_set(&peers);
    assert!(!erlay.needs_rotation());
}

/// **INT-004: ReconciliationSketch can be created and populated.**
#[test]
#[cfg(feature = "erlay")]
fn test_reconciliation_sketch_basic() {
    use dig_gossip::Bytes32;
    use dig_gossip::ReconciliationSketch;

    let mut sketch = ReconciliationSketch::with_default_capacity();
    assert!(sketch.is_empty());
    assert_eq!(sketch.len(), 0);

    sketch.add(&Bytes32::from([1u8; 32]));
    assert_eq!(sketch.len(), 1);
    assert!(!sketch.is_empty());
}
