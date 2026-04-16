//! Tests for **INT-011: Dandelion stem phase on locally-originated transactions**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-011.md`
//! - **Master SPEC:** SS1.9.1
//!
//! INT-011 is satisfied when StemTransaction and should_fluff() are callable.

/// **INT-011: StemTransaction can be created.**
#[test]
#[cfg(feature = "dandelion")]
fn test_stem_transaction_new() {
    use dig_gossip::Bytes32;
    use dig_gossip::StemTransaction;

    let tx_id = Bytes32::from([42u8; 32]);
    let payload = vec![1u8, 2, 3];
    let stem_tx = StemTransaction::new(tx_id, payload.clone());

    assert_eq!(stem_tx.tx_id, tx_id);
    assert_eq!(stem_tx.payload, payload);
    assert!(stem_tx.stem_started_at > 0);
}

/// **INT-011: StemTransaction timeout check works.**
#[test]
#[cfg(feature = "dandelion")]
fn test_stem_transaction_timeout() {
    use dig_gossip::Bytes32;
    use dig_gossip::StemTransaction;

    let tx = StemTransaction::new(Bytes32::from([1u8; 32]), vec![]);

    // Just created: should NOT be timed out with a reasonable timeout
    assert!(
        !tx.is_timed_out(30),
        "freshly created stem tx should not be timed out"
    );

    // With 0 second timeout: should be timed out immediately
    assert!(
        tx.is_timed_out(0),
        "zero timeout should always be timed out"
    );
}

/// **INT-011: should_fluff is callable and returns bool.**
#[test]
#[cfg(feature = "dandelion")]
fn test_should_fluff_callable() {
    use dig_gossip::privacy::dandelion::should_fluff;

    // With probability 0.0: should never fluff
    for _ in 0..10 {
        assert!(!should_fluff(0.0), "0% probability should never fluff");
    }

    // With probability 1.0: should always fluff
    for _ in 0..10 {
        assert!(should_fluff(1.0), "100% probability should always fluff");
    }
}

/// **INT-011: DandelionConfig can be constructed with defaults.**
#[test]
#[cfg(feature = "dandelion")]
fn test_dandelion_config_default() {
    use dig_gossip::privacy::dandelion::DandelionConfig;

    let config = DandelionConfig::default();
    assert!(config.enabled);
    assert!((config.fluff_probability - 0.10).abs() < 0.001);
    assert_eq!(config.stem_timeout_secs, 30);
    assert_eq!(config.epoch_secs, 600);
}

/// **INT-011: StemRelayManager rotation and selection.**
#[test]
#[cfg(feature = "dandelion")]
fn test_stem_relay_manager() {
    use dig_gossip::privacy::dandelion::StemRelayManager;
    use dig_gossip::Bytes32;

    let mut mgr = StemRelayManager::new(600);
    assert!(mgr.relay().is_none());
    assert!(mgr.needs_rotation());

    let peers = vec![Bytes32::from([1u8; 32]), Bytes32::from([2u8; 32])];
    mgr.rotate(&peers);

    // After rotation, should have a relay selected
    assert!(mgr.relay().is_some());
    assert!(!mgr.needs_rotation());
}
