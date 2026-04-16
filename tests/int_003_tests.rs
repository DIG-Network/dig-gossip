//! Tests for **INT-003: Broadcast with adaptive backpressure**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-003.md`
//! - **Master SPEC:** SS8.5
//!
//! INT-003 is satisfied when BackpressureState is available and thresholds
//! produce correct backpressure levels.

use dig_gossip::gossip::backpressure::{BackpressureConfig, BackpressureLevel, BackpressureState};

/// **INT-003: BackpressureState can be created with default config.**
#[test]
fn test_backpressure_state_default() {
    let bp = BackpressureState::new(BackpressureConfig::default());
    // At depth 0, level is Normal
    assert_eq!(bp.level(0), BackpressureLevel::Normal);
}

/// **INT-003: BackpressureLevel thresholds match SPEC SS8.5.**
#[test]
fn test_backpressure_level_thresholds() {
    let config = BackpressureConfig::default();

    // 0-24: Normal
    assert_eq!(
        BackpressureLevel::from_depth(0, &config),
        BackpressureLevel::Normal
    );
    assert_eq!(
        BackpressureLevel::from_depth(24, &config),
        BackpressureLevel::Normal
    );

    // 25-49: TxDedup (PRI-006)
    assert_eq!(
        BackpressureLevel::from_depth(25, &config),
        BackpressureLevel::TxDedup
    );
    assert_eq!(
        BackpressureLevel::from_depth(49, &config),
        BackpressureLevel::TxDedup
    );

    // 50-99: BulkDrop (PRI-007)
    assert_eq!(
        BackpressureLevel::from_depth(50, &config),
        BackpressureLevel::BulkDrop
    );
    assert_eq!(
        BackpressureLevel::from_depth(99, &config),
        BackpressureLevel::BulkDrop
    );

    // 100+: NormalDelay (PRI-008)
    assert_eq!(
        BackpressureLevel::from_depth(100, &config),
        BackpressureLevel::NormalDelay
    );
    assert_eq!(
        BackpressureLevel::from_depth(500, &config),
        BackpressureLevel::NormalDelay
    );
}

/// **INT-003: Tx dedup suppression activates at threshold (PRI-006).**
#[test]
fn test_backpressure_tx_dedup() {
    let mut bp = BackpressureState::new(BackpressureConfig::default());
    let tx_id = dig_gossip::Bytes32::from([1u8; 32]);

    // Below threshold: always send
    assert!(bp.should_send_tx(&tx_id, 10));
    // At threshold: first tx passes
    assert!(bp.should_send_tx(&tx_id, 30));
    // Same tx at threshold: suppressed (already seen)
    assert!(!bp.should_send_tx(&tx_id, 30));
}

/// **INT-003: Bulk messages dropped at threshold (PRI-007).**
#[test]
fn test_backpressure_bulk_drop() {
    let bp = BackpressureState::new(BackpressureConfig::default());

    // Below threshold: not dropped
    assert!(!bp.should_drop_bulk(10));
    assert!(!bp.should_drop_bulk(49));

    // At/above threshold: dropped
    assert!(bp.should_drop_bulk(50));
    assert!(bp.should_drop_bulk(100));
}

/// **INT-003: Normal messages delayed at threshold (PRI-008).**
#[test]
fn test_backpressure_normal_delay() {
    let bp = BackpressureState::new(BackpressureConfig::default());

    // Below threshold: not delayed
    assert!(!bp.should_delay_normal(10));
    assert!(!bp.should_delay_normal(99));

    // At/above threshold: delayed
    assert!(bp.should_delay_normal(100));
    assert!(bp.should_delay_normal(200));
}

/// **INT-003: Custom BackpressureConfig thresholds work.**
#[test]
fn test_backpressure_custom_config() {
    let config = BackpressureConfig {
        tx_dedup_threshold: 10,
        bulk_drop_threshold: 20,
        normal_delay_threshold: 30,
    };

    assert_eq!(
        BackpressureLevel::from_depth(9, &config),
        BackpressureLevel::Normal
    );
    assert_eq!(
        BackpressureLevel::from_depth(10, &config),
        BackpressureLevel::TxDedup
    );
    assert_eq!(
        BackpressureLevel::from_depth(20, &config),
        BackpressureLevel::BulkDrop
    );
    assert_eq!(
        BackpressureLevel::from_depth(30, &config),
        BackpressureLevel::NormalDelay
    );
}

/// **INT-003: Tx dedup reset clears seen tx IDs.**
#[test]
fn test_backpressure_tx_dedup_reset() {
    let mut bp = BackpressureState::new(BackpressureConfig::default());
    let tx_id = dig_gossip::Bytes32::from([1u8; 32]);

    // First send passes, second suppressed
    assert!(bp.should_send_tx(&tx_id, 30));
    assert!(!bp.should_send_tx(&tx_id, 30));

    // After reset, same tx passes again
    bp.reset_tx_dedup();
    assert!(bp.should_send_tx(&tx_id, 30));
}
