//! Tests for **PRI-005: BackpressureConfig**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/priority/specs/PRI-005.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.5

use dig_gossip::gossip::backpressure::{BackpressureConfig, BackpressureLevel};
use dig_gossip::{
    BACKPRESSURE_BULK_DROP_THRESHOLD, BACKPRESSURE_NORMAL_DELAY_THRESHOLD,
    BACKPRESSURE_TX_DEDUP_THRESHOLD, PRIORITY_STARVATION_RATIO,
};

/// **PRI-005: default thresholds match SPEC.**
#[test]
fn test_backpressure_config_defaults() {
    let c = BackpressureConfig::default();
    assert_eq!(c.tx_dedup_threshold, BACKPRESSURE_TX_DEDUP_THRESHOLD);
    assert_eq!(c.bulk_drop_threshold, BACKPRESSURE_BULK_DROP_THRESHOLD);
    assert_eq!(
        c.normal_delay_threshold,
        BACKPRESSURE_NORMAL_DELAY_THRESHOLD
    );
}

/// **PRI-005: constants match SPEC.**
#[test]
fn test_backpressure_constants() {
    assert_eq!(BACKPRESSURE_TX_DEDUP_THRESHOLD, 25);
    assert_eq!(BACKPRESSURE_BULK_DROP_THRESHOLD, 50);
    assert_eq!(BACKPRESSURE_NORMAL_DELAY_THRESHOLD, 100);
    assert_eq!(PRIORITY_STARVATION_RATIO, 10);
}

/// **PRI-005: level transitions at correct thresholds.**
#[test]
fn test_backpressure_levels() {
    let config = BackpressureConfig::default();

    assert_eq!(
        BackpressureLevel::from_depth(0, &config),
        BackpressureLevel::Normal
    );
    assert_eq!(
        BackpressureLevel::from_depth(24, &config),
        BackpressureLevel::Normal
    );
    assert_eq!(
        BackpressureLevel::from_depth(25, &config),
        BackpressureLevel::TxDedup
    );
    assert_eq!(
        BackpressureLevel::from_depth(49, &config),
        BackpressureLevel::TxDedup
    );
    assert_eq!(
        BackpressureLevel::from_depth(50, &config),
        BackpressureLevel::BulkDrop
    );
    assert_eq!(
        BackpressureLevel::from_depth(99, &config),
        BackpressureLevel::BulkDrop
    );
    assert_eq!(
        BackpressureLevel::from_depth(100, &config),
        BackpressureLevel::NormalDelay
    );
    assert_eq!(
        BackpressureLevel::from_depth(1000, &config),
        BackpressureLevel::NormalDelay
    );
}
