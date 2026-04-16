//! Tests for **PRI-006: Transaction Deduplication Under Backpressure**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/priority/specs/PRI-006.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.5

use dig_gossip::gossip::backpressure::{BackpressureConfig, BackpressureState};
use dig_gossip::Bytes32;

fn test_tx_id(n: u8) -> Bytes32 {
    let mut b = [0u8; 32];
    b[0] = n;
    Bytes32::from(b)
}

/// **PRI-006: tx dedup -- first tx_id passes, duplicate suppressed.**
#[test]
fn test_tx_dedup() {
    let mut state = BackpressureState::new(BackpressureConfig::default());
    let tx = test_tx_id(1);

    // Below threshold: all pass
    assert!(state.should_send_tx(&tx, 10));
    assert!(state.should_send_tx(&tx, 10));

    // At threshold: first passes, duplicate suppressed
    assert!(state.should_send_tx(&test_tx_id(2), 30)); // new tx
    assert!(!state.should_send_tx(&test_tx_id(2), 30)); // duplicate
}
