//! Tests for **PRI-008: Normal Delay Under Backpressure**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/priority/specs/PRI-008.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.5

use dig_gossip::gossip::backpressure::{BackpressureConfig, BackpressureState};

/// **PRI-008: normal delay at threshold.**
#[test]
fn test_normal_delay() {
    let state = BackpressureState::new(BackpressureConfig::default());

    assert!(!state.should_delay_normal(99));
    assert!(state.should_delay_normal(100));
    assert!(state.should_delay_normal(500));
}
