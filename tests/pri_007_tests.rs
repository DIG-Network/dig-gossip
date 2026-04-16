//! Tests for **PRI-007: Bulk Drop Under Backpressure**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/priority/specs/PRI-007.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.5

use dig_gossip::gossip::backpressure::{BackpressureConfig, BackpressureState};

/// **PRI-007: bulk drop at threshold.**
#[test]
fn test_bulk_drop() {
    let state = BackpressureState::new(BackpressureConfig::default());

    assert!(!state.should_drop_bulk(49));
    assert!(state.should_drop_bulk(50));
    assert!(state.should_drop_bulk(100));
}
