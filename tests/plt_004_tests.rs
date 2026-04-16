//! Tests for **PLT-004: Duplicate Detection and Pruning**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/plumtree/specs/PLT-004.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.1

use dig_gossip::gossip::plumtree::PlumtreeState;
use dig_gossip::Bytes32;

fn test_peer_id(n: u8) -> Bytes32 {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    Bytes32::from(bytes)
}

/// **PLT-004: demote_to_lazy moves peer from eager to lazy.**
///
/// Proves SPEC SS8.1: "Demote sender to lazy, send PRUNE."
#[test]
fn test_demote_to_lazy() {
    let mut state = PlumtreeState::new();
    let peer = test_peer_id(1);
    state.add_peer(peer);

    state.demote_to_lazy(&peer);

    assert!(!state.is_eager(&peer));
    assert!(state.is_lazy(&peer));
    assert_eq!(state.eager_count(), 0);
    assert_eq!(state.lazy_count(), 1);
}
