//! Tests for **PLT-005: Lazy Timeout and GRAFT**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/plumtree/specs/PLT-005.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.1

use dig_gossip::gossip::plumtree::PlumtreeState;
use dig_gossip::Bytes32;

fn test_peer_id(n: u8) -> Bytes32 {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    Bytes32::from(bytes)
}

/// **PLT-005: promote_to_eager moves peer from lazy to eager.**
///
/// Proves SPEC SS8.1: "Promote announcer from lazy to eager via GRAFT."
#[test]
fn test_promote_to_eager() {
    let mut state = PlumtreeState::new();
    let peer = test_peer_id(1);
    state.add_peer(peer);
    state.demote_to_lazy(&peer);

    state.promote_to_eager(&peer);

    assert!(state.is_eager(&peer));
    assert!(!state.is_lazy(&peer));
}
