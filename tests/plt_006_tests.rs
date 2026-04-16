//! Tests for **PLT-006: Tree Self-Healing on Disconnect**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/plumtree/specs/PLT-006.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.1

use dig_gossip::gossip::plumtree::PlumtreeState;
use dig_gossip::Bytes32;

fn test_peer_id(n: u8) -> Bytes32 {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    Bytes32::from(bytes)
}

/// **PLT-006: remove_peer removes from both sets.**
///
/// Proves SPEC SS8.1: tree self-healing after peer disconnect.
#[test]
fn test_remove_peer() {
    let mut state = PlumtreeState::new();
    let p1 = test_peer_id(1);
    let p2 = test_peer_id(2);
    state.add_peer(p1);
    state.add_peer(p2);
    state.demote_to_lazy(&p2);

    state.remove_peer(&p1);
    state.remove_peer(&p2);

    assert_eq!(state.peer_count(), 0);
}
