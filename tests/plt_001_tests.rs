//! Tests for **PLT-001: PlumtreeState Structure**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/plumtree/specs/PLT-001.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.1

use dig_gossip::gossip::plumtree::PlumtreeState;
use dig_gossip::Bytes32;

fn test_peer_id(n: u8) -> Bytes32 {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    Bytes32::from(bytes)
}

/// **PLT-001: new peers start as eager.**
///
/// Proves SPEC SS8.1: "All newly connected peers MUST start in eager_peers."
#[test]
fn test_new_peer_is_eager() {
    let mut state = PlumtreeState::new();
    let peer = test_peer_id(1);
    state.add_peer(peer);

    assert!(state.is_eager(&peer));
    assert!(!state.is_lazy(&peer));
    assert_eq!(state.eager_count(), 1);
    assert_eq!(state.lazy_count(), 0);
}

/// **PLT-001: lazy_timeout_ms defaults to 500.**
///
/// Proves SPEC SS8.1: "lazy_timeout_ms configurable (default 500ms)."
#[test]
fn test_default_lazy_timeout() {
    let state = PlumtreeState::new();
    assert_eq!(state.lazy_timeout_ms, 500);
}
