//! Tests for **INT-001: Broadcast via Plumtree (eager/lazy push)**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-001.md`
//! - **Master SPEC:** §8.1
//!
//! INT-001 is satisfied when broadcast() routes through PlumtreeState
//! rather than flat fan-out.

/// **INT-001: ServiceState has plumtree field.**
///
/// Proves Plumtree state is part of the shared service state.
#[test]
fn test_service_state_has_plumtree() {
    // Compiles = plumtree field exists on ServiceState.
    // Cannot construct ServiceState directly (needs TLS cert),
    // but the type check proves the field exists.
    fn _check_plumtree_field(state: &dig_gossip::ServiceState) {
        let _pt = state.plumtree.lock().unwrap();
    }
}

/// **INT-001: ServiceState has message_cache field.**
#[test]
fn test_service_state_has_message_cache() {
    fn _check_cache_field(state: &dig_gossip::ServiceState) {
        let _mc = state.message_cache.lock().unwrap();
    }
}

/// **INT-001: SeenSet compute_hash is deterministic.**
///
/// Proves dedup hash used by broadcast() is stable.
#[test]
fn test_seen_set_hash_deterministic() {
    use dig_gossip::gossip::seen_set::SeenSet;

    let h1 = SeenSet::compute_hash(20, b"payload");
    let h2 = SeenSet::compute_hash(20, b"payload");
    assert_eq!(h1, h2, "same input must produce same hash");

    let h3 = SeenSet::compute_hash(21, b"payload");
    assert_ne!(h1, h3, "different msg_type must produce different hash");
}

/// **INT-001: Plumtree add_peer registers new peer as eager.**
///
/// Proves peers start as eager (SPEC §8.1) which broadcast() uses.
#[test]
fn test_plumtree_integration_eager_default() {
    use dig_gossip::gossip::plumtree::PlumtreeState;
    use dig_gossip::Bytes32;

    let mut pt = PlumtreeState::new();
    let pid = Bytes32::from([1u8; 32]);
    pt.add_peer(pid);

    assert!(
        pt.is_eager(&pid),
        "new peers must start as eager for broadcast routing"
    );
    assert!(!pt.is_lazy(&pid));
}
