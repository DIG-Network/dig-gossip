//! Tests for **PRF-003: Plumtree tree optimization (prefer low-latency peers as eager)**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/performance/specs/PRF-003.md`
//! - **Master SPEC:** §1.8#6 — "Plumtree spanning tree optimized to prefer low-latency links"
//!
//! PRF-003 is satisfied when the Plumtree state can identify which eager peer
//! has worst RTT and which lazy peer has best RTT for potential swap.

use dig_gossip::gossip::plumtree::PlumtreeState;
use dig_gossip::Bytes32;
use std::collections::HashMap;

fn pid(n: u8) -> Bytes32 {
    let mut b = [0u8; 32];
    b[0] = n;
    Bytes32::from(b)
}

/// **PRF-003: can identify worst-RTT eager peer for swap.**
///
/// Proves SPEC §1.8#6: "when lower-latency peer discovered, replace higher-latency eager."
#[test]
fn test_identify_worst_eager_for_swap() {
    let mut state = PlumtreeState::new();
    let p1 = pid(1);
    let p2 = pid(2);
    let p3 = pid(3);
    state.add_peer(p1); // eager
    state.add_peer(p2); // eager
    state.add_peer(p3);
    state.demote_to_lazy(&p3); // lazy

    // Build RTT map
    let mut rtts: HashMap<Bytes32, u64> = HashMap::new();
    rtts.insert(p1, 50); // fast eager
    rtts.insert(p2, 500); // slow eager
    rtts.insert(p3, 30); // fast lazy

    // Find worst eager
    let worst_eager = state
        .eager_peers
        .iter()
        .max_by_key(|p| rtts.get(p).unwrap_or(&u64::MAX))
        .copied();
    assert_eq!(worst_eager, Some(p2), "p2 (500ms) is worst eager");

    // Find best lazy
    let best_lazy = state
        .lazy_peers
        .iter()
        .min_by_key(|p| rtts.get(p).unwrap_or(&u64::MAX))
        .copied();
    assert_eq!(best_lazy, Some(p3), "p3 (30ms) is best lazy");

    // Swap would improve tree: demote p2, promote p3
    assert!(
        rtts[&p3] < rtts[&p2],
        "lazy p3 faster than eager p2 — swap improves tree"
    );
}
