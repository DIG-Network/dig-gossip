//! Tests for **PRF-002: Peer selection preference by composite score**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/performance/specs/PRF-002.md`
//! - **Master SPEC:** §1.8#6 — "outbound selection prefers higher-scored peers"
//!
//! PRF-002 is satisfied when peers with higher scores are preferred
//! during outbound selection. This is tested by verifying the score
//! ordering property from PRF-001.

use dig_gossip::PeerReputation;

/// **PRF-002: score ordering enables peer selection preference.**
///
/// When multiple candidates pass group/AS filter, the one with
/// highest score (lowest RTT, lowest penalties) should be selected.
#[test]
fn test_score_ordering_for_selection() {
    let mut peers: Vec<(String, PeerReputation)> = vec![
        ("slow".into(), PeerReputation::default()),
        ("fast".into(), PeerReputation::default()),
        ("medium".into(), PeerReputation::default()),
    ];

    peers[0].1.record_rtt_ms(500); // slow
    peers[1].1.record_rtt_ms(50); // fast
    peers[2].1.record_rtt_ms(200); // medium

    // Sort by score descending (highest first = best candidate)
    peers.sort_by(|a, b| b.1.score.partial_cmp(&a.1.score).unwrap());

    assert_eq!(peers[0].0, "fast", "fastest peer must rank first");
    assert_eq!(peers[1].0, "medium");
    assert_eq!(peers[2].0, "slow", "slowest peer must rank last");
}

/// **PRF-002: penalized peer ranks lower even with good RTT.**
#[test]
fn test_penalized_peer_ranks_lower() {
    let mut good = PeerReputation::default();
    good.record_rtt_ms(100);

    let mut penalized = PeerReputation::default();
    penalized.record_rtt_ms(100); // same RTT
    penalized.apply_penalty(dig_gossip::PenaltyReason::Spam, 1000);

    assert!(
        good.score > penalized.score,
        "unpenalized peer must rank above penalized peer with same RTT"
    );
}
