//! Tests for **PRF-001: Latency-aware peer scoring (RTT tracking)**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/performance/specs/PRF-001.md`
//! - **Master SPEC:** §1.8#6, §2.5 (PeerReputation.avg_rtt_ms, rtt_history, score)
//!
//! ## What this file proves
//!
//! PRF-001 is satisfied when:
//! 1. record_rtt_ms() tracks RTT samples in a rolling window (RTT_WINDOW_SIZE=10)
//! 2. avg_rtt_ms is the arithmetic mean of recent samples
//! 3. score = trust_factor * (1/avg_rtt_ms), higher = better
//! 4. Lower RTT peers get higher scores (for outbound preference PRF-002)
//! 5. Zero/None avg_rtt_ms produces score 0.0 (no div-by-zero)

use dig_gossip::{PeerReputation, RTT_WINDOW_SIZE};

/// **PRF-001: RTT_WINDOW_SIZE = 10.**
#[test]
fn test_rtt_window_size() {
    assert_eq!(RTT_WINDOW_SIZE, 10, "SPEC §2.13: RTT window must be 10");
}

/// **PRF-001: record_rtt_ms updates avg and score.**
#[test]
fn test_record_rtt_updates_avg() {
    let mut rep = PeerReputation::default();
    assert!(rep.avg_rtt_ms.is_none(), "initial avg must be None");
    assert_eq!(rep.score, 0.0, "initial score must be 0");

    rep.record_rtt_ms(100);
    assert_eq!(rep.avg_rtt_ms, Some(100));
    assert!(rep.score > 0.0, "score must be positive after RTT sample");
}

/// **PRF-001: rolling window averages correctly.**
#[test]
fn test_rtt_rolling_average() {
    let mut rep = PeerReputation::default();

    // 5 samples of 100ms
    for _ in 0..5 {
        rep.record_rtt_ms(100);
    }
    assert_eq!(rep.avg_rtt_ms, Some(100));

    // 5 samples of 200ms → window full, avg = (5*100 + 5*200) / 10 = 150
    for _ in 0..5 {
        rep.record_rtt_ms(200);
    }
    assert_eq!(rep.avg_rtt_ms, Some(150));
}

/// **PRF-001: window evicts old samples at RTT_WINDOW_SIZE.**
#[test]
fn test_rtt_window_eviction() {
    let mut rep = PeerReputation::default();

    // Fill window with 10 samples of 100ms
    for _ in 0..10 {
        rep.record_rtt_ms(100);
    }
    assert_eq!(rep.avg_rtt_ms, Some(100));
    assert_eq!(rep.rtt_history.len(), 10);

    // Add 10 more at 200ms → all old samples evicted
    for _ in 0..10 {
        rep.record_rtt_ms(200);
    }
    assert_eq!(rep.avg_rtt_ms, Some(200));
    assert_eq!(rep.rtt_history.len(), 10);
}

/// **PRF-001: lower RTT → higher score.**
///
/// Proves SPEC §1.8#6: "low-latency peers preferred for outbound connections."
#[test]
fn test_lower_rtt_higher_score() {
    let mut fast = PeerReputation::default();
    fast.record_rtt_ms(50); // 50ms

    let mut slow = PeerReputation::default();
    slow.record_rtt_ms(500); // 500ms

    assert!(
        fast.score > slow.score,
        "50ms peer (score={}) must score higher than 500ms peer (score={})",
        fast.score,
        slow.score
    );
}

/// **PRF-001: score formula: trust * (1/avg_rtt_ms).**
///
/// With no penalties, trust_factor = 1.0.
/// score = 1.0 * (1.0 / 100.0) = 0.01
#[test]
fn test_score_formula() {
    let mut rep = PeerReputation::default();
    rep.record_rtt_ms(100);

    // trust = 1.0 (no penalties), score = 1.0 / 100.0 = 0.01
    let expected = 1.0 / 100.0_f64;
    assert!(
        (rep.score - expected).abs() < 1e-10,
        "score should be {expected}, got {}",
        rep.score
    );
}

/// **PRF-001: penalty reduces score via trust factor.**
#[test]
fn test_penalty_reduces_score() {
    let mut rep = PeerReputation::default();
    rep.record_rtt_ms(100);
    let score_before = rep.score;

    // Apply 50 penalty points (50% of ban threshold)
    rep.apply_penalty(dig_gossip::PenaltyReason::InvalidAttestation, 1000);
    // Trust drops, score should decrease
    assert!(
        rep.score < score_before,
        "penalty should reduce score: {} < {}",
        rep.score,
        score_before
    );
}

/// **PRF-001: zero RTT produces score 0 (no div-by-zero).**
#[test]
fn test_zero_rtt_no_crash() {
    let mut rep = PeerReputation::default();
    rep.record_rtt_ms(0);
    assert_eq!(rep.score, 0.0, "zero RTT must produce score 0, not panic");
}
