//! Tests for **API-006: [`PeerReputation`] and [`PenaltyReason`]**
//! (penalties, timed bans, RTT window, score, ASN slot).
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`API-006.md`](../docs/requirements/domains/crate_api/specs/API-006.md)
//! - **Point table:** [`CON-007.md`](../docs/requirements/domains/connection/specs/CON-007.md)
//! - **Constants:** [`crate::constants`] — `PENALTY_BAN_THRESHOLD`, `BAN_DURATION_SECS`, `RTT_WINDOW_SIZE`

use dig_gossip::{
    PeerReputation, PenaltyReason, BAN_DURATION_SECS, PENALTY_BAN_THRESHOLD, RTT_WINDOW_SIZE,
};

/// **Row:** `test_reputation_default`
#[test]
fn test_reputation_default() {
    let r = PeerReputation::default();
    assert_eq!(r.penalty_points, 0);
    assert!(!r.is_banned);
    assert_eq!(r.ban_until, None);
    assert_eq!(r.last_penalty_reason, None);
    assert_eq!(r.avg_rtt_ms, None);
    assert!(r.rtt_history.is_empty());
    assert_eq!(r.score, 0.0);
    assert_eq!(r.as_number, None);
}

/// **Row:** `test_penalty_accumulation`
#[test]
fn test_penalty_accumulation() {
    let mut r = PeerReputation::default();
    r.apply_penalty(PenaltyReason::ConnectionIssue, 1);
    r.apply_penalty(PenaltyReason::ConnectionIssue, 1);
    assert_eq!(
        r.penalty_points,
        PenaltyReason::ConnectionIssue.penalty_points() * 2
    );
}

/// **Row:** `test_auto_ban_at_threshold`
#[test]
fn test_auto_ban_at_threshold() {
    let mut r = PeerReputation::default();
    let t0 = 1_700_000_000u64;
    for _ in 0..10 {
        r.apply_penalty(PenaltyReason::ConnectionIssue, t0);
    }
    assert!(r.is_banned);
    assert_eq!(r.ban_until, Some(t0 + BAN_DURATION_SECS));
    assert!(r.penalty_points >= PENALTY_BAN_THRESHOLD);
}

/// **Row:** `test_ban_expiry`
#[test]
fn test_ban_expiry() {
    let mut r = PeerReputation::default();
    let t0 = 1000u64;
    r.apply_penalty(PenaltyReason::InvalidBlock, t0);
    assert!(r.is_banned);
    let until = r.ban_until.expect("ban_until set");
    r.refresh_ban_status(until);
    assert!(r.is_banned, "still banned at exact expiry boundary");
    r.refresh_ban_status(until + 1);
    assert!(!r.is_banned);
    assert_eq!(r.ban_until, None);
}

/// **Row:** `test_rtt_single_measurement`
#[test]
fn test_rtt_single_measurement() {
    let mut r = PeerReputation::default();
    r.record_rtt_ms(42);
    assert_eq!(r.avg_rtt_ms, Some(42));
}

/// **Row:** `test_rtt_rolling_average`
#[test]
fn test_rtt_rolling_average() {
    let mut r = PeerReputation::default();
    for _ in 0..RTT_WINDOW_SIZE {
        r.record_rtt_ms(100);
    }
    assert_eq!(r.avg_rtt_ms, Some(100));
    assert_eq!(r.rtt_history.len(), RTT_WINDOW_SIZE);
}

/// **Row:** `test_rtt_circular_buffer`
#[test]
fn test_rtt_circular_buffer() {
    let mut r = PeerReputation::default();
    for _ in 0..RTT_WINDOW_SIZE {
        r.record_rtt_ms(1000);
    }
    r.record_rtt_ms(2000);
    assert_eq!(r.rtt_history.len(), RTT_WINDOW_SIZE);
    let sum: u64 = r.rtt_history.iter().sum();
    // nine × 1000 + 2000 = 11000 → mean 1100
    assert_eq!(sum, 11_000);
    assert_eq!(r.avg_rtt_ms, Some(1100));
}

/// **Row:** `test_score_computation`
#[test]
fn test_score_computation() {
    let mut r = PeerReputation::default();
    r.record_rtt_ms(20);
    assert!(
        (r.score - 0.05).abs() < 1e-9,
        "score = 1/20 with trust1: {}",
        r.score
    );
}

/// **Row:** `test_score_zero_rtt`
#[test]
fn test_score_zero_rtt() {
    let mut r = PeerReputation::default();
    r.record_rtt_ms(0);
    assert_eq!(r.avg_rtt_ms, Some(0));
    assert_eq!(r.score, 0.0);
}

/// **Row:** `test_penalty_points_saturating`
#[test]
fn test_penalty_points_saturating() {
    let mut r = PeerReputation {
        penalty_points: u32::MAX - 5,
        ..Default::default()
    };
    r.apply_penalty(PenaltyReason::InvalidBlock, 0);
    assert_eq!(r.penalty_points, u32::MAX);
}

/// **Row:** `test_as_number_caching`
#[test]
fn test_as_number_caching() {
    let r = PeerReputation {
        as_number: Some(64_512),
        ..Default::default()
    };
    assert_eq!(r.as_number, Some(64_512));
}

/// **Row:** `test_penalty_reason_variants`
#[test]
fn test_penalty_reason_variants() {
    let _ = [
        PenaltyReason::InvalidBlock,
        PenaltyReason::InvalidAttestation,
        PenaltyReason::MalformedMessage,
        PenaltyReason::Spam,
        PenaltyReason::ConnectionIssue,
        PenaltyReason::ProtocolViolation,
        PenaltyReason::RateLimitExceeded,
        PenaltyReason::ConsensusError,
    ];
}

/// **Row:** `test_penalty_reason_clone_copy`
///
/// `PenaltyReason` is [`Copy`]; copies compare equal without heap allocation. (Clippy rejects redundant `.clone()`.)
#[test]
fn test_penalty_reason_clone_copy() {
    let a = PenaltyReason::Spam;
    let b = a;
    let c = a;
    assert_eq!(a, b);
    assert_eq!(a, c);
}

/// **Row:** `test_last_penalty_reason_updated`
#[test]
fn test_last_penalty_reason_updated() {
    let mut r = PeerReputation::default();
    r.apply_penalty(PenaltyReason::RateLimitExceeded, 0);
    assert_eq!(
        r.last_penalty_reason,
        Some(PenaltyReason::RateLimitExceeded)
    );
}

/// CON-007 weights are non-zero and cover the documented spread (regression guard).
#[test]
fn test_penalty_reason_weights_match_con007() {
    assert_eq!(PenaltyReason::InvalidBlock.penalty_points(), 100);
    assert_eq!(PenaltyReason::InvalidAttestation.penalty_points(), 50);
    assert_eq!(PenaltyReason::MalformedMessage.penalty_points(), 20);
    assert_eq!(PenaltyReason::Spam.penalty_points(), 25);
    assert_eq!(PenaltyReason::ConnectionIssue.penalty_points(), 10);
    assert_eq!(PenaltyReason::ProtocolViolation.penalty_points(), 50);
    assert_eq!(PenaltyReason::RateLimitExceeded.penalty_points(), 15);
    assert_eq!(PenaltyReason::ConsensusError.penalty_points(), 100);
}
