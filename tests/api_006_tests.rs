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

/// **Row:** `test_reputation_default` -- fresh reputation has zero penalties, no ban, no RTT.
/// SPEC §2.5 — `PeerReputation` default: `penalty_points: 0`, `is_banned: false`,
/// `ban_until: None`, `avg_rtt_ms: None`, `score: 0.0`, `as_number: None`.
///
/// This proves the initial state for a newly connected peer: clean slate with neutral score.
/// All subsequent reputation changes are relative to this baseline.
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

/// **Row:** `test_penalty_accumulation` -- repeated penalties of the same type stack additively.
///
/// Two `ConnectionIssue` penalties (10 points each per CON-007) should yield 20 total.
/// This proves the accumulation model is additive, not replacing or maxing.
#[test]
fn test_penalty_accumulation() {
    let mut r = PeerReputation::default();
    let _ = r.apply_penalty(PenaltyReason::ConnectionIssue, 1);
    let _ = r.apply_penalty(PenaltyReason::ConnectionIssue, 1);
    assert_eq!(
        r.penalty_points,
        PenaltyReason::ConnectionIssue.penalty_points() * 2
    );
}

/// **Row:** `test_auto_ban_at_threshold` -- crossing `PENALTY_BAN_THRESHOLD` triggers auto-ban.
///
/// Ten `ConnectionIssue` penalties (10 * 10 = 100 points) should cross the threshold,
/// setting `is_banned = true` and `ban_until` to `t0 + BAN_DURATION_SECS`. This is the
/// primary mechanism for ejecting misbehaving peers automatically.
#[test]
fn test_auto_ban_at_threshold() {
    let mut r = PeerReputation::default();
    let t0 = 1_700_000_000u64;
    for _ in 0..10 {
        let _ = r.apply_penalty(PenaltyReason::ConnectionIssue, t0);
    }
    assert!(r.is_banned);
    assert_eq!(r.ban_until, Some(t0 + BAN_DURATION_SECS));
    assert!(r.penalty_points >= PENALTY_BAN_THRESHOLD);
}

/// **Row:** `test_ban_expiry` -- bans are time-limited, not permanent.
///
/// After `InvalidBlock` (100 points, instant ban), `refresh_ban_status` at the exact
/// `ban_until` timestamp lifts the ban (**CON-007** inclusive `>=` boundary) and resets
/// `penalty_points` to zero so the peer earns a clean slate.
#[test]
fn test_ban_expiry() {
    let mut r = PeerReputation::default();
    let t0 = 1000u64;
    let _ = r.apply_penalty(PenaltyReason::InvalidBlock, t0);
    assert!(r.is_banned);
    let until = r.ban_until.expect("ban_until set");
    r.refresh_ban_status(until);
    assert!(!r.is_banned);
    assert_eq!(r.ban_until, None);
    assert_eq!(r.penalty_points, 0);
}

/// **Row:** `test_rtt_single_measurement` -- a single RTT sample sets `avg_rtt_ms` directly.
///
/// With one data point, the average equals the sample. This baseline is needed before
/// testing the rolling window behavior.
#[test]
fn test_rtt_single_measurement() {
    let mut r = PeerReputation::default();
    r.record_rtt_ms(42);
    assert_eq!(r.avg_rtt_ms, Some(42));
}

/// **Row:** `test_rtt_rolling_average` -- filling the window with identical values yields that value.
///
/// RTT_WINDOW_SIZE samples of 100ms each should produce avg=100ms and a full buffer.
/// This proves the window caps at the expected size and the average calculation is correct
/// for the uniform case.
#[test]
fn test_rtt_rolling_average() {
    let mut r = PeerReputation::default();
    for _ in 0..RTT_WINDOW_SIZE {
        r.record_rtt_ms(100);
    }
    assert_eq!(r.avg_rtt_ms, Some(100));
    assert_eq!(r.rtt_history.len(), RTT_WINDOW_SIZE);
}

/// **Row:** `test_rtt_circular_buffer` -- oldest sample is evicted when window is full.
///
/// After filling with 1000ms samples, one 2000ms sample replaces the oldest entry.
/// Sum = 9*1000 + 2000 = 11000, mean = 1100. This proves FIFO eviction and that the
/// buffer never grows beyond `RTT_WINDOW_SIZE`.
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

/// **Row:** `test_score_computation` -- score = trust_factor / avg_rtt_ms.
///
/// With a single 20ms RTT sample and implicit trust factor of 1.0, score = 1/20 = 0.05.
/// Lower RTT = higher score, incentivizing fast peers. The tolerance `1e-9` handles
/// floating-point imprecision.
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

/// **Row:** `test_score_zero_rtt` -- zero RTT does not cause division-by-zero; score stays 0.
///
/// This edge case (loopback or broken clock) must not panic or produce infinity/NaN.
#[test]
fn test_score_zero_rtt() {
    let mut r = PeerReputation::default();
    r.record_rtt_ms(0);
    assert_eq!(r.avg_rtt_ms, Some(0));
    assert_eq!(r.score, 0.0);
}

/// **Row:** `test_penalty_points_saturating` -- points saturate at `u32::MAX` instead of wrapping.
///
/// Starting near `u32::MAX`, an `InvalidBlock` penalty (100 points) should clamp to MAX
/// rather than overflowing. This prevents a wrap-around bug where a heavily penalized
/// peer could suddenly appear clean.
#[test]
fn test_penalty_points_saturating() {
    let mut r = PeerReputation {
        penalty_points: u32::MAX - 5,
        ..Default::default()
    };
    let _ = r.apply_penalty(PenaltyReason::InvalidBlock, 0);
    assert_eq!(r.penalty_points, u32::MAX);
}

/// **Row:** `test_as_number_caching` -- ASN slot stores and returns the cached value.
///
/// AS number is used for "one outbound per ASN" diversity policy. Storing 64512
/// (a private ASN) proves the `Option<u32>` field works for both populated and empty states.
#[test]
fn test_as_number_caching() {
    let r = PeerReputation {
        as_number: Some(64_512),
        ..Default::default()
    };
    assert_eq!(r.as_number, Some(64_512));
}

/// **Row:** `test_penalty_reason_variants` -- all eight penalty reasons are constructible.
/// SPEC §2.5 — `PenaltyReason` enum: InvalidBlock, InvalidAttestation, MalformedMessage,
/// Spam, ConnectionIssue, ProtocolViolation, RateLimitExceeded, ConsensusError.
///
/// This exhaustiveness test ensures no variant was accidentally removed or renamed.
/// If a new reason is added to the enum, this test should be updated to include it.
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

/// **Row:** `test_last_penalty_reason_updated` -- `apply_penalty` records the most recent reason.
///
/// Operators need to know *why* a peer was last penalized for debugging and ban review.
/// The `last_penalty_reason` field provides this diagnostic breadcrumb.
#[test]
fn test_last_penalty_reason_updated() {
    let mut r = PeerReputation::default();
    let _ = r.apply_penalty(PenaltyReason::RateLimitExceeded, 0);
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
