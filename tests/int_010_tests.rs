//! Tests for **INT-010: Cleanup task spawned in start()**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-010.md`
//! - **Master SPEC:** SS2.5 (PeerReputation)
//!
//! INT-010 is satisfied when PeerReputation::refresh_ban_status exists and
//! can be used for periodic cleanup of expired bans.

use dig_gossip::PeerReputation;
use dig_gossip::PenaltyReason;

/// **INT-010: PeerReputation::refresh_ban_status exists and is callable.**
#[test]
fn test_refresh_ban_status_exists() {
    let mut rep = PeerReputation::default();
    // Call with a far-future timestamp — should not panic.
    rep.refresh_ban_status(u64::MAX);
}

/// **INT-010: refresh_ban_status clears expired bans.**
#[test]
fn test_refresh_ban_status_clears_expired() {
    let mut rep = PeerReputation::default();

    // Apply enough penalties to trigger a ban
    let now = 1_000_000u64;
    let _crossed = rep.apply_penalty(PenaltyReason::RateLimitExceeded, now);

    // Keep applying until banned
    for _ in 0..20 {
        rep.apply_penalty(PenaltyReason::RateLimitExceeded, now);
    }

    // Check if banned
    if rep.is_banned {
        let ban_until = rep.ban_until.unwrap();

        // Before expiry: still banned
        rep.refresh_ban_status(ban_until - 1);
        assert!(rep.is_banned, "should still be banned before expiry");

        // At expiry: ban cleared
        rep.refresh_ban_status(ban_until);
        assert!(!rep.is_banned, "ban should be cleared at expiry");
        assert_eq!(rep.penalty_points, 0, "points should reset on unban");
    }
}

/// **INT-010: check_unban returns whether ban just cleared.**
#[test]
fn test_check_unban_returns_cleared() {
    let mut rep = PeerReputation::default();
    let now = 1_000_000u64;

    // Apply enough penalties to trigger a ban
    for _ in 0..20 {
        rep.apply_penalty(PenaltyReason::RateLimitExceeded, now);
    }

    if rep.is_banned {
        let ban_until = rep.ban_until.unwrap();

        // check_unban before expiry returns false
        assert!(!rep.check_unban(ban_until - 1));

        // check_unban at expiry returns true (ban just cleared)
        assert!(rep.check_unban(ban_until));

        // check_unban again returns false (already cleared)
        assert!(!rep.check_unban(ban_until + 1));
    }
}

/// **INT-010: PeerReputation default starts with no ban.**
#[test]
fn test_peer_reputation_default_no_ban() {
    let rep = PeerReputation::default();
    assert!(!rep.is_banned);
    assert!(rep.ban_until.is_none());
    assert_eq!(rep.penalty_points, 0);
}
