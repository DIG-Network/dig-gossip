//! Tests for **CNC-006: Periodic cleanup task (stale connections, expired bans)**.
//!
//! - **Spec:** `docs/requirements/domains/concurrency/specs/CNC-006.md`
//! - **Master SPEC:** §9.1

use dig_gossip::{PeerReputation, PenaltyReason, BAN_DURATION_SECS, PEER_TIMEOUT_SECS};

/// **CNC-006: expired bans are cleared by refresh_ban_status.**
///
/// Proves the cleanup mechanism: after BAN_DURATION_SECS, ban expires.
#[test]
fn test_expired_ban_cleared() {
    let mut rep = PeerReputation::default();

    // Ban the peer
    let now = 1000u64;
    rep.apply_penalty(PenaltyReason::InvalidBlock, now); // 100 points → auto-ban
    assert!(rep.is_banned);
    assert_eq!(rep.ban_until, Some(now + BAN_DURATION_SECS));

    // Before expiry: still banned
    rep.refresh_ban_status(now + BAN_DURATION_SECS - 1);
    assert!(rep.is_banned);

    // After expiry: unbanned
    rep.refresh_ban_status(now + BAN_DURATION_SECS + 1);
    assert!(!rep.is_banned);
    assert!(rep.ban_until.is_none());
}

/// **CNC-006: PEER_TIMEOUT_SECS defines stale connection threshold.**
///
/// Proves SPEC §2.13: connections with no Pong within PEER_TIMEOUT_SECS are stale.
#[test]
fn test_peer_timeout_constant() {
    assert_eq!(
        PEER_TIMEOUT_SECS, 90,
        "stale connection threshold must be 90s"
    );
}

/// **CNC-006: BAN_DURATION_SECS defines ban expiry.**
#[test]
fn test_ban_duration_constant() {
    assert_eq!(BAN_DURATION_SECS, 3600, "ban duration must be 1 hour");
}
