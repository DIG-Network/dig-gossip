//! Integration + focused unit tests for **CON-007: Peer banning via reputation**
//! ([`PenaltyReason`] accumulation, [`PeerReputation`] timed bans, and
//! [`chia_sdk_client::ClientState`] `ban` / `unban` mirroring).
//!
//! ## Traceability
//!
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/connection/NORMATIVE.md)
//! - **Spec + test plan table:** [`CON-007.md`](../docs/requirements/domains/connection/specs/CON-007.md)
//! - **Implementation:** [`dig_gossip::service::gossip_handle::GossipHandle::penalize_peer`],
//!   [`dig_gossip::service::state::ServiceState`], [`dig_gossip::types::reputation::PeerReputation`]
//!
//! ## How these tests map to CON-007.md § Test Plan
//!
//! Each `#[test]` / `#[tokio::test]` name aligns with a **Row** in the markdown table so reviewers
//! can grep the spec file and find the proving test in this file.

mod common;

use std::net::SocketAddr;

use dig_gossip::{
    BAN_DURATION_SECS, GossipError, GossipHandle, GossipService, NodeType, PeerReputation,
    PenaltyReason, RequestPeers,
};

// ---------------------------------------------------------------------------
// Unit rows — `PeerReputation` pure logic (same process as API-006, duplicated here
// per CON-007.md "Expected Test Files: tests/con_007_tests.rs")
// ---------------------------------------------------------------------------

/// **Row:** `test_penalty_accumulation` — five `ConnectionIssue` penalties (10 pts each) ⇒ 50.
#[test]
fn test_penalty_accumulation() {
    let mut r = PeerReputation::default();
    for _ in 0..5 {
        let _ = r.apply_penalty(PenaltyReason::ConnectionIssue, 1);
    }
    assert_eq!(r.penalty_points, 50);
}

/// **Row:** `test_ban_at_threshold` — exactly 100 pts triggers `is_banned` + `ban_until`.
#[test]
fn test_ban_at_threshold() {
    let mut r = PeerReputation::default();
    let t0 = 2_000u64;
    for _ in 0..10 {
        let _ = r.apply_penalty(PenaltyReason::ConnectionIssue, t0);
    }
    assert!(r.is_banned);
    assert_eq!(r.ban_until, Some(t0 + BAN_DURATION_SECS));
}

/// **Row:** `test_ban_above_threshold` — overshooting to 120 pts still leaves a single ban window.
#[test]
fn test_ban_above_threshold() {
    let mut r = PeerReputation::default();
    let t0 = 3_000u64;
    for _ in 0..12 {
        let _ = r.apply_penalty(PenaltyReason::ConnectionIssue, t0);
    }
    assert!(r.is_banned);
    assert!(r.penalty_points >= 120);
}

/// **Row:** `test_immediate_ban_invalid_block`
#[test]
fn test_immediate_ban_invalid_block() {
    let mut r = PeerReputation::default();
    let _ = r.apply_penalty(PenaltyReason::InvalidBlock, 0);
    assert!(r.is_banned);
}

/// **Row:** `test_immediate_ban_consensus_error`
#[test]
fn test_immediate_ban_consensus_error() {
    let mut r = PeerReputation::default();
    let _ = r.apply_penalty(PenaltyReason::ConsensusError, 0);
    assert!(r.is_banned);
}

/// **Row:** `test_auto_unban_after_duration` — advance clock to `ban_until`, `check_unban` clears state.
#[test]
fn test_auto_unban_after_duration() {
    let mut r = PeerReputation::default();
    let t0 = 10_000u64;
    let _ = r.apply_penalty(PenaltyReason::InvalidBlock, t0);
    let until = r.ban_until.expect("ban");
    assert!(r.check_unban(until));
    assert!(!r.is_banned);
    assert_eq!(r.penalty_points, 0);
}

/// **Row:** `test_no_unban_before_duration` — one second before `ban_until`, still banned.
#[test]
fn test_no_unban_before_duration() {
    let mut r = PeerReputation::default();
    let t0 = 20_000u64;
    let _ = r.apply_penalty(PenaltyReason::InvalidBlock, t0);
    let until = r.ban_until.expect("ban");
    assert!(!r.check_unban(until.saturating_sub(1)));
    assert!(r.is_banned);
}

/// **Row:** `test_idempotent_ban` — second burst past threshold must not shift `ban_until`.
#[test]
fn test_idempotent_ban() {
    let mut r = PeerReputation::default();
    let t0 = 100u64;
    for _ in 0..10 {
        let _ = r.apply_penalty(PenaltyReason::ConnectionIssue, t0);
    }
    let until_first = r.ban_until;
    let t1 = t0 + 50;
    for _ in 0..5 {
        let _ = r.apply_penalty(PenaltyReason::ConnectionIssue, t1);
    }
    assert_eq!(r.ban_until, until_first);
}

/// **Row:** `test_last_penalty_reason_updated`
#[test]
fn test_last_penalty_reason_updated() {
    let mut r = PeerReputation::default();
    let _ = r.apply_penalty(PenaltyReason::Spam, 0);
    let _ = r.apply_penalty(PenaltyReason::MalformedMessage, 0);
    assert_eq!(
        r.last_penalty_reason,
        Some(PenaltyReason::MalformedMessage)
    );
}

// ---------------------------------------------------------------------------
// Integration rows — `GossipHandle` + `ClientState` shadow table
// ---------------------------------------------------------------------------

async fn running_handle() -> (GossipService, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    (svc, h)
}

/// **Row:** `test_client_state_ban_called` — auto-ban calls upstream IP ban for the stub's IP.
#[tokio::test]
async fn test_client_state_ban_called() {
    let (_s, h) = running_handle().await;
    let addr: SocketAddr = "127.0.0.1:20001".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(addr, NodeType::FullNode, true)
        .await
        .unwrap();
    for _ in 0..4 {
        h.penalize_peer(&pid, PenaltyReason::Spam).await.unwrap();
    }
    assert!(
        h.__con007_chia_client_is_ip_banned_for_tests(addr.ip())
            .await,
        "ClientState must record the IPv4 from the stub SocketAddr"
    );
}

/// **Row:** `test_client_state_unban_called` — pruning at expiry clears Chia's ban map entry.
#[tokio::test]
async fn test_client_state_unban_called() {
    let (_s, h) = running_handle().await;
    let addr: SocketAddr = "127.0.0.1:20002".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(addr, NodeType::FullNode, true)
        .await
        .unwrap();
    for _ in 0..4 {
        h.penalize_peer(&pid, PenaltyReason::Spam).await.unwrap();
    }
    assert!(h.__con007_chia_client_is_ip_banned_for_tests(addr.ip()).await);
    // Any wall clock `>= DigBanEntry::until` evicts the row — use a far-future constant so the
    // test is deterministic regardless of when `penalize_peer` ran on the host clock.
    h.__con007_prune_expired_bans_for_tests(u64::MAX / 2).await;
    assert!(
        !h.__con007_chia_client_is_ip_banned_for_tests(addr.ip())
            .await
    );
}

/// **Row:** `test_banned_peer_disconnected` — crossing threshold empties the peer map.
#[tokio::test]
async fn test_banned_peer_disconnected() {
    let (_s, h) = running_handle().await;
    let addr: SocketAddr = "127.0.0.1:20003".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(addr, NodeType::FullNode, true)
        .await
        .unwrap();
    for _ in 0..4 {
        h.penalize_peer(&pid, PenaltyReason::Spam).await.unwrap();
    }
    assert_eq!(h.peer_count().await, 0);
    let err = h.send_to(pid, RequestPeers::new()).await.unwrap_err();
    assert!(matches!(err, GossipError::PeerBanned(_)));
}
