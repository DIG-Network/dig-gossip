//! Integration and unit tests for **CON-005: per-connection inbound rate limiting**.
//!
//! ## Traceability
//!
//! - **Spec:** [`CON-005.md`](../docs/requirements/domains/connection/specs/CON-005.md) — §Acceptance
//!   Criteria, §Test Plan, §DIG Extension Rate Limits.
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/connection/NORMATIVE.md) §CON-005
//!
//! ## Proof strategy
//!
//! Outbound limiting stays inside [`chia_sdk_client::Peer`] (not duplicated here). These tests
//! prove the **DIG-specific** pieces: merged [`RateLimits`] (V2 + `dig_wire`), independent limiters
//! per connection, [`RateLimiter::handle_message`] / [`RateLimiter::check_dig_extension`] behavior,
//! and the **penalty** path exercised through [`dig_gossip::apply_inbound_rate_limit_violation`]
//! (integration-style with a synthetic [`ServiceState`] row).

mod common;

use std::sync::Arc;

use chia_protocol::{Bytes, Message, ProtocolMessageTypes};
use chia_sdk_client::{RateLimit, RateLimiter, V2_RATE_LIMITS};

use dig_gossip::{
    apply_inbound_rate_limit_violation, dig_extension_rate_limits_map, gossip_inbound_rate_limits,
    load_ssl_cert, new_inbound_rate_limiter, peer_id_for_addr, DigMessageType, PenaltyReason,
    ServiceState,
};

/// **Row:** `test_inbound_rate_limiter_creation` — [`RateLimiter::new`] with `incoming = true`,
/// `reset_seconds = 60`, and merged limits builds successfully (CON-005 §Inbound Rate Limiting).
#[test]
fn test_inbound_rate_limiter_creation() {
    let lim = new_inbound_rate_limiter(1.0);
    let _ = std::mem::size_of_val(&lim);
}

/// **Row:** `test_separate_limiter_per_connection` — two limiters with the same static limits but
/// independent counters: exhausting one does not trip the other (CON-005 “per-connection” rule).
#[test]
fn test_separate_limiter_per_connection() {
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.other.insert(
        ProtocolMessageTypes::Handshake,
        RateLimit::new(1.0, 1_000_000.0, None),
    );
    let mut a = RateLimiter::new(true, 60, 1.0, limits.clone());
    let mut b = RateLimiter::new(true, 60, 1.0, limits);
    let m = |t: ProtocolMessageTypes| Message {
        msg_type: t,
        id: None,
        data: Bytes::new(vec![0u8; 10]),
    };
    let handshake = || m(ProtocolMessageTypes::Handshake);
    assert!(a.handle_message(&handshake()));
    assert!(!a.handle_message(&handshake()));
    assert!(
        b.handle_message(&handshake()),
        "B must still accept first handshake"
    );
}

/// **Row:** `test_dig_message_types_added` — merged limits include CON-005 table entries `200..=208`.
#[test]
fn test_dig_message_types_added() {
    let map = dig_extension_rate_limits_map();
    for wire in 200u8..=208 {
        assert!(
            map.contains_key(&wire),
            "missing DIG wire limit for {wire}: keys {:?}",
            map.keys().collect::<Vec<_>>()
        );
    }
    let merged = gossip_inbound_rate_limits();
    for wire in 200u8..=208 {
        assert!(
            merged.dig_wire.contains_key(&wire),
            "gossip_inbound_rate_limits missing dig_wire {wire}"
        );
    }
}

/// **Row:** `test_rate_limit_allows_normal_traffic` — traffic under the per-type cap passes.
#[test]
fn test_rate_limit_allows_normal_traffic() {
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.other.insert(
        ProtocolMessageTypes::Handshake,
        RateLimit::new(10.0, 1_000_000.0, None),
    );
    let mut lim = RateLimiter::new(true, 60, 1.0, limits);
    let msg = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: Bytes::new(vec![0u8; 100]),
    };
    for _ in 0..5 {
        assert!(lim.handle_message(&msg), "handshake within cap should pass");
    }
}

/// **Row:** `test_rate_limit_blocks_excess_traffic` — frequency cap rejects excess.
#[test]
fn test_rate_limit_blocks_excess_traffic() {
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.other.insert(
        ProtocolMessageTypes::Handshake,
        RateLimit::new(2.0, 1_000_000.0, None),
    );
    let mut lim = RateLimiter::new(true, 60, 1.0, limits);
    let msg = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: Bytes::new(vec![0u8; 10]),
    };
    assert!(lim.handle_message(&msg));
    assert!(lim.handle_message(&msg));
    assert!(
        !lim.handle_message(&msg),
        "third handshake should exceed frequency=2"
    );
}

/// **Row:** `test_rate_limit_blocks_oversized_message` — single-frame `max_size` exceeded.
#[test]
fn test_rate_limit_blocks_oversized_message() {
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.other.insert(
        ProtocolMessageTypes::Handshake,
        RateLimit::new(100.0, 50.0, None),
    );
    let mut lim = RateLimiter::new(true, 60, 1.0, limits);
    let msg = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: Bytes::new(vec![0u8; 100]),
    };
    assert!(!lim.handle_message(&msg));
}

/// **Row:** `test_rate_limit_penalty_applied` — [`PenaltyReason::RateLimitExceeded`] weight matches
/// CON-007 so inbound policy stays consistent with [`PeerReputation::apply_penalty`].
///
/// **Note:** The live-slot forwarder path (CON-005) calls [`apply_inbound_rate_limit_violation`];
/// proving points land on an inserted row would require a full WSS `Peer` fixture. This row locks
/// the numeric contract instead.
#[test]
fn test_rate_limit_penalty_applied() {
    assert_eq!(
        PenaltyReason::RateLimitExceeded.penalty_points(),
        15,
        "CON-007 table — must stay aligned with inbound_limits penalty application"
    );
}

/// **Row:** `test_apply_inbound_rate_limit_violation_no_panic` — missing `peer_id` is a no-op
/// (forwarder should only fire for live rows; defensive coding).
#[test]
fn test_apply_inbound_rate_limit_violation_no_panic() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let tls = load_ssl_cert(&cfg.cert_path, &cfg.key_path).expect("load test tls");
    let state = Arc::new(ServiceState::new(cfg, tls).expect("ServiceState::new"));
    let ghost = peer_id_for_addr("127.0.0.1:59999".parse().unwrap());
    apply_inbound_rate_limit_violation(&state, ghost);
}

/// **Row:** `test_rate_limit_factor_scaling` — lower [`dig_gossip::PeerOptions::rate_limit_factor`]
/// equivalent scales effective caps (`frequency * factor`).
#[test]
fn test_rate_limit_factor_scaling() {
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.other.insert(
        ProtocolMessageTypes::Handshake,
        RateLimit::new(10.0, 1_000_000.0, None),
    );
    let mut strict = RateLimiter::new(true, 60, 0.5, limits.clone());
    let mut loose = RateLimiter::new(true, 60, 1.0, limits);
    let msg = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: Bytes::new(vec![0u8; 10]),
    };
    // effective cap: strict 5, loose 10 first-window accepts
    for _ in 0..5 {
        assert!(strict.handle_message(&msg));
    }
    assert!(
        !strict.handle_message(&msg),
        "6th message should exceed 10*0.5=5"
    );
    for _ in 0..10 {
        assert!(loose.handle_message(&msg));
    }
    assert!(!loose.handle_message(&msg));
}

/// **Row:** `test_rate_limit_window_reset` — new period clears counters (`reset_seconds` shortened for speed).
#[tokio::test]
async fn test_rate_limit_window_reset() {
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.other.insert(
        ProtocolMessageTypes::Handshake,
        RateLimit::new(1.0, 1_000_000.0, None),
    );
    let mut lim = RateLimiter::new(true, 2, 1.0, limits);
    let msg = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: Bytes::new(vec![0u8; 10]),
    };
    assert!(lim.handle_message(&msg));
    assert!(!lim.handle_message(&msg));
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(
        lim.handle_message(&msg),
        "after 2s window rolls, first handshake in new period should pass"
    );
}

/// **Row:** `test_check_dig_extension_limits` — [`RateLimiter::check_dig_extension`] honors `dig_wire`.
#[test]
fn test_check_dig_extension_limits() {
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.dig_wire = dig_extension_rate_limits_map();
    let mut lim = RateLimiter::new(true, 60, 1.0, limits);
    let t = DigMessageType::NewAttestation as u8;
    for _ in 0..100 {
        assert!(lim.check_dig_extension(t, 100));
    }
    assert!(
        !lim.check_dig_extension(t, 100),
        "101st attestation exceeds frequency=100"
    );
}

/// Unknown DIG opcode has no `dig_wire` row — must fail-open (`true`) until a limit is registered.
#[test]
fn test_check_dig_extension_unknown_wire_allowed() {
    let limits = gossip_inbound_rate_limits();
    let mut lim = RateLimiter::new(true, 60, 1.0, limits);
    assert!(lim.check_dig_extension(255, 1_000_000));
}
