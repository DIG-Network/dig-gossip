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
//! prove the **DIG-specific** pieces: the DIG per-opcode table, independent limiters per
//! connection, [`OpcodeRateLimiter::allow`] / [`DigRateLimiter::check`] behavior,
//! and the **penalty** path exercised through [`dig_gossip::apply_inbound_rate_limit_violation`]
//! (integration-style with a synthetic [`ServiceState`] row).

mod common;

use std::sync::Arc;

use dig_gossip::{Bytes, DigMessage, ProtocolMessageTypes};
use dig_gossip::{Admission, OpcodeRateLimiter, OpcodeRateLimits, RateLimit, V2_RATE_LIMITS};

use dig_gossip::{
    apply_inbound_rate_limit_violation, dig_extension_rate_limits_map, load_ssl_cert,
    new_inbound_rate_limiter, peer_id_for_addr, CandidateAddr, DigMessageType, DigRateLimiter,
    HoldingsAnnounce, HoldingsDelta, PenaltyReason, ServiceState, HOLDINGS_ANNOUNCE,
    HOLDINGS_MAX_CHANGES,
};

/// A DIG limiter over the production table, shaped exactly like a live inbound connection's
/// (`incoming = true`, 60 s window) so these tests bind the real rows, not a bespoke fixture.
fn dig_limiter(limit_factor: f64) -> DigRateLimiter {
    DigRateLimiter::new(true, 60, limit_factor, dig_extension_rate_limits_map())
}

/// **Row:** `test_inbound_rate_limiter_creation` — the inbound limiter over the merged DIG
/// limits, with a 60 s window, builds successfully (CON-005 §Inbound Rate Limiting).
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
    let mut a = OpcodeRateLimiter::new(60, 1.0, OpcodeRateLimits::from(&limits));
    let mut b = OpcodeRateLimiter::new(60, 1.0, OpcodeRateLimits::from(&limits));
    let m = |t: ProtocolMessageTypes| DigMessage {
        msg_type: t as u8,
        id: None,
        data: Bytes::new(vec![0u8; 10]),
    };
    let handshake = || m(ProtocolMessageTypes::Handshake);
    assert!(a.allow(&handshake()));
    assert!(!a.allow(&handshake()));
    assert!(
        b.allow(&handshake()),
        "B must still accept first handshake"
    );
}

/// **Row:** `test_dig_message_types_added` — merged limits include CON-005 table entries `200..=208`
/// plus **DSC-005** introducer registration (`218` / `219`).
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
    for wire in 218u8..=219 {
        assert!(
            map.contains_key(&wire),
            "missing DIG wire limit for {wire}: keys {:?}",
            map.keys().collect::<Vec<_>>()
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
    let mut lim = OpcodeRateLimiter::new(60, 1.0, OpcodeRateLimits::from(&limits));
    let msg = DigMessage {
        msg_type: ProtocolMessageTypes::Handshake as u8,
        id: None,
        data: Bytes::new(vec![0u8; 100]),
    };
    for _ in 0..5 {
        assert!(lim.allow(&msg), "handshake within cap should pass");
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
    let mut lim = OpcodeRateLimiter::new(60, 1.0, OpcodeRateLimits::from(&limits));
    let msg = DigMessage {
        msg_type: ProtocolMessageTypes::Handshake as u8,
        id: None,
        data: Bytes::new(vec![0u8; 10]),
    };
    assert!(lim.allow(&msg));
    assert!(lim.allow(&msg));
    assert!(
        !lim.allow(&msg),
        "third handshake should exceed frequency=2"
    );
}

/// **Row:** `test_rate_limit_blocks_oversized_message` — single-frame `max_size` exceeded.
///
/// The bound is pinned from BOTH sides: a frame exactly at `max_size` is admitted, one byte over is
/// refused. The refusal is asserted as [`Admission::Unsendable`], not merely "not admitted", because
/// a size refusal survives every window roll — a `Deferred` here would tell a retrying caller to
/// wait for a budget that can never clear.
#[test]
fn test_rate_limit_blocks_oversized_message() {
    const MAX_SIZE: usize = 50;
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.other.insert(
        ProtocolMessageTypes::Handshake,
        #[allow(clippy::cast_precision_loss)]
        RateLimit::new(100.0, MAX_SIZE as f64, None),
    );
    let handshake = |len: usize| DigMessage {
        msg_type: ProtocolMessageTypes::Handshake as u8,
        id: None,
        data: Bytes::new(vec![0u8; len]),
    };

    let mut at_bound = OpcodeRateLimiter::new(60, 1.0, OpcodeRateLimits::from(&limits));
    assert_eq!(
        at_bound.admit(&handshake(MAX_SIZE)),
        Admission::Admitted,
        "a frame exactly at max_size must pass — otherwise the over-bound case proves nothing"
    );

    let mut over_bound = OpcodeRateLimiter::new(60, 1.0, OpcodeRateLimits::from(&limits));
    assert_eq!(
        over_bound.admit(&handshake(MAX_SIZE + 1)),
        Admission::Unsendable,
        "one byte over max_size is refused in every window, not merely deferred"
    );
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
    apply_inbound_rate_limit_violation(&state, ghost, 0);
}

/// **Row:** `test_rate_limit_factor_scaling` — lower [`dig_gossip::LinkOptions::rate_limit_factor`]
/// equivalent scales effective caps (`frequency * factor`).
#[test]
fn test_rate_limit_factor_scaling() {
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.other.insert(
        ProtocolMessageTypes::Handshake,
        RateLimit::new(10.0, 1_000_000.0, None),
    );
    let mut strict = OpcodeRateLimiter::new(60, 0.5, OpcodeRateLimits::from(&limits));
    let mut loose = OpcodeRateLimiter::new(60, 1.0, OpcodeRateLimits::from(&limits));
    let msg = DigMessage {
        msg_type: ProtocolMessageTypes::Handshake as u8,
        id: None,
        data: Bytes::new(vec![0u8; 10]),
    };
    // effective cap: strict 5, loose 10 first-window accepts
    for _ in 0..5 {
        assert!(strict.allow(&msg));
    }
    assert!(
        !strict.allow(&msg),
        "6th message should exceed 10*0.5=5"
    );
    for _ in 0..10 {
        assert!(loose.allow(&msg));
    }
    assert!(!loose.allow(&msg));
}

/// **Row:** `test_rate_limit_window_reset` — new period clears counters (`reset_seconds` shortened for speed).
#[tokio::test]
async fn test_rate_limit_window_reset() {
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.other.insert(
        ProtocolMessageTypes::Handshake,
        RateLimit::new(1.0, 1_000_000.0, None),
    );
    let mut lim = OpcodeRateLimiter::new(2, 1.0, OpcodeRateLimits::from(&limits));
    let msg = DigMessage {
        msg_type: ProtocolMessageTypes::Handshake as u8,
        id: None,
        data: Bytes::new(vec![0u8; 10]),
    };
    assert!(lim.allow(&msg));
    assert!(!lim.allow(&msg));
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(
        lim.allow(&msg),
        "after 2s window rolls, first handshake in new period should pass"
    );
}

/// **Row:** `test_check_dig_extension_limits` — [`DigRateLimiter::check`] honors the DIG table.
#[test]
fn test_check_dig_extension_limits() {
    let mut lim = dig_limiter(1.0);
    let t = DigMessageType::NewAttestation as u8;
    for _ in 0..100 {
        assert!(lim.check(t, 100));
    }
    assert!(
        !lim.check(t, 100),
        "101st attestation exceeds frequency=100"
    );
}

/// Unknown DIG opcode has no row — must fail-open (`true`) until a limit is registered.
#[test]
fn test_check_dig_extension_unknown_wire_allowed() {
    let mut lim = dig_limiter(1.0);
    assert!(lim.check(255, 1_000_000));
}

/// **Row:** `test_holdings_announce_222_row_bounds` (#1720) — opcode 222 (HoldingsAnnounce) has a
/// DELIBERATE inbound row, not the loose 1 MiB / 100-frame `default_settings` fall-through. The
/// bounds cap the expensive post-decode P-256 verify a hostile peer can force.
#[test]
fn test_holdings_announce_222_row_bounds() {
    let map = dig_extension_rate_limits_map();
    let row = map.get(&HOLDINGS_ANNOUNCE).expect(
        "opcode 222 (HoldingsAnnounce) must carry an explicit inbound rate-limit row (#1720)",
    );
    assert_eq!(
        row.frequency, 20.0,
        "222 frequency: ~2x the 221 anchor (10/min)"
    );
    assert_eq!(
        row.max_size, 131_072.0,
        "222 max single frame: 128 KiB, sized to a full legit MAX_CHANGES batch + headroom"
    );
    assert_eq!(row.max_total_size, None, "matches the table convention");
}

/// **Row:** `test_holdings_announce_222_frequency_bounded` (#1720) — a burst beyond the 20/min cap is
/// rejected, so a hostile peer cannot force 100 P-256 verifies/min/conn via the old default.
#[test]
fn test_holdings_announce_222_frequency_bounded() {
    let mut lim = dig_limiter(1.0);
    for _ in 0..20 {
        assert!(lim.check(HOLDINGS_ANNOUNCE, 1024));
    }
    assert!(
        !lim.check(HOLDINGS_ANNOUNCE, 1024),
        "21st holdings-announce in the window exceeds frequency=20"
    );
}

/// **Row:** `test_holdings_announce_222_max_batch_not_clipped` (#1720) — the `max_size` fits a full
/// legit `MAX_CHANGES` (256) re-announce (each key at a fat 4-address, 64-byte-host candidate set), so
/// a real provider's full-holdings frame is admitted, not clipped. Guards against choosing a cap that
/// would break the discovery flywheel.
#[test]
fn test_holdings_announce_222_max_batch_not_clipped() {
    let host = "h".repeat(64); // covers a full IPv6 literal / modest hostname
    let addresses: Vec<CandidateAddr> = (0..4)
        .map(|_| CandidateAddr {
            host: host.clone(),
            port: 9256,
        })
        .collect();
    let changes: Vec<HoldingsDelta> = (0..HOLDINGS_MAX_CHANGES)
        .map(|i| {
            let mut content_key = [0u8; 32];
            content_key[0] = i as u8;
            content_key[1] = (i >> 8) as u8;
            HoldingsDelta::Add {
                content_key,
                addresses: addresses.clone(),
                expires_at: 1_900_000_000,
            }
        })
        .collect();
    // A size fixture: fields are filler of realistic length (real P-256 SPKI ~91 B, ECDSA-P256
    // ASN.1 sig ~72 B) — encode() does not verify, so this exercises only the encoded frame size.
    let announce = HoldingsAnnounce {
        provider_peer_id: "aa".repeat(32), // 64 hex chars
        provider_spki: vec![0u8; 120],
        seq: 1,
        announced_at: 2,
        changes,
        signature: vec![0u8; 72],
    };
    let encoded = announce.encode();
    let map = dig_extension_rate_limits_map();
    let max_size = map.get(&HOLDINGS_ANNOUNCE).unwrap().max_size;
    assert!(
        encoded.len() as f64 <= max_size,
        "legit MAX_CHANGES holdings-announce ({} bytes) must fit under max_size ({max_size})",
        encoded.len()
    );
    let mut lim = dig_limiter(1.0);
    assert!(
        lim.check(HOLDINGS_ANNOUNCE, encoded.len() as u32),
        "a legit full-holdings frame must be admitted, not clipped"
    );
}

// The live-gate 220-band flood guards for opcodes 221/222 live in the crate's own
// `connection::inbound_limits::tests` module (`real_gate_bounds_store_melted_221`,
// `real_gate_bounds_holdings_announce_222`), which drive the REAL `InboundRateLimiter::allows`. The
// external mirrors that once lived here re-implemented the gate's branch and so could not detect a
// broken production gate; they were removed (#1760 E) in favour of the authoritative in-crate tests.
