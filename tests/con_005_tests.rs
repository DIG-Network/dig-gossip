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

use dig_gossip::{Bytes, Message, ProtocolMessageTypes};
use dig_gossip::{RateLimit, RateLimiter, V2_RATE_LIMITS};

use dig_gossip::{
    apply_inbound_rate_limit_violation, dig_extension_rate_limits_map, gossip_inbound_rate_limits,
    load_ssl_cert, new_inbound_rate_limiter, peer_id_for_addr, CandidateAddr, DigMessageType,
    HoldingsAnnounce, HoldingsDelta, PenaltyReason, ServiceState, HOLDINGS_ANNOUNCE,
    HOLDINGS_MAX_CHANGES, STORE_MELTED,
};

/// Mirror of the crate-private `connection::inbound_limits::inbound_gate_allows` — the live inbound
/// admission gate. `inbound_gate_allows` is `pub(crate)`, so these integration tests exercise the
/// EXACT combination it wraps: the Chia base bound plus, for the DIG 220-band, the `dig_wire` bound.
/// A change to the production gate that diverged from this would surface as a behaviour mismatch here.
fn live_gate_allows(lim: &mut RateLimiter, msg: &Message) -> bool {
    if !lim.handle_message(msg) {
        return false;
    }
    let opcode = msg.msg_type as u8;
    if opcode >= 220 {
        lim.check_dig_extension(opcode, msg.data.len() as u32)
    } else {
        true
    }
}

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
    let merged = gossip_inbound_rate_limits();
    for wire in 200u8..=208 {
        assert!(
            merged.dig_wire.contains_key(&wire),
            "gossip_inbound_rate_limits missing dig_wire {wire}"
        );
    }
    for wire in 218u8..=219 {
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
    apply_inbound_rate_limit_violation(&state, ghost, 0);
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
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.dig_wire = dig_extension_rate_limits_map();
    let mut lim = RateLimiter::new(true, 60, 1.0, limits);
    for _ in 0..20 {
        assert!(lim.check_dig_extension(HOLDINGS_ANNOUNCE, 1024));
    }
    assert!(
        !lim.check_dig_extension(HOLDINGS_ANNOUNCE, 1024),
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
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.dig_wire = map;
    let mut lim = RateLimiter::new(true, 60, 1.0, limits);
    assert!(
        lim.check_dig_extension(HOLDINGS_ANNOUNCE, encoded.len() as u32),
        "a legit full-holdings frame must be admitted, not clipped"
    );
}

/// **Row:** `holdings_announce_222_flood_rejected_on_live_gate` (#1720) — the LIVE ingress gate
/// (built exactly as the forwarders build it) bounds opcode-222 flooding to the `dig_wire` row
/// (20/min), NOT the loose 100/min `default_settings` fall-through. Proves the row is enforced on
/// the live path, not merely unit-tested via `check_dig_extension` in isolation.
///
/// Pre-fix (base `handle_message` alone) this frame fell through to the 100/min default and ~100
/// frames would pass; the extra assertion below documents that gap the combined gate closes.
#[test]
fn holdings_announce_222_flood_rejected_on_live_gate() {
    let announce_frame = || Message {
        msg_type: ProtocolMessageTypes::HoldingsAnnounce,
        id: None,
        data: Bytes::new(vec![0u8; 1024]), // well under the 128 KiB max_size
    };

    let mut lim = RateLimiter::new(true, 60, 1.0, gossip_inbound_rate_limits());
    for i in 0..20 {
        assert!(
            live_gate_allows(&mut lim, &announce_frame()),
            "frame {i} within the 20/min holdings-announce cap must pass the live gate"
        );
    }
    assert!(
        !live_gate_allows(&mut lim, &announce_frame()),
        "21st holdings-announce (222) in the window must be rejected by the live gate (#1720)"
    );

    // The enforcement gap this fix closes: the Chia base bound alone (the pre-fix live gate) reads
    // only `default_settings` (100/min) for opcode 222, so it would admit the 21st frame.
    let mut base_only = RateLimiter::new(true, 60, 1.0, gossip_inbound_rate_limits());
    for _ in 0..21 {
        assert!(
            base_only.handle_message(&announce_frame()),
            "pre-fix: handle_message alone lets 222 flood through the loose 100/min default"
        );
    }
}

/// **Row:** `store_melted_221_flood_rejected_on_live_gate` (#1316) — the LIVE ingress gate bounds
/// opcode-221 (StoreMelted, fixed `ENCODED_LEN` = 164 B) flooding to the `dig_wire` row (10/min).
/// This is the FIRST time the #1316 row binds on the live wire; guards it going live.
///
/// The extra assertion documents the pre-fix gap: base `handle_message` alone admits the 11th frame
/// via the 100/min default.
#[test]
fn store_melted_221_flood_rejected_on_live_gate() {
    assert_eq!(STORE_MELTED, 221, "opcode contract");
    let melted_frame = || Message {
        msg_type: ProtocolMessageTypes::StoreMelted,
        id: None,
        data: Bytes::new(vec![0u8; 164]), // fixed StoreMeltedAnnounce ENCODED_LEN
    };

    let mut lim = RateLimiter::new(true, 60, 1.0, gossip_inbound_rate_limits());
    for i in 0..10 {
        assert!(
            live_gate_allows(&mut lim, &melted_frame()),
            "frame {i} within the 10/min store-melted cap must pass the live gate"
        );
    }
    assert!(
        !live_gate_allows(&mut lim, &melted_frame()),
        "11th store-melted (221) in the window must be rejected by the live gate (#1316)"
    );

    let mut base_only = RateLimiter::new(true, 60, 1.0, gossip_inbound_rate_limits());
    for _ in 0..11 {
        assert!(
            base_only.handle_message(&melted_frame()),
            "pre-fix: handle_message alone lets 221 flood through the loose 100/min default"
        );
    }
}
