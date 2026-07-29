//! CON-005 — per-connection **inbound** rate limits on top of [`V2_RATE_LIMITS`](dig_peer_protocol::V2_RATE_LIMITS).
//!
//! ## Normative trace
//!
//! - [`CON-005.md`](../../../docs/requirements/domains/connection/specs/CON-005.md)
//! - [`NORMATIVE.md`](../../../docs/requirements/domains/connection/NORMATIVE.md) §CON-005
//! - [`SPEC.md`](../../../docs/resources/SPEC.md) §5.3
//!
//! ## Outbound vs inbound
//!
//! Outbound sends go through [`dig_peer_protocol::Peer::send_raw`] which already applies
//! [`RateLimiter`] with `incoming = false` (CON-005 acceptance: *no custom outbound implementation*).
//! Inbound frames are delivered on the per-connection `mpsc` from [`Peer::from_websocket`]; **DIG**
//! enforces [`RateLimiter::handle_message`] here **before** forwarding to the broadcast hub.
//!
//! ## DIG wire types (`dig_wire` map)
//!
//! [`crate::types::dig_messages::DigMessageType`] discriminants (`200..=219`) are **not**
//! [`ProtocolMessageTypes`] variants in `chia-protocol` 0.26, so they cannot appear in
//! [`dig_peer_protocol::RateLimits`] `tx` / `other` maps. But the **220-band** opcodes —
//! `StoreMelted` = 221 (#1316), `HoldingsAnnounce` = 222 (#1720) — ARE `ProtocolMessageTypes`
//! variants and DO arrive on the live wire as Chia [`Message`] values. Either way their bound lives
//! in [`RateLimits::dig_wire`](dig_peer_protocol::RateLimits::dig_wire) (vendored `chia-sdk-client`),
//! which [`RateLimiter::handle_message`] never reads.
//!
//! [`inbound_gate_allows`] closes that gap: the live forwarders call it (not `handle_message`
//! directly), and for 220-band frames it additionally requires the [`RateLimiter::check_dig_extension`]
//! pass — so the 221/222 rows are **enforced on the live path**, not merely unit-tested. Below the
//! band, `handle_message` remains the whole gate (unchanged behaviour).

use std::collections::HashMap;

use dig_peer_protocol::{
    Message, ProtocolMessageTypes, RateLimit, RateLimiter, RateLimits, V2_RATE_LIMITS,
};

use crate::types::dig_messages::DigMessageType;

/// The first opcode of the DIG 220..=255 wire band.
///
/// Opcodes in this band (e.g. `StoreMelted` = 221 (#1316), `HoldingsAnnounce` = 222 (#1720)) ARE
/// `chia_protocol::ProtocolMessageTypes` variants — so they arrive as real Chia [`Message`] values —
/// but their bound lives in [`RateLimits::dig_wire`], which [`RateLimiter::handle_message`] never
/// reads. The live ingress gate therefore has to consult [`RateLimiter::check_dig_extension`] for
/// them explicitly; see [`inbound_gate_allows`].
const DIG_WIRE_BAND_START: u8 = 220;

/// The single inbound admission gate every live forwarder runs on each received frame, BEFORE the
/// frame is broadcast to the service (and thus before the downstream P-256 verify).
///
/// It combines the two rate-limit checks under the caller's existing [`RateLimiter`] guard — one
/// lock, no TOCTOU:
///
/// 1. [`RateLimiter::handle_message`] — the Chia `default_settings`/`tx`/`other` bound keyed by
///    [`ProtocolMessageTypes`](dig_peer_protocol::ProtocolMessageTypes).
/// 2. For frames in the DIG wire band (opcode `>= DIG_WIRE_BAND_START`), ALSO
///    [`RateLimiter::check_dig_extension`] keyed by the raw opcode.
///
/// **Why both for the 220 band:** 221/222 ARE Chia `Message` variants, but `handle_message` has no
/// `tx`/`other` row for them, so it falls through to the loose `default_settings` (100 frames/min,
/// 1 MiB) and their deliberate [`dig_extension_rate_limits_map`] rows (#1316, #1720) would never
/// bind on the live wire. Requiring the `check_dig_extension` pass in addition is what makes those
/// rows actually enforced. Frames below the band are decided by `handle_message` alone (unchanged).
///
/// A frame is admitted only if EVERY applicable check passes.
pub(crate) fn inbound_gate_allows(guard: &mut RateLimiter, msg: &Message) -> bool {
    // Always apply the Chia base bound first (and unconditionally, so its counters advance).
    if !guard.handle_message(msg) {
        return false;
    }

    let opcode = msg.msg_type as u8;
    if opcode >= DIG_WIRE_BAND_START {
        // DIG 220-band frame: its real bound lives in `dig_wire`, so require that pass too.
        guard.check_dig_extension(opcode, msg.data.len() as u32)
    } else {
        // Below the band: the base bound is the whole gate.
        true
    }
}

/// Whether `msg_type` is a **public-flood** broadcast opcode: a message any internet host may
/// originate and that disseminates to EVERY peer via Plumtree — `StoreMelted` = 221 (#1316) and
/// `HoldingsAnnounce` = 222 (#1428).
///
/// This is keyed by the very opcode constants the [`dig_extension_rate_limits_map`] rows use, and it
/// is kept in lockstep with the canonical public-flood grouping in
/// [`classify_broadcast`](crate::gossip::broadcaster::classify_broadcast) — both name exactly
/// `StoreMelted | HoldingsAnnounce` — so the two lists cannot drift (a guard test enumerates the wire
/// enum to prove it). It exists as the single source of truth for the #1626 penalty exemption below.
pub(crate) fn is_public_flood_opcode(msg_type: ProtocolMessageTypes) -> bool {
    matches!(
        msg_type as u8,
        crate::service::store_melted::STORE_MELTED
            | crate::service::holdings_announce::HOLDINGS_ANNOUNCE
    )
}

/// Whether a frame REJECTED by [`inbound_gate_allows`] should additionally charge a
/// [`PenaltyReason::RateLimitExceeded`](crate::types::peer::PenaltyReason) reputation penalty against
/// the delivering peer, versus being dropped silently.
///
/// A rejected frame is ALWAYS dropped (the #1720 per-connection cap counts pre-verify frames,
/// eager duplicates included). It additionally incurs a penalty ONLY when it is not a public-flood
/// opcode. On a multi-hop public flood (221/222) the delivering connection is a **forwarder, not the
/// origin**, so charging it would ban honest relayers by false attribution (#1626) — a single hostile
/// origin could get every peer that redistributes its over-cap flood banned. Dropping the excess frame
/// alone is graceful: the receiver's seen-set, Plumtree eager/lazy redundancy, and the periodic
/// re-announce all recover the message without the delivering peer being punished. The exemption is
/// deliberately opcode-scoped — every other over-cap opcode is still penalised as before.
pub(crate) fn rejected_frame_incurs_penalty(msg_type: ProtocolMessageTypes) -> bool {
    !is_public_flood_opcode(msg_type)
}

/// Table from [`CON-005.md`](../../../docs/requirements/domains/connection/specs/CON-005.md) §DIG Extension Rate Limits.
///
/// Frequencies are **per rolling minute bucket** (see [`RateLimiter::new`] `reset_seconds: 60` in
/// call sites). Sizes are maximum **single-frame** payload bytes unless `max_total_size` is set.
pub fn dig_extension_rate_limits_map() -> HashMap<u8, RateLimit> {
    let mut m = HashMap::new();
    m.insert(
        DigMessageType::NewAttestation as u8,
        RateLimit::new(100.0, 4096.0, None),
    );
    m.insert(
        DigMessageType::NewCheckpointProposal as u8,
        RateLimit::new(10.0, 8192.0, None),
    );
    m.insert(
        DigMessageType::NewCheckpointSignature as u8,
        RateLimit::new(100.0, 4096.0, None),
    );
    m.insert(
        DigMessageType::RequestCheckpointSignatures as u8,
        RateLimit::new(10.0, 1024.0, None),
    );
    m.insert(
        DigMessageType::RespondCheckpointSignatures as u8,
        RateLimit::new(10.0, 65536.0, None),
    );
    m.insert(
        DigMessageType::RequestStatus as u8,
        RateLimit::new(10.0, 1024.0, None),
    );
    m.insert(
        DigMessageType::RespondStatus as u8,
        RateLimit::new(10.0, 8192.0, None),
    );
    m.insert(
        DigMessageType::NewCheckpointSubmission as u8,
        RateLimit::new(10.0, 65536.0, None),
    );
    m.insert(
        DigMessageType::ValidatorAnnounce as u8,
        RateLimit::new(10.0, 4096.0, None),
    );
    // DSC-005 — introducer registration is low-frequency but still needs bounded ingress if ever
    // proxied through a gossip peer path (defensive; primary flow is introducer WSS client).
    m.insert(
        DigMessageType::RegisterPeer as u8,
        RateLimit::new(4.0, 512.0, None),
    );
    m.insert(
        DigMessageType::RegisterAck as u8,
        RateLimit::new(4.0, 256.0, None),
    );
    // #1316 — store-melted (opcode 221) is a fixed-size, infrequent public broadcast. Bound its
    // ingress like `ValidatorAnnounce`: a peer cannot flood store-melt announcements. Keyed by the
    // raw opcode (221 is a `ProtocolMessageTypes` variant in the vendored fork, not a
    // `DigMessageType`); the `dig_wire` map is `u8 -> RateLimit`, so the bound applies uniformly.
    m.insert(
        crate::service::store_melted::STORE_MELTED,
        RateLimit::new(10.0, 4096.0, None),
    );
    // #1720 — holdings-announce (opcode 222) is a signed, periodic public-discovery broadcast that
    // any internet host can send, and its P-256 signature verify (`verify_holdings_announce`) runs on
    // the decoded frame. Without an explicit row it fell through to `default_settings` (100 frames/min,
    // 1 MiB) — bounding that expensive verify only by accident. Give it a deliberate row keyed by the
    // raw opcode (222 is a `ProtocolMessageTypes` variant in the vendored fork, not a `DigMessageType`;
    // the `dig_wire` map is `u8 -> RateLimit`, so the bound applies uniformly). Sized larger than 221:
    // - `max_size` = `MAX_ANNOUNCE_FRAME_BYTES` (128 KiB). This is NOT a loose estimate: `holdings_announce`
    //   ENFORCES that same bound (#1760 B) — both the builder and `verify_holdings_announce` reject any
    //   announce whose encoded frame exceeds it, plus per-field addr-count/host-len caps — so every legit
    //   announce is provably `<= max_size` and never hard-dropped (the availability bug this closes). A
    //   realistic full `MAX_CHANGES` (256) re-announce with ~6 IPv6-literal addresses per key is ~85 KiB,
    //   well under the bound. Referencing the const keeps the limiter and the enforced bound from drifting.
    //   Far below the 1 MiB default (8x tighter).
    // - `freq` 20/min is ~2x the 221 anchor (10/min): a provider re-announces its whole holdings in ONE
    //   frame, so steady state is minutes apart; 20/min allows legit burst re-announces (a 0→N peer
    //   transition plus a cluster of holdings-change events) while capping a hostile conn at 20 P-256
    //   verifies/min/conn — 5x below the 100/min default.
    m.insert(
        crate::service::holdings_announce::HOLDINGS_ANNOUNCE,
        RateLimit::new(
            20.0,
            crate::service::holdings_announce::MAX_ANNOUNCE_FRAME_BYTES as f64,
            None,
        ),
    );
    m
}

/// Chia **V2** limits plus DIG `dig_wire` rows — shared definition for every inbound [`LiveSlot`](crate::service::state::LiveSlot).
pub fn gossip_inbound_rate_limits() -> RateLimits {
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.dig_wire = dig_extension_rate_limits_map();
    limits
}

/// Build a per-connection inbound limiter: **incoming = true**, **60 s** window, scaled by
/// [`crate::types::config::GossipConfig::peer_options`](crate::types::config::GossipConfig::peer_options).
pub fn new_inbound_rate_limiter(rate_limit_factor: f64) -> RateLimiter {
    RateLimiter::new(true, 60, rate_limit_factor, gossip_inbound_rate_limits())
}

#[cfg(test)]
mod tests {
    //! In-crate regression tests for the 220-band live gate (#1720, #1316).
    //!
    //! These call the REAL [`inbound_gate_allows`] (reachable in-crate because it is `pub(crate)`),
    //! NOT a hand-copied mirror. This is the authoritative regression guard: if the production gate
    //! ever drops its `>= DIG_WIRE_BAND_START` `check_dig_extension` branch and reverts to
    //! `handle_message`-only, a 220-band flood would fall through to the loose 100/min
    //! `default_settings` and these tests go RED (proven by reverting the branch). The external
    //! mirror in `tests/con_005_tests.rs` cannot detect that regression and is only a secondary check.

    use dig_peer_protocol::{Bytes, ProtocolMessageTypes, Streamable};

    use super::*;

    /// #1760 D — completeness guard for the DIG 220-band `dig_wire` rows.
    ///
    /// [`RateLimiter::check_dig_extension`] **fails OPEN**: an opcode in the 220 band with no
    /// [`dig_extension_rate_limits_map`] row silently falls through to the loose Chia
    /// `default_settings` (100/min, 1 MiB) instead of a deliberate bound (the class of gap #1720
    /// closed for 221/222). This test enumerates every ≥[`DIG_WIRE_BAND_START`]
    /// [`ProtocolMessageTypes`] variant that actually exists (probed via the wire discriminant, so
    /// it can never go stale against a hand-copied list) and asserts each is CLASSIFIED — either it
    /// carries a dedicated `dig_wire` row, or it is a documented member of
    /// [`BASE_BOUND_ONLY_BAND_OPCODES`]. A newly-added 220-band opcode that is neither fails this
    /// test, forcing a deliberate rate-limit decision rather than a silent fail-open default.
    #[test]
    fn every_220_band_opcode_is_classified() {
        // Opcodes deliberately bounded ONLY by the base `handle_message` default (100/min, 1 MiB),
        // with no tighter dedicated `dig_wire` row. `DigMessage` (220) is a DIRECTED envelope whose
        // inner `DigMessageType` decides semantics; its ingress is covered by the base bound like any
        // generic message, so — unlike the 221/222 public-flood broadcasts — it needs no dedicated
        // tighter row. Adding an opcode here is a conscious "base bound is sufficient" statement.
        const BASE_BOUND_ONLY_BAND_OPCODES: &[u8] = &[crate::service::dig_message::DIG_MESSAGE];

        let map = dig_extension_rate_limits_map();
        for opcode in DIG_WIRE_BAND_START..=u8::MAX {
            // Probe whether this opcode is a real `ProtocolMessageTypes` variant via its wire
            // discriminant — the authoritative source, so the guard tracks the enum, not a literal.
            if ProtocolMessageTypes::from_bytes(&[opcode]).is_err() {
                continue;
            }
            let has_row = map.contains_key(&opcode);
            let base_bound_only = BASE_BOUND_ONLY_BAND_OPCODES.contains(&opcode);
            assert!(
                has_row ^ base_bound_only,
                "220-band opcode {opcode} must be classified EXACTLY once: give it a \
                 dig_extension_rate_limits_map row (a dedicated bound) OR list it in \
                 BASE_BOUND_ONLY_BAND_OPCODES (base default is sufficient) — never both, never \
                 neither. A fail-open fall-through to default_settings is the #1720/#1760 D bug."
            );
        }
    }

    /// Real 222 (HoldingsAnnounce) flood: the live gate admits the first 20 (the `dig_wire` row) and
    /// rejects the 21st, driven through the REAL [`inbound_gate_allows`]. Without the 220-band branch
    /// this admits the 21st via the 100/min default, so the test pins that branch to production.
    #[test]
    fn real_gate_bounds_holdings_announce_222() {
        let announce_frame = || Message {
            msg_type: ProtocolMessageTypes::HoldingsAnnounce,
            id: None,
            data: Bytes::new(vec![0u8; 1024]), // well under the 128 KiB max_size
        };
        let mut guard = new_inbound_rate_limiter(1.0);
        for i in 0..20 {
            assert!(
                inbound_gate_allows(&mut guard, &announce_frame()),
                "frame {i} within the 20/min holdings-announce cap must pass the REAL gate"
            );
        }
        assert!(
            !inbound_gate_allows(&mut guard, &announce_frame()),
            "21st holdings-announce (222) must be rejected by the REAL inbound_gate_allows (#1720)"
        );
    }

    /// The opcode-222 `max_size` MUST equal the enforced `MAX_ANNOUNCE_FRAME_BYTES` bound
    /// (#1760 B) — the limiter row references that const, so a legit announce that passes the
    /// enforced frame bound is provably within the limiter cap and never hard-dropped.
    #[test]
    fn holdings_announce_222_max_size_ties_to_enforced_frame_bound() {
        let limits = dig_extension_rate_limits_map();
        let row = limits
            .get(&crate::service::holdings_announce::HOLDINGS_ANNOUNCE)
            .expect("opcode 222 has a dig_wire row");
        assert_eq!(
            row.max_size,
            crate::service::holdings_announce::MAX_ANNOUNCE_FRAME_BYTES as f64
        );
    }

    /// #1626 — the public-flood exemption set is EXACTLY `StoreMelted` (221) and `HoldingsAnnounce`
    /// (222), enumerated over the real wire enum so it can never drift against the canonical
    /// [`classify_broadcast`](crate::gossip::broadcaster::classify_broadcast) grouping or a hand-typed
    /// list.
    #[test]
    fn public_flood_opcode_set_is_exactly_221_and_222() {
        for opcode in 0u8..=u8::MAX {
            let Ok(msg_type) = ProtocolMessageTypes::from_bytes(&[opcode]) else {
                continue;
            };
            let expected = opcode == crate::service::store_melted::STORE_MELTED
                || opcode == crate::service::holdings_announce::HOLDINGS_ANNOUNCE;
            assert_eq!(
                is_public_flood_opcode(msg_type),
                expected,
                "opcode {opcode} public-flood classification"
            );
        }
    }

    /// #1626 — a 222 (HoldingsAnnounce) frame the REAL gate rejects for exceeding the per-connection
    /// cap is DROPPED (drop behaviour unchanged) but is EXEMPT from the reputation penalty, so an
    /// honest forwarder of another host's over-cap flood is never banned by false attribution.
    ///
    /// RED without the fix: [`rejected_frame_incurs_penalty`] returned `true` for every rejected
    /// frame, so the final assertion (`!incurs_penalty`) failed and the delivering peer was charged.
    #[test]
    fn over_cap_holdings_announce_222_is_dropped_but_not_penalised() {
        let frame = |seed: u32| Message {
            msg_type: ProtocolMessageTypes::HoldingsAnnounce,
            id: None,
            data: Bytes::new({
                // Distinct payloads (well under the 128 KiB cap) so each is a real, non-duplicate frame.
                let mut v = vec![0u8; 64];
                v[0] = seed as u8;
                v[1] = (seed >> 8) as u8;
                v
            }),
        };
        let mut guard = new_inbound_rate_limiter(1.0);
        for seed in 0..20 {
            assert!(
                inbound_gate_allows(&mut guard, &frame(seed)),
                "frame {seed} within the 20/min 222 cap must pass the REAL gate"
            );
        }
        let over_cap = frame(999);
        assert!(
            !inbound_gate_allows(&mut guard, &over_cap),
            "21st 222 must be DROPPED by the REAL gate (#1720 cap intact)"
        );
        assert!(
            !rejected_frame_incurs_penalty(over_cap.msg_type),
            "a dropped 222 public flood must NOT charge a reputation penalty (#1626)"
        );
    }

    /// #1626 — same guarantee for 221 (StoreMelted): the 11th frame is dropped by the REAL gate yet
    /// exempt from the penalty. Covers 221 identically to 222 (the false-attribution bug is the same).
    #[test]
    fn over_cap_store_melted_221_is_dropped_but_not_penalised() {
        let frame = |seed: u32| Message {
            msg_type: ProtocolMessageTypes::StoreMelted,
            id: None,
            data: Bytes::new({
                let mut v = vec![0u8; 164];
                v[0] = seed as u8;
                v[1] = (seed >> 8) as u8;
                v
            }),
        };
        let mut guard = new_inbound_rate_limiter(1.0);
        for seed in 0..10 {
            assert!(
                inbound_gate_allows(&mut guard, &frame(seed)),
                "frame {seed} within the 10/min 221 cap must pass the REAL gate"
            );
        }
        let over_cap = frame(999);
        assert!(
            !inbound_gate_allows(&mut guard, &over_cap),
            "11th 221 must be DROPPED by the REAL gate (#1316 cap intact)"
        );
        assert!(
            !rejected_frame_incurs_penalty(over_cap.msg_type),
            "a dropped 221 public flood must NOT charge a reputation penalty (#1626)"
        );
    }

    /// #1626 — CONTRAST: an over-cap NON-flood opcode is dropped by the REAL gate AND still incurs the
    /// penalty. Proves the exemption is opcode-scoped, not a blanket disable of rate-limit attribution.
    #[test]
    fn over_cap_non_flood_opcode_is_still_penalised() {
        let frame = || Message {
            msg_type: ProtocolMessageTypes::Handshake,
            id: None,
            data: Bytes::new(vec![0u8; 16]),
        };
        let mut guard = new_inbound_rate_limiter(1.0);
        let mut rejected = None;
        // Drive the base bound past its cap; the first rejected frame is the one under test.
        for _ in 0..1_000 {
            if !inbound_gate_allows(&mut guard, &frame()) {
                rejected = Some(frame());
                break;
            }
        }
        let rejected = rejected.expect("a Handshake flood must eventually exceed its inbound cap");
        assert!(
            rejected_frame_incurs_penalty(rejected.msg_type),
            "a non-flood over-cap opcode MUST still be penalised (#1626 exemption is opcode-scoped)"
        );
    }

    /// Real 221 (StoreMelted, fixed `ENCODED_LEN` = 164 B) flood: the live gate admits the first 10
    /// (the `dig_wire` row) and rejects the 11th, driven through the REAL [`inbound_gate_allows`].
    #[test]
    fn real_gate_bounds_store_melted_221() {
        let melted_frame = || Message {
            msg_type: ProtocolMessageTypes::StoreMelted,
            id: None,
            data: Bytes::new(vec![0u8; 164]), // fixed StoreMeltedAnnounce ENCODED_LEN
        };
        let mut guard = new_inbound_rate_limiter(1.0);
        for i in 0..10 {
            assert!(
                inbound_gate_allows(&mut guard, &melted_frame()),
                "frame {i} within the 10/min store-melted cap must pass the REAL gate"
            );
        }
        assert!(
            !inbound_gate_allows(&mut guard, &melted_frame()),
            "11th store-melted (221) must be rejected by the REAL inbound_gate_allows (#1316)"
        );
    }
}
