//! CON-005 — per-connection **inbound** rate limits on top of Chia's `V2_RATE_LIMITS`.
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
//! [`OpcodeRateLimiter`] with no inbound flag (CON-005 acceptance: *no custom outbound implementation*).
//! Inbound frames are delivered on the per-connection `mpsc` from [`Peer::from_websocket`]; **DIG**
//! enforces [`OpcodeRateLimiter::allow`] here **before** forwarding to the broadcast hub.
//!
//! ## DIG wire types (the `dig_extension_rate_limits_map` table)
//!
//! [`crate::types::dig_messages::DigMessageType`] discriminants (`200..=219`) are **not**
//! [`ProtocolMessageTypes`] variants in `chia-protocol` 0.26, so they cannot appear in
//! [`dig_peer_protocol::RateLimits`] `tx` / `other` maps. But the **220-band** opcodes —
//! `StoreMelted` = 221 (#1316), `HoldingsAnnounce` = 222 (#1720) — ARE `ProtocolMessageTypes`
//! variants and DO arrive on the live wire as Chia [`DigMessage`] values. Either way their bound is a
//! DIG bound, keyed by the raw opcode byte in [`dig_extension_rate_limits_map`] and enforced by
//! [`DigRateLimiter`] — which [`OpcodeRateLimiter::allow`] knows nothing about.
//!
//! [`InboundRateLimiter`] closes that gap: the live forwarders admit frames through it (not through
//! `handle_message` directly), and for 220-band frames it additionally requires the
//! [`DigRateLimiter::check`] pass — so the 221/222 rows are **enforced on the live path**, not
//! merely unit-tested. Below the band, `handle_message` remains the whole gate.
//!
//! Until dig_ecosystem#2228 the DIG table and its accounting lived inside the vendored
//! `chia-sdk-client` fork (`RateLimits::dig_wire`, `RateLimiter::check_dig_extension`). They were
//! never entangled with Chia's — see [`DigRateLimiter`] — so they now live here and those two files
//! of the fork are byte-identical to upstream again.

use std::collections::HashMap;

use dig_peer_protocol::{DigMessage, OpcodeRateLimiter, OpcodeRateLimits, RateLimit};

use super::dig_rate_limiter::DigRateLimiter;
use crate::types::dig_messages::DigMessageType;

/// The rolling window, in seconds, both halves of the inbound gate account over.
///
/// Shared by construction so the Chia and DIG tallies clear on the SAME absolute wall-clock
/// boundaries (both limiters derive their window as `unix_secs / RESET_SECONDS`). Every
/// `frequency` in [`dig_extension_rate_limits_map`] is therefore "per minute".
const RESET_SECONDS: u64 = 60;

/// The first opcode of the DIG 220..=255 wire band.
///
/// Opcodes in this band (e.g. `StoreMelted` = 221 (#1316), `HoldingsAnnounce` = 222 (#1720)) ARE
/// `chia_protocol::ProtocolMessageTypes` variants — so they arrive as real Chia [`DigMessage`] values —
/// but their bound is a DIG bound that [`OpcodeRateLimiter::allow`] never reads. The live
/// ingress gate therefore has to consult [`DigRateLimiter`] for them explicitly; see
/// [`InboundRateLimiter::allows`].
const DIG_WIRE_BAND_START: u8 = 220;

/// The per-connection inbound admission gate (CON-005): Chia's bound and DIG's, behind one lock.
///
/// Every live forwarder admits each received frame through [`Self::allows`] BEFORE broadcasting it
/// to the service (and thus before the downstream P-256 verify). Holding both halves in one value
/// is what makes the pair atomic under the caller's single `Mutex` — no TOCTOU between the two
/// checks, and no way for a call site to consult one and forget the other.
#[derive(Debug, Clone)]
pub struct InboundRateLimiter {
    /// Chia's bound, keyed by the raw wire byte: `default_settings` / `tx` / `other`.
    ///
    /// [`OpcodeRateLimiter`] carries no table of its own — it re-keys Chia's `V2_RATE_LIMITS`
    /// from `ProtocolMessageTypes` onto the wire byte, so every Chia opcode keeps exactly the
    /// bound Chia gives it while a DIG opcode (which has no enum variant) remains expressible.
    chia: OpcodeRateLimiter,
    /// DIG's bound, keyed by the raw opcode byte: [`dig_extension_rate_limits_map`].
    dig: DigRateLimiter,
}

impl InboundRateLimiter {
    /// Builds the gate for one inbound connection — `incoming = true`, a [`RESET_SECONDS`] window,
    /// every bound scaled by
    /// [`rate_limit_factor`](crate::types::config::GossipConfig::peer_options).
    pub fn new(rate_limit_factor: f64) -> Self {
        Self {
            chia: OpcodeRateLimiter::new(
                RESET_SECONDS,
                rate_limit_factor,
                OpcodeRateLimits::default(),
            ),
            dig: DigRateLimiter::new(
                true,
                RESET_SECONDS,
                rate_limit_factor,
                dig_extension_rate_limits_map(),
            ),
        }
    }

    /// Whether `msg` is admitted. A frame passes only if EVERY applicable check passes.
    ///
    /// 1. [`OpcodeRateLimiter::allow`] — the Chia bound — always, and first, so its counters
    ///    advance for every frame regardless of opcode.
    /// 2. For frames in the DIG wire band (opcode `>= DIG_WIRE_BAND_START`), ALSO
    ///    [`DigRateLimiter::check`] on the raw opcode.
    ///
    /// **Why both for the 220 band:** the Chia table has no `tx`/`other` row for 220-222, so they
    /// fall through to the loose `default_settings` (100 frames/min, 1 MiB) and their deliberate
    /// [`dig_extension_rate_limits_map`] rows (#1316, #1720) would never bind on the live wire. Requiring the DIG pass in addition is what makes
    /// those rows actually enforced. Frames below the band are decided by `handle_message` alone.
    ///
    /// The DIG half can only ever ADD a restriction: it is consulted after the Chia bound has
    /// already been applied, and an opcode with no row fails open.
    pub fn allows(&mut self, msg: &DigMessage) -> bool {
        // Always apply the Chia base bound first (and unconditionally, so its counters advance).
        if !self.chia.allow(msg) {
            return false;
        }

        let opcode = msg.msg_type;
        if opcode >= DIG_WIRE_BAND_START {
            // DIG 220-band frame: its real bound is the DIG row, so require that pass too.
            self.dig.check(opcode, msg.data.len() as u32)
        } else {
            // Below the band: the base bound is the whole gate.
            true
        }
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
/// enum to prove it). It is the single source of truth for the SET of flood opcodes the #1626/#1796
/// penalty exemption applies to (the exemption itself is further narrowed to RATE violations — see
/// [`rejected_frame_incurs_penalty`]).
pub(crate) fn is_public_flood_opcode(msg_type: ProtocolMessageTypes) -> bool {
    matches!(
        msg_type as u8,
        crate::service::store_melted::STORE_MELTED
            | crate::service::holdings_announce::HOLDINGS_ANNOUNCE
    )
}

/// Whether a frame REJECTED by [`InboundRateLimiter::allows`] should additionally charge a
/// [`PenaltyReason::RateLimitExceeded`](crate::types::peer::PenaltyReason) reputation penalty against
/// the delivering peer, versus being dropped silently.
///
/// A rejected frame is ALWAYS dropped (the #1720 per-connection cap counts pre-verify frames,
/// eager duplicates included). Whether it ALSO incurs a penalty is scoped by BOTH the opcode AND the
/// KIND of violation (#1796):
///
/// - A **non-flood** opcode is always penalised on rejection (unchanged).
/// - A **public-flood** opcode (221/222) is penalised ONLY when the frame is a SIZE/format violation
///   (`exceeds_dig_wire_max_size`). An over-cap RATE/frequency rejection of a legit-sized flood stays
///   EXEMPT: on a multi-hop public flood the delivering connection is a **forwarder, not the origin**,
///   so charging it for redistributing another host's over-cap flood would ban honest relayers by
///   false attribution (#1626). But an OVERSIZED flood frame is not a forwarding artefact — no honest
///   relayer emits a frame larger than the enforced bound — so it is origin-attributable and IS
///   penalised.
///
/// Dropping an over-cap (rate) flood frame alone is graceful: the receiver's seen-set, Plumtree
/// eager/lazy redundancy, and the periodic re-announce all recover the message without the delivering
/// peer being punished. The exemption is thus opcode + violation-kind scoped, not opcode-only.
pub(crate) fn rejected_frame_incurs_penalty(msg: &DigMessage) -> bool {
    if is_public_flood_opcode(msg.msg_type) {
        // Flood opcode: exempt for an over-cap RATE rejection, penalised for a SIZE violation.
        exceeds_dig_wire_max_size(msg)
    } else {
        true
    }
}

/// Whether `msg`'s payload exceeds the single-frame `max_size` its opcode's
/// [`dig_extension_rate_limits_map`] row declares — i.e. the rejection is a SIZE/format violation
/// rather than a rate/frequency one. The row is the SINGLE SOURCE OF TRUTH for the bound (never a
/// hardcoded literal); an opcode with no row cannot exceed a bound it doesn't have, so returns
/// `false` (unreachable for 221/222 — the completeness guard pins their rows).
fn exceeds_dig_wire_max_size(msg: &DigMessage) -> bool {
    dig_extension_rate_limits_map()
        .get(&(msg.msg_type as u8))
        .map(|row| (msg.data.len() as f64) > row.max_size)
        .unwrap_or(false)
}

/// Table from [`CON-005.md`](../../../docs/requirements/domains/connection/specs/CON-005.md) §DIG Extension Rate Limits.
///
/// Frequencies are **per rolling minute bucket** (the [`RESET_SECONDS`] window). Sizes are maximum
/// **single-frame** payload bytes unless `max_total_size` is set.
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
    // `DigMessageType`); the DIG table is `u8 -> RateLimit`, so the bound applies uniformly.
    //
    // #1801 — `max_size` = `store_melted::ENCODED_LEN` (164 B), the EXACT enforced frame bound: a
    // StoreMelted announce is a fixed-length wire message that `StoreMeltedAnnounce::decode` accepts
    // only at exactly `ENCODED_LEN`, so every legit frame is provably `<= max_size` and never
    // hard-dropped, while any larger 221 frame is a size violation. Referencing the const keeps the
    // limiter and the enforced bound from drifting (mirrors the 222 tie to `MAX_ANNOUNCE_FRAME_BYTES`).
    m.insert(
        crate::service::store_melted::STORE_MELTED,
        RateLimit::new(10.0, crate::service::store_melted::ENCODED_LEN as f64, None),
    );
    // #1720 — holdings-announce (opcode 222) is a signed, periodic public-discovery broadcast that
    // any internet host can send, and its P-256 signature verify (`verify_holdings_announce`) runs on
    // the decoded frame. Without an explicit row it fell through to `default_settings` (100 frames/min,
    // 1 MiB) — bounding that expensive verify only by accident. Give it a deliberate row keyed by the
    // raw opcode (222 is a `ProtocolMessageTypes` variant in the vendored fork, not a `DigMessageType`;
    // the DIG table is `u8 -> RateLimit`, so the bound applies uniformly). Sized larger than 221:
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

/// Build the per-connection inbound gate for every inbound
/// [`LiveSlot`](crate::service::state::LiveSlot). See [`InboundRateLimiter::new`].
pub fn new_inbound_rate_limiter(rate_limit_factor: f64) -> InboundRateLimiter {
    InboundRateLimiter::new(rate_limit_factor)
}

#[cfg(test)]
mod tests {
    //! In-crate regression tests for the 220-band live gate (#1720, #1316).
    //!
    //! These drive the REAL [`InboundRateLimiter::allows`] production gate,
    //! NOT a hand-copied mirror. This is the authoritative regression guard: if the production gate
    //! ever drops its `>= DIG_WIRE_BAND_START` [`DigRateLimiter`] branch and reverts to
    //! `handle_message`-only, a 220-band flood would fall through to the loose 100/min
    //! `default_settings` and these tests go RED (proven by reverting the branch). The external
    //! mirror in `tests/con_005_tests.rs` cannot detect that regression and is only a secondary check.

    use dig_peer_protocol::{Bytes, ProtocolMessageTypes, Streamable};

    use super::*;

    /// #1760 D — completeness guard for the DIG 220-band rate-limit rows.
    ///
    /// [`DigRateLimiter::check`] **fails OPEN**: an opcode in the 220 band with no
    /// [`dig_extension_rate_limits_map`] row silently falls through to the loose Chia
    /// `default_settings` (100/min, 1 MiB) instead of a deliberate bound (the class of gap #1720
    /// closed for 221/222). This test enumerates every ≥[`DIG_WIRE_BAND_START`]
    /// [`ProtocolMessageTypes`] variant that actually exists (probed via the wire discriminant, so
    /// it can never go stale against a hand-copied list) and asserts each is CLASSIFIED — either it
    /// carries a dedicated rate-limit row, or it is a documented member of
    /// [`BASE_BOUND_ONLY_BAND_OPCODES`]. A newly-added 220-band opcode that is neither fails this
    /// test, forcing a deliberate rate-limit decision rather than a silent fail-open default.
    #[test]
    fn every_220_band_opcode_is_classified() {
        // Opcodes deliberately bounded ONLY by the base `handle_message` default (100/min, 1 MiB),
        // with no tighter dedicated DIG row. `DigMessage` (220) is a DIRECTED envelope whose
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

    /// Real 222 (HoldingsAnnounce) flood: the live gate admits the first 20 (the DIG row) and
    /// rejects the 21st, driven through the REAL [`InboundRateLimiter::allows`]. Without the 220-band branch
    /// this admits the 21st via the 100/min default, so the test pins that branch to production.
    #[test]
    fn real_gate_bounds_holdings_announce_222() {
        let announce_frame = || DigMessage {
            msg_type: ProtocolMessageTypes::HoldingsAnnounce,
            id: None,
            data: Bytes::new(vec![0u8; 1024]), // well under the 128 KiB max_size
        };
        let mut gate = InboundRateLimiter::new(1.0);
        for i in 0..20 {
            assert!(
                gate.allows(&announce_frame()),
                "frame {i} within the 20/min holdings-announce cap must pass the REAL gate"
            );
        }
        assert!(
            !gate.allows(&announce_frame()),
            "21st holdings-announce (222) must be rejected by the REAL InboundRateLimiter::allows (#1720)"
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
            .expect("opcode 222 has a DIG rate-limit row");
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
        let frame = |seed: u32| DigMessage {
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
        let mut gate = InboundRateLimiter::new(1.0);
        for seed in 0..20 {
            assert!(
                gate.allows(&frame(seed)),
                "frame {seed} within the 20/min 222 cap must pass the REAL gate"
            );
        }
        let over_cap = frame(999);
        assert!(
            !gate.allows(&over_cap),
            "21st 222 must be DROPPED by the REAL gate (#1720 cap intact)"
        );
        assert!(
            !rejected_frame_incurs_penalty(&over_cap),
            "a dropped 222 public flood must NOT charge a reputation penalty (#1626)"
        );
    }

    /// #1626 — same guarantee for 221 (StoreMelted): the 11th frame is dropped by the REAL gate yet
    /// exempt from the penalty. Covers 221 identically to 222 (the false-attribution bug is the same).
    #[test]
    fn over_cap_store_melted_221_is_dropped_but_not_penalised() {
        let frame = |seed: u32| DigMessage {
            msg_type: ProtocolMessageTypes::StoreMelted,
            id: None,
            data: Bytes::new({
                let mut v = vec![0u8; 164];
                v[0] = seed as u8;
                v[1] = (seed >> 8) as u8;
                v
            }),
        };
        let mut gate = InboundRateLimiter::new(1.0);
        for seed in 0..10 {
            assert!(
                gate.allows(&frame(seed)),
                "frame {seed} within the 10/min 221 cap must pass the REAL gate"
            );
        }
        let over_cap = frame(999);
        assert!(
            !gate.allows(&over_cap),
            "11th 221 must be DROPPED by the REAL gate (#1316 cap intact)"
        );
        assert!(
            !rejected_frame_incurs_penalty(&over_cap),
            "a dropped 221 public flood must NOT charge a reputation penalty (#1626)"
        );
    }

    /// #1626 — CONTRAST: an over-cap NON-flood opcode is dropped by the REAL gate AND still incurs the
    /// penalty. Proves the exemption is opcode-scoped, not a blanket disable of rate-limit attribution.
    #[test]
    fn over_cap_non_flood_opcode_is_still_penalised() {
        let frame = || DigMessage {
            msg_type: ProtocolMessageTypes::Handshake,
            id: None,
            data: Bytes::new(vec![0u8; 16]),
        };
        let mut gate = InboundRateLimiter::new(1.0);
        let mut rejected = None;
        // Drive the base bound past its cap; the first rejected frame is the one under test.
        for _ in 0..1_000 {
            if !gate.allows(&frame()) {
                rejected = Some(frame());
                break;
            }
        }
        let rejected = rejected.expect("a Handshake flood must eventually exceed its inbound cap");
        assert!(
            rejected_frame_incurs_penalty(&rejected),
            "a non-flood over-cap opcode MUST still be penalised (#1626 exemption is opcode-scoped)"
        );
    }

    /// #1720 — an oversized 222 (HoldingsAnnounce) frame — one whose payload EXCEEDS
    /// `MAX_ANNOUNCE_FRAME_BYTES` — is a SIZE/format violation, attributable to the delivering
    /// connection itself, so it is dropped AND penalised (a forwarder never legitimately relays a
    /// frame larger than the enforced bound).
    ///
    /// RED before #1796: the penalty was opcode-only, exempting ALL 221/222 rejections regardless of
    /// WHY, so an oversized flood frame escaped attribution.
    #[test]
    fn oversized_holdings_announce_222_is_penalised() {
        let over_size = DigMessage {
            msg_type: ProtocolMessageTypes::HoldingsAnnounce,
            id: None,
            data: Bytes::new(vec![
                0u8;
                crate::service::holdings_announce::MAX_ANNOUNCE_FRAME_BYTES
                    + 1
            ]),
        };
        let mut gate = InboundRateLimiter::new(1.0);
        assert!(
            !gate.allows(&over_size),
            "an oversized 222 frame must be rejected by the REAL gate (size cap)"
        );
        assert!(
            rejected_frame_incurs_penalty(&over_size),
            "an oversized (size-violating) 222 flood is origin-attributable and MUST be penalised"
        );
    }

    /// #1801 / #1796 — an oversized 221 (StoreMelted) frame — payload EXCEEDS `ENCODED_LEN` (164 B) —
    /// is a SIZE violation → dropped AND penalised. Mirrors the 222 case.
    ///
    /// RED before #1796: opcode-only exemption let it escape the penalty.
    #[test]
    fn oversized_store_melted_221_is_penalised() {
        let over_size = DigMessage {
            msg_type: ProtocolMessageTypes::StoreMelted,
            id: None,
            data: Bytes::new(vec![0u8; crate::service::store_melted::ENCODED_LEN + 1]),
        };
        let mut gate = InboundRateLimiter::new(1.0);
        assert!(
            !gate.allows(&over_size),
            "an oversized 221 frame must be rejected by the REAL gate (size cap)"
        );
        assert!(
            rejected_frame_incurs_penalty(&over_size),
            "an oversized (size-violating) 221 flood is origin-attributable and MUST be penalised"
        );
    }

    /// #1801 — the opcode-221 `max_size` MUST equal the enforced `ENCODED_LEN` (164 B) frame bound,
    /// mirroring the 222 tie to `MAX_ANNOUNCE_FRAME_BYTES`: the limiter row references that const, so
    /// a legit fixed-size StoreMelted announce is provably within the cap and never hard-dropped.
    #[test]
    fn store_melted_221_max_size_ties_to_enforced_frame_bound() {
        let limits = dig_extension_rate_limits_map();
        let row = limits
            .get(&crate::service::store_melted::STORE_MELTED)
            .expect("opcode 221 has a DIG rate-limit row");
        assert_eq!(
            row.max_size,
            crate::service::store_melted::ENCODED_LEN as f64
        );
    }

    /// Real 221 (StoreMelted, fixed `ENCODED_LEN` = 164 B) flood: the live gate admits the first 10
    /// (the DIG row) and rejects the 11th, driven through the REAL [`InboundRateLimiter::allows`].
    #[test]
    fn real_gate_bounds_store_melted_221() {
        let melted_frame = || DigMessage {
            msg_type: ProtocolMessageTypes::StoreMelted,
            id: None,
            data: Bytes::new(vec![0u8; 164]), // fixed StoreMeltedAnnounce ENCODED_LEN
        };
        let mut gate = InboundRateLimiter::new(1.0);
        for i in 0..10 {
            assert!(
                gate.allows(&melted_frame()),
                "frame {i} within the 10/min store-melted cap must pass the REAL gate"
            );
        }
        assert!(
            !gate.allows(&melted_frame()),
            "11th store-melted (221) must be rejected by the REAL InboundRateLimiter::allows (#1316)"
        );
    }
}
