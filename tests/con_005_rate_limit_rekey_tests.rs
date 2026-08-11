//! CON-005 — the Chia rate-limit table survives being re-keyed onto raw opcodes.
//!
//! # Why this file exists
//!
//! Inbound rate limiting used to run through `chia_sdk_client::RateLimiter`, keyed by
//! `ProtocolMessageTypes`. That enum cannot name a DIG opcode, which is one of the two
//! reasons dig-gossip vendored a forked `chia-protocol` (dig_ecosystem#2228). The fork
//! retires by moving to [`dig_peer_protocol::OpcodeRateLimiter`], which re-keys Chia's
//! own `V2_RATE_LIMITS` from the enum onto the wire byte.
//!
//! **A re-key is precisely the operation that can silently loosen every bound.** If an
//! entry fails to carry across, its opcode does not error — it quietly falls through to
//! `default_settings`, which is far more permissive than most specific rows. A rate-limit
//! table that silently becomes permissive is a DoS surface, and nothing about it is
//! visible to the compiler.
//!
//! # How these tests are built to catch that
//!
//! The bounds are pinned as **absolute literals**, deliberately *not* by comparing the
//! re-keyed table against `V2_RATE_LIMITS`. Asking the same possibly-shifted table for
//! its own expected answer only proves it agrees with itself; it cannot see a shift that
//! moved both sides together.
//!
//! The fixtures are chosen so a collapse to `default_settings` is *loudly* visible rather
//! than marginal:
//!
//! - `Handshake` is capped at **5 frames** per window against a default of 100 — so a
//!   collapsed table admits the 6th frame instead of refusing it, a 20x gap.
//! - `RequestPeers` is capped at **100 bytes** per message against a default of 1 MiB —
//!   so a collapsed table admits a body four orders of magnitude too large.
//!
//! Each bound is pinned from **both** sides (at-bound admitted, one-over refused): a
//! bound tested only from below can be satisfied by a limiter that refuses everything,
//! and one tested only from above by a limiter with no bound at all.

use dig_gossip::connection::inbound_limits::InboundRateLimiter;
use dig_peer_protocol::{DigMessage, ProtocolMessageTypes, V2_RATE_LIMITS};

/// Wire opcode of `Handshake`, whose Chia row is far tighter than `default_settings`.
const HANDSHAKE: u8 = ProtocolMessageTypes::Handshake as u8;

/// Wire opcode of `RequestPeers`, whose Chia row has a very small `max_size`.
const REQUEST_PEERS: u8 = ProtocolMessageTypes::RequestPeers as u8;

/// Chia's `Handshake => 5, 10 * 1024` frequency, restated as a literal on purpose.
const HANDSHAKE_FREQUENCY: usize = 5;

/// Chia's `RequestPeers => 10, 100` per-message size cap, restated as a literal.
const REQUEST_PEERS_MAX_SIZE: usize = 100;

/// `default_settings` frequency — the value a collapsed table would apply instead.
const DEFAULT_FREQUENCY: usize = 100;

/// A limiter with an unscaled budget, so the literals above are the bounds under test.
fn limiter() -> InboundRateLimiter {
    InboundRateLimiter::new(1.0)
}

/// Build an inbound frame of `opcode` carrying `body_len` bytes.
fn frame(opcode: u8, body_len: usize) -> DigMessage {
    DigMessage::new(opcode, None, vec![0u8; body_len].into())
}

#[test]
fn handshake_keeps_its_tight_frequency_and_does_not_fall_to_the_default() {
    // The fixture is only meaningful while the specific row is far below the default; if that ever
    // stops holding, this test can no longer see a collapse. Both operands are consts, so clippy
    // sees a constant assertion — that is the point: the guard must fail the build the moment the
    // fixture goes blind.
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            HANDSHAKE_FREQUENCY < DEFAULT_FREQUENCY,
            "fixture is blind unless the Handshake row is tighter than default_settings"
        );
    }

    let mut limiter = limiter();

    for i in 1..=HANDSHAKE_FREQUENCY {
        assert!(
            limiter.allows(&frame(HANDSHAKE, 64)),
            "frame {i} is within the Handshake budget of {HANDSHAKE_FREQUENCY}"
        );
    }

    assert!(
        !limiter.allows(&frame(HANDSHAKE, 64)),
        "frame {} must be refused; admitting it means the Handshake row was lost and \
         default_settings ({DEFAULT_FREQUENCY}/window) is being applied instead",
        HANDSHAKE_FREQUENCY + 1
    );
}

#[test]
fn request_peers_keeps_its_tight_size_cap_and_does_not_fall_to_the_default() {
    // Two independent limiters, so the at-cap probe cannot spend budget the over-cap
    // probe is then refused for -- that would make the second assertion pass for the
    // wrong reason.
    let mut at_cap = limiter();
    let mut over_cap = limiter();

    assert!(
        at_cap.allows(&frame(REQUEST_PEERS, REQUEST_PEERS_MAX_SIZE)),
        "a body of exactly {REQUEST_PEERS_MAX_SIZE} bytes is at the cap and must pass"
    );

    assert!(
        !over_cap.allows(&frame(REQUEST_PEERS, REQUEST_PEERS_MAX_SIZE + 1)),
        "a {}-byte body must be refused; admitting it means the RequestPeers row was \
         lost and the 1 MiB default cap is being applied instead",
        REQUEST_PEERS_MAX_SIZE + 1
    );
}

#[test]
fn no_chia_opcode_occupies_the_dig_band() {
    // Every DIG opcode lives at 200-222. A Chia opcode there would collide after the
    // re-key: two different messages would share one budget row, and the DIG bound
    // dig-gossip layers on top would be applied to Chia traffic.
    for (label, keys) in [
        ("tx", V2_RATE_LIMITS.tx.keys()),
        ("other", V2_RATE_LIMITS.other.keys()),
    ] {
        for msg_type in keys {
            let opcode = *msg_type as u8;
            assert!(
                opcode < 200,
                "{label} row {msg_type:?} sits at opcode {opcode}, inside the DIG band"
            );
        }
    }
}

#[test]
fn the_chia_table_is_populated() {
    // A table that silently emptied would push EVERY opcode onto default_settings while
    // each individual bound test above still passed for whichever rows remained. The
    // floor is set well below the real count so ordinary upstream churn does not trip
    // it, while an emptied or drastically truncated table does.
    let entries = V2_RATE_LIMITS.tx.len() + V2_RATE_LIMITS.other.len();
    assert!(
        entries >= 50,
        "expected a populated Chia rate-limit table, found {entries} entries"
    );
}

#[test]
fn an_untabled_opcode_really_is_looser_which_is_what_makes_the_tests_above_falsifiable() {
    // The control. Every assertion above claims a specific row is TIGHTER than the
    // fallback -- but if the fallback were itself tight (or if every opcode were capped
    // at 5), those tests would pass while proving nothing.
    //
    // Opcode 200 is the first DIG consensus-band opcode. It has no Chia row, so it takes
    // `default_settings`; and it sits below DIG_WIRE_BAND_START (220), so dig-gossip's
    // own DIG bound does not apply either. It therefore measures the fallback alone.
    let mut limiter = limiter();

    for i in 1..=HANDSHAKE_FREQUENCY + 1 {
        assert!(
            limiter.allows(&frame(200, 64)),
            "frame {i} on an untabled opcode must still be admitted: the fallback is \
             {DEFAULT_FREQUENCY}/window, so if it refuses here then the Handshake test \
             above cannot distinguish a preserved row from a collapsed one"
        );
    }
}
