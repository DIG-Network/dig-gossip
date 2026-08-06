//! CON-005 — the DIG L2 per-opcode inbound rate limiter, keyed by the **raw wire byte**.
//!
//! ## Why this is a DIG type and not a Chia one
//!
//! DIG's per-opcode bound was originally bolted onto the vendored `chia-sdk-client` fork as
//! `RateLimits::dig_wire` + `RateLimiter::check_dig_extension`. It never needed to be: the DIG
//! table is keyed by the raw opcode `u8`, never by [`ProtocolMessageTypes`], and its accounting
//! state was already fully parallel to Chia's — a separate count map, a separate size map, sharing
//! only a window boundary and a scalar factor. Both are trivially reproducible here, so the bound
//! lives in DIG's own crate and the fork keeps only genuinely upstreamable API
//! (dig_ecosystem#2228).
//!
//! Keying by the raw byte is also the *coherent* treatment, and deliberately so. Whether the
//! 220-band opcodes should be [`ProtocolMessageTypes`] variants at all is a separate, open wire
//! question. A limiter keyed by `u8` is correct under **either** answer — it bounds an opcode that
//! is a Chia enum variant and one that is not, identically — so nothing here prejudges it.
//!
//! ## Relationship to the Chia bound
//!
//! This limiter never *replaces* Chia's; it only ever adds a restriction. The composed inbound
//! gate ([`InboundRateLimiter`](super::inbound_limits::InboundRateLimiter)) applies
//! [`RateLimiter::handle_message`](dig_peer_protocol::RateLimiter::handle_message) first and
//! unconditionally, so a DIG opcode with no row is still bounded by Chia's `default_settings`.
//!
//! ## Normative trace
//!
//! - [`CON-005.md`](../../../docs/requirements/domains/connection/specs/CON-005.md)
//! - [`SPEC.md`](../../../docs/resources/SPEC.md) §5.3
//!
//! [`ProtocolMessageTypes`]: dig_peer_protocol::ProtocolMessageTypes

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use dig_peer_protocol::RateLimit;

/// A rolling-window rate limiter over DIG wire opcodes, keyed by the raw discriminant byte.
///
/// One instance belongs to one connection. Counts and cumulative sizes accumulate per opcode
/// within a window and are cleared wholesale when the window rolls over.
#[derive(Debug, Clone)]
pub struct DigRateLimiter {
    /// Whether this limiter guards an INBOUND connection.
    ///
    /// On an inbound connection a *rejected* frame still charges its count and size (the peer
    /// already spent our bandwidth to deliver it, so a flood must not be free). On an outbound
    /// connection only an admitted frame is charged, because the caller retries rather than sends.
    incoming: bool,
    /// Window length in seconds. The window boundary is absolute — `unix_secs / reset_seconds` —
    /// not measured from construction, so every limiter on the host rolls over in lockstep.
    reset_seconds: u64,
    /// The window this limiter's tallies belong to. A change means the tallies are stale.
    period: u64,
    /// Scales every configured bound; `< 1.0` tightens, `> 1.0` loosens.
    limit_factor: f64,
    /// Per-opcode bounds. An opcode absent from this table is unbounded *here* (fail-open) and is
    /// left to the Chia base bound.
    limits: HashMap<u8, RateLimit>,
    /// Frames admitted-or-charged per opcode in the current window.
    counts: HashMap<u8, f64>,
    /// Cumulative payload bytes charged per opcode in the current window.
    sizes: HashMap<u8, f64>,
}

impl DigRateLimiter {
    /// Builds a limiter over `limits`, scaled by `limit_factor`, resetting every `reset_seconds`.
    pub fn new(
        incoming: bool,
        reset_seconds: u64,
        limit_factor: f64,
        limits: HashMap<u8, RateLimit>,
    ) -> Self {
        Self {
            incoming,
            reset_seconds,
            period: current_period(reset_seconds),
            limit_factor,
            limits,
            counts: HashMap::new(),
            sizes: HashMap::new(),
        }
    }

    /// Rate-checks one frame of `data_len` payload bytes carrying wire opcode `wire_type`.
    ///
    /// Returns whether the frame is within its bound. An opcode with **no row fails OPEN**
    /// (returns `true`) — it is not silently dropped, it is simply not bounded here; the Chia base
    /// bound in the composed gate still applies. The completeness guard in
    /// [`inbound_limits`](super::inbound_limits) is what keeps a new 220-band opcode from reaching
    /// production relying on that fall-through.
    pub fn check(&mut self, wire_type: u8, data_len: u32) -> bool {
        self.sync_period();

        let Some(limits) = self.limits.get(&wire_type).copied() else {
            return true;
        };

        let size = f64::from(data_len);
        let new_count = self.counts.get(&wire_type).unwrap_or(&0.0) + 1.0;
        let new_cumulative_size = self.sizes.get(&wire_type).unwrap_or(&0.0) + size;
        // An unset `max_total_size` means "as much as the frequency and per-frame caps jointly
        // allow", not "unbounded" — mirroring the Chia table's own convention.
        let max_total_size = limits
            .max_total_size
            .unwrap_or(limits.frequency * limits.max_size);

        let passed = new_count <= limits.frequency * self.limit_factor
            && size <= limits.max_size
            && new_cumulative_size <= max_total_size * self.limit_factor;

        if self.incoming || passed {
            *self.counts.entry(wire_type).or_default() = new_count;
            *self.sizes.entry(wire_type).or_default() = new_cumulative_size;
        }

        passed
    }

    /// Discards the previous window's tallies once the wall clock has crossed a boundary.
    fn sync_period(&mut self) {
        let period = current_period(self.reset_seconds);
        if self.period != period {
            self.period = period;
            self.counts.clear();
            self.sizes.clear();
        }
    }
}

/// The absolute window index the wall clock currently falls in.
fn current_period(reset_seconds: u64) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        / reset_seconds
}

#[cfg(test)]
mod tests {
    //! Tests for the properties that the dig_ecosystem#2228 extraction could silently have lost.
    //!
    //! Each fixture is built to separate the real property from the NEAREST WRONG implementation,
    //! which for this move is: a window measured from construction instead of from the absolute
    //! clock, an accounting rule that charges only admitted frames, a dropped `limit_factor`, and a
    //! `max_total_size` of `None` read as "unbounded".

    use std::{thread::sleep, time::Duration};

    use dig_peer_protocol::{Bytes, Message, ProtocolMessageTypes, RateLimiter, V2_RATE_LIMITS};

    use super::*;

    /// The 221 anchor row, used where a test needs a small, concrete bound.
    const FREQ: f64 = 10.0;
    const MAX_SIZE: f64 = 164.0;

    fn limiter_of(incoming: bool, reset_seconds: u64, factor: f64) -> DigRateLimiter {
        let mut limits = HashMap::new();
        limits.insert(221u8, RateLimit::new(FREQ, MAX_SIZE, None));
        DigRateLimiter::new(incoming, reset_seconds, factor, limits)
    }

    /// Sleeps until the wall clock has just crossed into a fresh `reset_seconds` window, so a test
    /// starts with a full window of headroom rather than a random fraction of one.
    fn wait_for_window_start(reset_seconds: u64) {
        let start = current_period(reset_seconds);
        while current_period(reset_seconds) == start {
            sleep(Duration::from_millis(20));
        }
    }

    /// The window is ABSOLUTE (`unix_secs / reset_seconds`), not elapsed-since-construction — and
    /// the Chia limiter this bound was extracted out of agrees with it on the boundary.
    ///
    /// Before #2228 a single `period` field cleared the Chia and DIG tallies together, so they could
    /// not disagree by construction. Now they are separate objects and only a shared ABSOLUTE
    /// formula keeps them in step. The fixture STAGGERS construction by ~1 s of a 2 s window
    /// precisely so an elapsed-since-construction window would be observably different: at the final
    /// assertion the Chia half is ~2 s old (it would have rolled either way) while the DIG half is
    /// only ~1 s old, so an elapsed window would leave it still exhausted and that assertion RED.
    /// Both are also asserted still-exhausted BEFORE the boundary, so "both admit" cannot be
    /// satisfied merely by time having passed.
    #[test]
    fn window_boundary_is_absolute_and_shared_with_the_chia_limiter() {
        const RESET: u64 = 2;

        let mut chia_limits = (*V2_RATE_LIMITS).clone();
        chia_limits.other.insert(
            ProtocolMessageTypes::Handshake,
            RateLimit::new(1.0, 1_000_000.0, None),
        );
        let handshake = || Message {
            msg_type: ProtocolMessageTypes::Handshake,
            id: None,
            data: Bytes::new(vec![0u8; 10]),
        };

        wait_for_window_start(RESET);
        let opening_period = current_period(RESET);

        // Constructed at the START of the window.
        let mut chia = RateLimiter::new(true, RESET, 1.0, chia_limits);
        // Constructed ~1 s LATER, in the SAME window — the stagger is the discriminator.
        sleep(Duration::from_secs(1));
        let mut dig = limiter_of(true, RESET, 1.0);

        // Exhaust both within this window.
        assert!(chia.handle_message(&handshake()));
        assert!(!chia.handle_message(&handshake()), "chia half exhausted");
        for _ in 0..FREQ as u32 {
            assert!(dig.check(221, 1));
        }
        assert!(!dig.check(221, 1), "dig half exhausted");

        // Control: still inside the opening window, so both must STILL reject. Without this the
        // final assertions could pass merely because the boundary was crossed early.
        assert_eq!(
            current_period(RESET),
            opening_period,
            "test lost its race with the window boundary; the bounds below would be vacuous"
        );
        assert!(!chia.handle_message(&handshake()));
        assert!(!dig.check(221, 1));

        // Cross the shared absolute boundary.
        wait_for_window_start(RESET);
        assert!(
            chia.handle_message(&handshake()),
            "chia tallies must clear on the absolute boundary"
        );
        assert!(
            dig.check(221, 1),
            "the DIG tallies must clear on the SAME absolute boundary despite the later \
             construction — an elapsed-since-construction window fails here (#2228)"
        );
    }

    /// On an INBOUND connection a rejected frame still charges its count: a peer cannot buy free
    /// retries by sending junk.
    ///
    /// The fixture rejects the first `FREQ` frames on SIZE (each one byte over `max_size`), then
    /// offers a perfectly legal frame. It must be rejected, because the count is already at the cap.
    /// Under the nearest wrong implementation — charge only when admitted — the count would still be
    /// zero and the legal frame would pass.
    #[test]
    fn inbound_charges_rejected_frames_so_junk_buys_no_retries() {
        let mut lim = limiter_of(true, 60, 1.0);
        let oversized = MAX_SIZE as u32 + 1;

        for i in 0..FREQ as u32 {
            assert!(
                !lim.check(221, oversized),
                "oversized frame {i} is rejected"
            );
        }
        assert!(
            !lim.check(221, MAX_SIZE as u32),
            "a legal-sized frame after {FREQ} rejected oversized ones must STILL be rejected — \
             rejected frames are charged against an inbound peer's budget"
        );
    }

    /// The counterpart: on an OUTBOUND limiter only admitted frames are charged, so a caller that
    /// backs off and retries is not punished for the attempts it made.
    #[test]
    fn outbound_charges_only_admitted_frames() {
        let mut lim = limiter_of(false, 60, 1.0);
        let oversized = MAX_SIZE as u32 + 1;

        for _ in 0..FREQ as u32 {
            assert!(!lim.check(221, oversized));
        }
        assert!(
            lim.check(221, MAX_SIZE as u32),
            "an outbound limiter must not charge rejected attempts"
        );
    }

    /// `limit_factor` scales the frequency bound. Pinned from BOTH sides: the frame at the scaled
    /// bound passes and the one over it fails.
    #[test]
    fn limit_factor_scales_the_frequency_bound_from_both_sides() {
        let mut lim = limiter_of(true, 60, 0.5);
        let scaled = (FREQ * 0.5) as u32;

        for i in 1..=scaled {
            assert!(
                lim.check(221, 1),
                "frame {i} is at or under the scaled bound"
            );
        }
        assert!(
            !lim.check(221, 1),
            "frame {} is one over the 0.5-scaled bound of {scaled}",
            scaled + 1
        );
    }

    /// A per-frame size one byte over `max_size` fails while exactly `max_size` passes — the bound
    /// pinned from both sides, so an off-by-one comparison cannot satisfy it.
    #[test]
    fn max_size_is_inclusive_and_one_over_fails() {
        let mut lim = limiter_of(true, 60, 1.0);
        assert!(lim.check(221, MAX_SIZE as u32), "exactly max_size passes");
        assert!(
            !lim.check(221, MAX_SIZE as u32 + 1),
            "one byte over max_size fails"
        );
    }

    /// An unset `max_total_size` means `frequency * max_size`, NOT unbounded.
    ///
    /// A row whose `max_total_size` is `None` can never have its cumulative bound BIND — reaching
    /// `frequency * max_size` takes `frequency` max-sized frames, by which point the count bound has
    /// already tripped — so the volume rule is only observable against an explicit `Some` row that
    /// is DELIBERATELY looser on count than on volume. This fixture sets `frequency` high (100) and
    /// `max_total_size` low (250 B) so the cumulative bound is the one that trips: two 100-byte
    /// frames pass and the third (total 300 > 250) fails, with the count nowhere near its cap.
    #[test]
    fn explicit_max_total_size_bounds_cumulative_volume_before_the_count_cap() {
        let mut limits = HashMap::new();
        limits.insert(221u8, RateLimit::new(100.0, 200.0, Some(250.0)));
        let mut lim = DigRateLimiter::new(true, 60, 1.0, limits);

        assert!(
            lim.check(221, 100),
            "cumulative 100 B is under the 250 B cap"
        );
        assert!(
            lim.check(221, 100),
            "cumulative 200 B is under the 250 B cap"
        );
        assert!(
            !lim.check(221, 100),
            "cumulative 300 B exceeds max_total_size=250 while the count (3) is far under \
             frequency=100 — the volume bound must be enforced independently"
        );
    }

    /// An opcode with no row fails OPEN, indefinitely.
    #[test]
    fn unrowed_opcode_fails_open_indefinitely() {
        let mut lim = limiter_of(true, 60, 1.0);
        for _ in 0..1_000 {
            assert!(
                lim.check(254, 10_000_000),
                "an unrowed opcode is not bounded here"
            );
        }
    }

    /// Tallies are per-opcode: exhausting one opcode leaves another untouched.
    #[test]
    fn tallies_are_scoped_per_opcode() {
        let mut limits = HashMap::new();
        limits.insert(221u8, RateLimit::new(FREQ, MAX_SIZE, None));
        limits.insert(222u8, RateLimit::new(FREQ, MAX_SIZE, None));
        let mut lim = DigRateLimiter::new(true, 60, 1.0, limits);

        for _ in 0..FREQ as u32 {
            assert!(lim.check(221, 1));
        }
        assert!(!lim.check(221, 1), "221 is exhausted");
        assert!(lim.check(222, 1), "222 has its own budget");
    }
}
