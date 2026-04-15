//! Peer reputation tracking and graduated penalty enforcement (**API-006** / SPEC §2.5).
//!
//! This module implements the reputation model that extends Chia's binary ban/trust
//! approach (`chia_sdk_client::ClientState`) with:
//!
//! - **Numeric penalty accumulation** — each misbehavior adds weighted points toward a
//!   ban threshold, rather than immediately banning or silently ignoring.
//! - **RTT-based latency scoring** — a rolling window of round-trip samples feeds into
//!   a composite score used for peer selection (PRF-001) and Plumtree tree optimization
//!   (PRF-002).
//! - **Time-limited bans** — peers are banned for [`BAN_DURATION_SECS`] (1 hour) and
//!   then may reconnect, unlike Chia's permanent `ClientState::ban()`.
//! - **AS-level grouping** — `as_number` caches the Autonomous System for IP-diversity
//!   enforcement (one outbound per AS, mirroring Chia's `address_manager.py` bucket
//!   diversification).
//!
//! ## Normative references
//!
//! - [`API-006.md`](../../../docs/requirements/domains/crate_api/specs/API-006.md) —
//!   struct and field requirements.
//! - [`CON-007.md`](../../../docs/requirements/domains/connection/specs/CON-007.md) —
//!   penalty point table and ban/unban lifecycle.
//! - [`NORMATIVE.md`](../../../docs/requirements/domains/crate_api/NORMATIVE.md) — API-006
//!   normative prose.
//! - [`SPEC.md`](../../../docs/resources/SPEC.md) §2.5 — PeerReputation design.
//!
//! ## Chia comparison
//!
//! Chia's `ClientState` offers only `ban(ip)` / `unban(ip)` with no point weights,
//! no RTT scoring, and no automatic expiry. DIG layers this richer model *on top of*
//! `ClientState` — the [`crate::service::gossip_handle::GossipHandle::penalize_peer`]
//! bridge calls `ClientState::ban()` when `PeerReputation` crosses the threshold.
//!
//! ## Design notes
//!
//! - **No `Hash` on [`PenaltyReason`]** — API-006: not used as a `HashMap` key.
//! - **`PeerReputation` is only `PartialEq`, not `Eq`** — `score` is `f64` (NaN would break total equality).
//! - **Saturating penalty math** — avoids wraparound attacks from malicious peers spamming penalties.
//!   Without saturation, a u32 overflow would reset `penalty_points` to near-zero, effectively
//!   un-banning a malicious peer.
//! - **Ban expiry** — call [`PeerReputation::refresh_ban_status`] with wall-clock seconds on read paths
//!   (CON-007 / CNC-006 will centralize scheduling).

use std::collections::VecDeque;

use crate::constants::{BAN_DURATION_SECS, PENALTY_BAN_THRESHOLD, RTT_WINDOW_SIZE};

/// Why a peer was penalized (gossip / consensus / transport policy).
///
/// Each variant carries a fixed penalty weight (see [`PenaltyReason::penalty_points`]).
/// Weights are defined by the **CON-007** penalty table and chosen so that:
///
/// - A single critical violation (`InvalidBlock`, `ConsensusError`) equals
///   [`PENALTY_BAN_THRESHOLD`] (100 pts) and triggers an **immediate ban**.
/// - Moderate violations (`InvalidAttestation`, `ProtocolViolation` at 50 pts)
///   require two occurrences to reach the ban threshold.
/// - Minor / transient issues (`ConnectionIssue` at 10 pts, `RateLimitExceeded`
///   at 15 pts) accumulate gradually, banning only chronic offenders.
///
/// # Requirement traceability
///
/// - [`API-006.md`](../../../docs/requirements/domains/crate_api/specs/API-006.md) — enum definition.
/// - [`CON-007.md`](../../../docs/requirements/domains/connection/specs/CON-007.md) — point weights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyReason {
    /// Peer sent a block that fails validation. **100 pts — immediate ban.**
    ///
    /// A single invalid block is treated as a critical protocol violation because
    /// it can waste significant validation resources and may indicate a Byzantine
    /// or eclipse-attack peer.
    InvalidBlock,

    /// Peer sent an attestation that fails signature or epoch verification.
    /// **50 pts** — two occurrences trigger a ban.
    ///
    /// Less severe than `InvalidBlock` because attestation validation is cheaper,
    /// but still indicates either a buggy or malicious node.
    InvalidAttestation,

    /// Peer sent a message that could not be deserialized or violated structural
    /// invariants (e.g., wrong field count, unknown message type).
    /// **20 pts** — five occurrences trigger a ban.
    ///
    /// Relatively lenient because version skew or partial upgrades can cause
    /// transient parse failures.
    MalformedMessage,

    /// Peer is sending an excessive volume of valid but unnecessary messages
    /// (e.g., duplicate announcements, repeated requests for data already sent).
    /// **25 pts** — four occurrences trigger a ban.
    Spam,

    /// Transport-level failure: keepalive timeout, TLS error, unexpected
    /// disconnect. **10 pts** — ten occurrences trigger a ban.
    ///
    /// Low weight because connection issues are often transient (network flap,
    /// peer restart). Applied by [`crate::connection::keepalive::disconnect_after_keepalive_failure`]
    /// on each keepalive failure (CON-004).
    ConnectionIssue,

    /// Peer violated the wire protocol (e.g., sent a response without a matching
    /// request, used a forbidden message during handshake).
    /// **50 pts** — two occurrences trigger a ban.
    ProtocolViolation,

    /// Peer exceeded the per-connection rate limit (messages per second).
    /// **15 pts** — seven occurrences trigger a ban.
    ///
    /// Slightly lighter than `Spam` because rate-limit hits can be caused by
    /// bursty but legitimate traffic.
    RateLimitExceeded,

    /// Peer's behavior is inconsistent with the consensus rules (e.g., proposing
    /// on the wrong epoch, conflicting checkpoint votes). **100 pts — immediate ban.**
    ///
    /// Treated identically to `InvalidBlock` in severity because consensus
    /// violations threaten chain integrity.
    ConsensusError,
}

impl PenaltyReason {
    /// Return the numeric weight added to [`PeerReputation::penalty_points`] for this
    /// reason.
    ///
    /// Values follow the **CON-007 penalty table** so that
    /// [`crate::service::gossip_handle::GossipHandle::penalize_peer`] and the
    /// keepalive disconnect path
    /// ([`crate::connection::keepalive::disconnect_after_keepalive_failure`]) agree
    /// on cost.
    ///
    /// The function is `const` so it can be used in constant expressions (e.g.,
    /// compile-time assertions in tests).
    pub const fn penalty_points(self) -> u32 {
        match self {
            PenaltyReason::InvalidBlock => 100,
            PenaltyReason::InvalidAttestation => 50,
            PenaltyReason::MalformedMessage => 20,
            PenaltyReason::Spam => 25,
            PenaltyReason::ConnectionIssue => 10,
            PenaltyReason::ProtocolViolation => 50,
            PenaltyReason::RateLimitExceeded => 15,
            PenaltyReason::ConsensusError => 100,
        }
    }
}

/// Rolling reputation state for a single peer: penalties, optional timed ban, RTT
/// sample window, composite score, and cached AS number.
///
/// # Ownership
///
/// Each [`crate::service::state::LiveSlot`] owns a `Mutex<PeerReputation>`. The mutex
/// is locked briefly by the keepalive task (to record RTT) and by penalty paths (to
/// accumulate points). There is no cross-peer locking — each peer's reputation is
/// independent.
///
/// # Invariants
///
/// - `penalty_points` is monotonically non-decreasing within a ban cycle (reset only
///   on unban, which is handled externally by CON-007 / CNC-006).
/// - `rtt_history.len() <= RTT_WINDOW_SIZE` at all times.
/// - `score` is always non-negative and finite (never NaN or negative).
/// - `is_banned == true` implies `ban_until.is_some()`.
///
/// # Requirement traceability
///
/// - [`API-006.md`](../../../docs/requirements/domains/crate_api/specs/API-006.md) — struct fields and defaults.
/// - [`CON-007.md`](../../../docs/requirements/domains/connection/specs/CON-007.md) — ban lifecycle.
/// - PRF-001 / PRF-002 — `score` feeds peer selection and Plumtree tree optimization.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PeerReputation {
    /// Cumulative penalty points accumulated via [`apply_penalty`](Self::apply_penalty).
    ///
    /// Uses saturating addition to prevent u32 wraparound — a malicious peer spamming
    /// penalties cannot overflow this back to zero. When the value reaches
    /// [`PENALTY_BAN_THRESHOLD`] (100), the peer is auto-banned.
    pub penalty_points: u32,

    /// Whether this peer is currently banned. Set to `true` by [`apply_penalty`](Self::apply_penalty)
    /// when `penalty_points >= PENALTY_BAN_THRESHOLD`, cleared by
    /// [`refresh_ban_status`](Self::refresh_ban_status) after `ban_until` expires.
    pub is_banned: bool,

    /// Unix-seconds timestamp at which the current ban expires. `Some(_)` iff
    /// `is_banned == true`. Set to `now + BAN_DURATION_SECS` (3600 s = 1 hour) when
    /// the ban is imposed.
    pub ban_until: Option<u64>,

    /// The most recent reason this peer was penalized. Updated on every
    /// [`apply_penalty`](Self::apply_penalty) call. Useful for diagnostics and logging;
    /// does not affect scoring.
    pub last_penalty_reason: Option<PenaltyReason>,

    /// Rolling average of recent RTT samples in milliseconds, or `None` if no samples
    /// have been recorded yet.
    ///
    /// Updated by [`record_rtt_ms`](Self::record_rtt_ms) (called from the keepalive
    /// loop, CON-004). Feeds into [`score`](Self::score) computation for latency-aware
    /// peer selection (PRF-001).
    pub avg_rtt_ms: Option<u64>,

    /// Circular buffer of the last [`RTT_WINDOW_SIZE`] (10) RTT samples in
    /// milliseconds. Oldest samples are evicted when the buffer is full.
    ///
    /// The window size is kept small to react quickly to latency changes while still
    /// smoothing out individual outliers.
    pub rtt_history: VecDeque<u64>,

    /// Composite peer quality score: `trust_factor * (1.0 / avg_rtt_ms)`.
    ///
    /// - **`trust_factor`** = `max(0, 1 - penalty_points / PENALTY_BAN_THRESHOLD)` —
    ///   linearly decreases from 1.0 (no penalties) to 0.0 (at ban threshold).
    /// - **`1.0 / avg_rtt_ms`** — inverse latency, so lower RTT yields a higher score.
    ///
    /// The product means: a peer with zero penalties and 10 ms RTT scores 0.1,
    /// while the same peer with 50 penalty points scores 0.05 (halved trust).
    /// A peer at the ban threshold or with no RTT data scores 0.0.
    ///
    /// This formulation is intentionally simple — it can be replaced with a more
    /// sophisticated model (e.g., exponential decay, Bayesian trust) in future phases.
    /// The key property is that it is cheap to compute on every RTT sample without
    /// needing historical state beyond the window.
    ///
    /// Returns `0.0` when `avg_rtt_ms` is `None` or `0` (avoids division by zero —
    /// API-006 edge case).
    pub score: f64,

    /// Autonomous System number for this peer's IP address, cached from a BGP prefix
    /// table lookup on first connection.
    ///
    /// Used for AS-level diversity enforcement: the outbound connector avoids opening
    /// multiple connections to the same AS, reducing the effectiveness of AS-level
    /// eclipse attacks (similar to Chia's `address_manager.py` bucket grouping by
    /// /16 prefix).
    pub as_number: Option<u32>,
}

impl PeerReputation {
    /// Accumulate penalty points for `reason` and auto-ban if the threshold is reached.
    ///
    /// # Arguments
    ///
    /// - `reason` — the misbehavior category (determines point weight).
    /// - `now_unix_secs` — current wall-clock time as Unix seconds, used to set
    ///   `ban_until`. Passed explicitly so callers can use a consistent timestamp
    ///   across multiple operations and tests can inject deterministic values.
    ///
    /// # Semantics
    ///
    /// - **Saturating add:** `penalty_points` uses [`u32::saturating_add`] so that
    ///   overflow is impossible. Without this, a malicious peer that triggers many
    ///   small penalties could wrap the counter back to zero and escape a ban.
    /// - **Auto-ban:** once `penalty_points >= PENALTY_BAN_THRESHOLD` (100), the peer
    ///   is immediately marked banned with a `ban_until` of
    ///   `now_unix_secs + BAN_DURATION_SECS` (3600 s). The ban check is idempotent —
    ///   additional penalties on an already-banned peer just extend `ban_until`.
    ///
    /// # Post-conditions
    ///
    /// - `self.penalty_points >= old_penalty_points`
    /// - `self.last_penalty_reason == Some(reason)`
    /// - If `self.penalty_points >= PENALTY_BAN_THRESHOLD`: `self.is_banned == true`
    ///   and `self.ban_until.is_some()`.
    ///
    /// # Cross-references
    ///
    /// - CON-007 step "Penalty Application"
    /// - Called from [`crate::connection::keepalive::disconnect_after_keepalive_failure`]
    ///   and [`crate::service::gossip_handle::GossipHandle::penalize_peer`].
    pub fn apply_penalty(&mut self, reason: PenaltyReason, now_unix_secs: u64) {
        self.penalty_points = self.penalty_points.saturating_add(reason.penalty_points());
        self.last_penalty_reason = Some(reason);
        if self.penalty_points >= PENALTY_BAN_THRESHOLD {
            self.is_banned = true;
            // saturating_add guards against far-future timestamps overflowing u64.
            self.ban_until = Some(now_unix_secs.saturating_add(BAN_DURATION_SECS));
        }
    }

    /// Check whether a time-limited ban has expired and, if so, clear the ban flag.
    ///
    /// # When to call
    ///
    /// This should be called on **read paths** that consult `is_banned` — for example,
    /// before deciding whether to accept a reconnection or include a peer in gossip
    /// fan-out. A centralized periodic sweep (CNC-006, not yet implemented) will
    /// eventually call this for all known peers.
    ///
    /// # Arguments
    ///
    /// - `now_unix_secs` — current wall-clock time. If `now_unix_secs > ban_until`,
    ///   the ban is considered expired.
    ///
    /// # Post-conditions
    ///
    /// If the ban expired: `self.is_banned == false` and `self.ban_until == None`.
    /// Note that `penalty_points` is **not** reset here — CON-007 specifies that
    /// points reset on unban, but that is handled by the higher-level unban flow
    /// which also calls `ClientState::unban()`.
    pub fn refresh_ban_status(&mut self, now_unix_secs: u64) {
        if let Some(until) = self.ban_until {
            if now_unix_secs > until {
                self.is_banned = false;
                self.ban_until = None;
            }
        }
    }

    /// Record a single RTT sample (in milliseconds), maintain the sliding window, and
    /// recompute [`avg_rtt_ms`](Self::avg_rtt_ms) and [`score`](Self::score).
    ///
    /// # Windowed average algorithm
    ///
    /// The last [`RTT_WINDOW_SIZE`] (10) samples are kept in a [`VecDeque`]. When the
    /// buffer is full, the oldest sample is evicted before the new one is pushed.
    /// The average is a simple arithmetic mean of all samples in the window — no
    /// exponential weighting, because the small window already provides fast
    /// responsiveness to latency changes.
    ///
    /// # Score recomputation
    ///
    /// After updating the average, [`recompute_score`](Self::recompute_score) is called
    /// to refresh the composite score (see [`score`](Self::score) field docs for the
    /// formula).
    ///
    /// # Call sites
    ///
    /// Called from the keepalive loop ([`crate::connection::keepalive::keepalive_loop`])
    /// on each successful `RequestPeers` probe (CON-004 step 4).
    pub fn record_rtt_ms(&mut self, rtt_ms: u64) {
        // Evict oldest sample if window is full, maintaining the invariant
        // rtt_history.len() <= RTT_WINDOW_SIZE.
        if self.rtt_history.len() == RTT_WINDOW_SIZE {
            self.rtt_history.pop_front();
        }
        self.rtt_history.push_back(rtt_ms);
        self.recompute_rtt_average();
        self.recompute_score();
    }

    /// Recompute `avg_rtt_ms` as the arithmetic mean of `rtt_history`.
    ///
    /// Sets `avg_rtt_ms = None` when the history is empty (no samples yet).
    /// Division uses `n.max(1)` as a defensive guard, though `n == 0` is already
    /// handled by the early return.
    fn recompute_rtt_average(&mut self) {
        if self.rtt_history.is_empty() {
            self.avg_rtt_ms = None;
            return;
        }
        let sum: u64 = self.rtt_history.iter().copied().sum();
        let n = self.rtt_history.len() as u64;
        self.avg_rtt_ms = Some(sum / n.max(1));
    }

    /// Recompute the composite peer quality score.
    ///
    /// ## Formula
    ///
    /// ```text
    /// trust = clamp(1.0 - penalty_points / PENALTY_BAN_THRESHOLD, 0.0, 1.0)
    /// score = trust * (1.0 / avg_rtt_ms)
    /// ```
    ///
    /// **Why this formulation:**
    ///
    /// - `trust` linearly degrades as penalties accumulate, reaching zero at the ban
    ///   threshold. This means a peer with 50 points of penalties is valued at half
    ///   the rate of a clean peer with the same latency.
    /// - `1 / avg_rtt_ms` favors low-latency peers, which is desirable for block
    ///   propagation speed (reducing orphan rates and improving finality time).
    /// - The product ensures that *either* high penalties *or* high latency drive
    ///   the score toward zero — a peer must be both trustworthy and fast to rank
    ///   highly.
    ///
    /// **Edge cases:** score is set to `0.0` when `avg_rtt_ms` is `None` (no samples)
    /// or `0` (avoid division by zero). A zero-RTT sample is theoretically impossible
    /// in practice but is guarded against defensively (API-006 edge case).
    fn recompute_score(&mut self) {
        let Some(avg) = self.avg_rtt_ms else {
            self.score = 0.0;
            return;
        };
        if avg == 0 {
            self.score = 0.0;
            return;
        }
        // trust_factor: 1.0 for a clean peer, 0.0 at or above ban threshold.
        let trust = (1.0
            - (f64::from(self.penalty_points) / f64::from(PENALTY_BAN_THRESHOLD)).min(1.0))
        .max(0.0);
        self.score = trust * (1.0 / avg as f64);
    }
}
