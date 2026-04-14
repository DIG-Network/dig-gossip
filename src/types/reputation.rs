//! Peer reputation and penalty reasons (**API-006** / SPEC §2.5).
//!
//! **Normative:** [`API-006.md`](../../../docs/requirements/domains/crate_api/specs/API-006.md),
//! [`NORMATIVE.md`](../../../docs/requirements/domains/crate_api/NORMATIVE.md).
//!
//! **Point weights** match the CON-007 table so connection policy and gossip agree:
//! [`CON-007.md`](../../../docs/requirements/domains/connection/specs/CON-007.md).
//!
//! ## Design notes
//!
//! - **No `Hash` on [`PenaltyReason`]** — API-006: not used as a `HashMap` key.
//! - **`PeerReputation` is only `PartialEq`, not `Eq`** — `score` is `f64` (NaN would break total equality).
//! - **Saturating penalty math** — avoids wraparound attacks from malicious peers spamming penalties.
//! - **Ban expiry** — call [`PeerReputation::refresh_ban_status`] with wall-clock seconds on read paths
//!   (CON-007 / CNC-006 will centralize scheduling).

use std::collections::VecDeque;

use crate::constants::{BAN_DURATION_SECS, PENALTY_BAN_THRESHOLD, RTT_WINDOW_SIZE};

/// Why a peer was penalized (gossip / consensus / transport policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyReason {
    InvalidBlock,
    InvalidAttestation,
    MalformedMessage,
    Spam,
    ConnectionIssue,
    ProtocolViolation,
    RateLimitExceeded,
    ConsensusError,
}

impl PenaltyReason {
    /// Numeric weight added to [`PeerReputation::penalty_points`] for this reason.
    ///
    /// Values follow **CON-007** so [`crate::service::gossip_handle::GossipHandle::penalize_peer`] and
    /// future per-connection reputation stay consistent.
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

/// Rolling reputation: penalties, optional timed ban, RTT sample window, coarse score, cached ASN.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PeerReputation {
    /// Cumulative penalty points (saturating add).
    pub penalty_points: u32,
    pub is_banned: bool,
    pub ban_until: Option<u64>,
    pub last_penalty_reason: Option<PenaltyReason>,
    pub avg_rtt_ms: Option<u64>,
    pub rtt_history: VecDeque<u64>,
    /// `trust * (1 / avg_rtt_ms)` when `avg_rtt_ms > 0`, else `0.0` (API-006 — avoids div-by-zero).
    pub score: f64,
    pub as_number: Option<u32>,
}

impl PeerReputation {
    /// Apply a penalty at `now_unix_secs` (wall-clock seconds). Sets ban window when over threshold.
    pub fn apply_penalty(&mut self, reason: PenaltyReason, now_unix_secs: u64) {
        self.penalty_points = self.penalty_points.saturating_add(reason.penalty_points());
        self.last_penalty_reason = Some(reason);
        if self.penalty_points >= PENALTY_BAN_THRESHOLD {
            self.is_banned = true;
            self.ban_until = Some(now_unix_secs.saturating_add(BAN_DURATION_SECS));
        }
    }

    /// Clear `is_banned` when `now_unix_secs` is past `ban_until` (time-limited bans, API-006).
    pub fn refresh_ban_status(&mut self, now_unix_secs: u64) {
        if let Some(until) = self.ban_until {
            if now_unix_secs > until {
                self.is_banned = false;
                self.ban_until = None;
            }
        }
    }

    /// Push one RTT sample (ms), keep last [`RTT_WINDOW_SIZE`] samples, refresh average + [`Self::score`].
    pub fn record_rtt_ms(&mut self, rtt_ms: u64) {
        if self.rtt_history.len() == RTT_WINDOW_SIZE {
            self.rtt_history.pop_front();
        }
        self.rtt_history.push_back(rtt_ms);
        self.recompute_rtt_average();
        self.recompute_score();
    }

    fn recompute_rtt_average(&mut self) {
        if self.rtt_history.is_empty() {
            self.avg_rtt_ms = None;
            return;
        }
        let sum: u64 = self.rtt_history.iter().copied().sum();
        let n = self.rtt_history.len() as u64;
        self.avg_rtt_ms = Some(sum / n.max(1));
    }

    /// Trust shrinks linearly with penalty ratio; score favors low RTT when trust remains.
    fn recompute_score(&mut self) {
        let Some(avg) = self.avg_rtt_ms else {
            self.score = 0.0;
            return;
        };
        if avg == 0 {
            self.score = 0.0;
            return;
        }
        let trust = (1.0
            - (f64::from(self.penalty_points) / f64::from(PENALTY_BAN_THRESHOLD)).min(1.0))
        .max(0.0);
        self.score = trust * (1.0 / avg as f64);
    }
}
