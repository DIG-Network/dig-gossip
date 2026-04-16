//! Introducer-side vetting types.
//!
//! **Re-export:** STR-003; **state machine:** DSC-012.
//!
//! ## API-011
//!
//! [`VettedPeer`] is a Rust port of Chia `introducer_peers.py:12-28` — see
//! [`docs/requirements/domains/crate_api/specs/API-011.md`](../../../docs/requirements/domains/crate_api/specs/API-011.md)
//! and [`SPEC.md`](../../../docs/resources/SPEC.md) §2.8.
//!
//! ## SPEC citations
//!
//! - SPEC §2.8 — `VettedPeer` struct: signed `vetted` counter, `host`/`port`,
//!   `vetted_timestamp`, `last_attempt`, `time_added` (Chia `introducer_peers.py:12-28`).
//! - SPEC §1.6#9 — VettedPeer tracking: introducer tracks peers with vetting state
//!   (`introducer_peers.py:12-28`).

use crate::types::peer::metric_unix_timestamp_secs;

/// Collection of introducer-tracked peers with vetting state machine (**DSC-012**).
///
/// Rust port of Chia `introducer_peers.py:36-77` (`IntroducerPeers` class).
/// Stores known peers and tracks their vetting history so the introducer can
/// share only reachable peers with querying nodes.
///
/// SPEC §1.6#9: "VettedPeer tracking: introducer tracks peers with vetting state."
/// SPEC §2.8: "VettedPeer — 0=unvetted, negative=failed, positive=successful."
#[derive(Debug, Clone, Default)]
pub struct IntroducerPeers {
    peers: std::collections::HashSet<VettedPeer>,
}

impl IntroducerPeers {
    /// Create empty peer set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add peer to tracked set. Returns true if new, false if already present.
    ///
    /// Chia `introducer_peers.py:45-56` — add with `time_added`.
    pub fn add(&mut self, host: String, port: u16) -> bool {
        if port == 0 {
            return false;
        }
        let peer = VettedPeer {
            host,
            port,
            vetted: 0,
            vetted_timestamp: 0,
            last_attempt: 0,
            time_added: metric_unix_timestamp_secs(),
        };
        self.peers.insert(peer)
    }

    /// Remove peer from tracked set.
    ///
    /// Chia `introducer_peers.py:58-65`.
    pub fn remove(&mut self, host: &str, port: u16) -> bool {
        // HashSet::remove needs an owned value matching Hash/Eq (host+port).
        let dummy = VettedPeer {
            host: host.to_string(),
            port,
            vetted: 0,
            vetted_timestamp: 0,
            last_attempt: 0,
            time_added: 0,
        };
        self.peers.remove(&dummy)
    }

    /// Record a successful vetting probe.
    ///
    /// Increments `vetted` (resets to 1 if was negative). Updates timestamps.
    /// SPEC §2.8: "positive = consecutive successful probe count."
    pub fn record_success(&mut self, host: &str, port: u16) {
        if let Some(mut peer) = self.take(host, port) {
            let now = metric_unix_timestamp_secs();
            peer.vetted = if peer.vetted < 0 {
                1
            } else {
                peer.vetted.saturating_add(1)
            };
            peer.vetted_timestamp = now;
            peer.last_attempt = now;
            self.peers.insert(peer);
        }
    }

    /// Record a failed vetting probe.
    ///
    /// Decrements `vetted` (resets to -1 if was positive). Updates last_attempt.
    /// SPEC §2.8: "negative = consecutive failures."
    pub fn record_failure(&mut self, host: &str, port: u16) {
        if let Some(mut peer) = self.take(host, port) {
            let now = metric_unix_timestamp_secs();
            peer.vetted = if peer.vetted > 0 {
                -1
            } else {
                peer.vetted.saturating_sub(1)
            };
            peer.last_attempt = now;
            self.peers.insert(peer);
        }
    }

    /// Get all vetted peers (vetted > 0).
    ///
    /// Chia `introducer_peers.py:67-76` — `get_peers(recent_threshold)`.
    pub fn get_vetted_peers(&self) -> Vec<&VettedPeer> {
        self.peers.iter().filter(|p| p.vetted > 0).collect()
    }

    /// Get all peers regardless of vetting state.
    pub fn all_peers(&self) -> Vec<&VettedPeer> {
        self.peers.iter().collect()
    }

    /// Number of tracked peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether set is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Take peer out of set for mutation. Returns None if not found.
    fn take(&mut self, host: &str, port: u16) -> Option<VettedPeer> {
        let dummy = VettedPeer {
            host: host.to_string(),
            port,
            vetted: 0,
            vetted_timestamp: 0,
            last_attempt: 0,
            time_added: 0,
        };
        self.peers.take(&dummy)
    }
}

/// Introducer’s view of a candidate peer with **signed** vetting score.
///
/// - **`vetted == 0`:** never successfully vetted.
/// - **`vetted > 0`:** consecutive successful probe count.
/// - **`vetted < 0`:** consecutive failures (blacklist pressure).
///
/// **`Hash`/`Eq`** are implemented on `(host, port)` only so the `HashSet` in
/// [`IntroducerPeers`] can find/remove peers by address regardless of vetting state.
/// This matches Chia `introducer_peers.py:29-30` where `__eq__` and `__hash__`
/// use `(host, port)`.
#[derive(Debug, Clone)]
pub struct VettedPeer {
    /// Hostname or IP literal (same convention as [`crate::types::peer::PeerInfo::host`]).
    pub host: String,
    /// P2P listening port.
    pub port: u16,
    /// Signed consecutive success/failure counter (see struct docs).
    pub vetted: i32,
    /// When [`Self::vetted`] was last updated (Unix seconds).
    pub vetted_timestamp: u64,
    /// Last outbound connection attempt to this peer (Unix seconds).
    pub last_attempt: u64,
    /// When this row was first created (Unix seconds).
    pub time_added: u64,
}

// Hash/Eq by (host, port) only — matches Chia introducer_peers.py:29-30.
impl PartialEq for VettedPeer {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host && self.port == other.port
    }
}

impl Eq for VettedPeer {}

impl std::hash::Hash for VettedPeer {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.host.hash(state);
        self.port.hash(state);
    }
}
