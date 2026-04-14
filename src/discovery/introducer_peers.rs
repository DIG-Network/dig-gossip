//! Introducer-side vetting types.
//!
//! **Re-export:** STR-003; **state machine:** DSC-012.
//!
//! ## API-011
//!
//! [`VettedPeer`] is a Rust port of Chia `introducer_peers.py:12-28` — see
//! [`docs/requirements/domains/crate_api/specs/API-011.md`](../../../docs/requirements/domains/crate_api/specs/API-011.md)
//! and [`SPEC.md`](../../../docs/resources/SPEC.md) §2.8.

/// Collection / policy wrapper for introducer-tracked peers (DSC-012 — logic later).
#[derive(Debug, Clone, Default)]
pub struct IntroducerPeers {}

/// Introducer’s view of a candidate peer with **signed** vetting score.
///
/// - **`vetted == 0`:** never successfully vetted.
/// - **`vetted > 0`:** consecutive successful probe count.
/// - **`vetted < 0`:** consecutive failures (blacklist pressure).
///
/// **`Hash`** enables `HashSet`/`HashMap` keys for the introducer’s live directory without
/// allocating a composite key type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
