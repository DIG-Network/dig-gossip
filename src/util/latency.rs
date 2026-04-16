//! RTT sampling and composite peer scoring utilities (**PRF-001**, **PRF-002**, **PRF-003**).
//!
//! # Requirements
//!
//! - **PRF-001** — RTT tracking (rolling window, composite score)
//! - **PRF-002** — Peer selection preference by score
//! - **PRF-003** — Plumtree tree optimization (prefer low-latency eager peers)
//! - **Master SPEC:** §1.8#6 (latency-aware peer scoring)
//!
//! # Design
//!
//! The core RTT tracking lives in [`PeerReputation`](crate::types::reputation::PeerReputation)
//! (`record_rtt_ms`, `avg_rtt_ms`, `score`). This module provides utility functions
//! for comparing peers by score and selecting optimal Plumtree tree configurations.
//!
//! SPEC §1.8#6: "score = trust_score × (1 / avg_rtt_ms). Higher = better."

use crate::types::peer::PeerId;
use crate::types::reputation::PeerReputation;

/// Compare two peers by composite score (PRF-002).
///
/// Returns the peer with higher score (preferred for outbound selection).
/// If scores are equal, returns peer_a (stable tie-breaking).
///
/// SPEC §1.8#6: "outbound selection prefers higher-scored peers."
pub fn prefer_by_score<'a>(
    peer_a: (&'a PeerId, &PeerReputation),
    peer_b: (&'a PeerId, &PeerReputation),
) -> &'a PeerId {
    if peer_b.1.score > peer_a.1.score {
        peer_b.0
    } else {
        peer_a.0
    }
}

/// Find the worst-RTT peer among a set (for Plumtree tree optimization).
///
/// PRF-003: "When a lower-latency peer is discovered, replace higher-latency eager."
/// Returns the peer with highest avg_rtt_ms (worst latency).
pub fn worst_rtt_peer<'a>(peers: &'a [(PeerId, PeerReputation)]) -> Option<&'a PeerId> {
    peers
        .iter()
        .filter(|(_, rep)| rep.avg_rtt_ms.is_some())
        .max_by_key(|(_, rep)| rep.avg_rtt_ms.unwrap_or(0))
        .map(|(pid, _)| pid)
}

/// Find the best-RTT peer among a set (for Plumtree tree optimization).
///
/// PRF-003: candidate lazy peer to promote to eager if faster than worst eager.
pub fn best_rtt_peer<'a>(peers: &'a [(PeerId, PeerReputation)]) -> Option<&'a PeerId> {
    peers
        .iter()
        .filter(|(_, rep)| rep.avg_rtt_ms.is_some() && rep.avg_rtt_ms.unwrap_or(0) > 0)
        .min_by_key(|(_, rep)| rep.avg_rtt_ms.unwrap_or(u64::MAX))
        .map(|(pid, _)| pid)
}

/// Check if swapping eager/lazy peers would improve tree latency (PRF-003).
///
/// Returns true if best_lazy_rtt < worst_eager_rtt (swap would help).
pub fn should_swap_for_latency(worst_eager_rtt: Option<u64>, best_lazy_rtt: Option<u64>) -> bool {
    match (worst_eager_rtt, best_lazy_rtt) {
        (Some(eager), Some(lazy)) => lazy < eager,
        _ => false, // can't compare without RTT data
    }
}
