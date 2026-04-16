//! Plumtree eager/lazy push gossip protocol (**PLT-001** through **PLT-006**).
//!
//! # Requirements
//!
//! - **PLT-001** — PlumtreeState: eager_peers, lazy_peers, lazy_queue
//! - **PLT-002** — Eager push: full message to eager_peers
//! - **PLT-003** — Lazy push: hash-only LazyAnnounce to lazy_peers
//! - **PLT-004** — Duplicate detection → PRUNE (demote sender to lazy)
//! - **PLT-005** — Lazy timeout → GRAFT (promote sender to eager)
//! - **PLT-006** — Tree self-healing on peer disconnect
//! - **Master SPEC:** §8.1 (Plumtree Structured Gossip, Leitao et al., 2007)
//!
//! # Design
//!
//! All connected peers start as **eager**. When a duplicate is received via eager,
//! the sender is demoted to lazy and PRUNE is sent. When a lazy announcement
//! times out (hash not received eagerly), the announcer is promoted to eager
//! via GRAFT. This creates a spanning tree that self-heals.
//!
//! SPEC §1.8#1: "60-80% bandwidth reduction vs Chia's naive flood-to-all."

use std::collections::{HashMap, HashSet};

use chia_protocol::Bytes32;

use crate::constants::PLUMTREE_LAZY_TIMEOUT_MS;
use crate::types::peer::{metric_unix_timestamp_secs, PeerId};

/// Plumtree gossip state (**PLT-001**).
///
/// SPEC §8.1: "PlumtreeState with eager_peers, lazy_peers, lazy_queue."
/// All peers start as eager (SPEC §8.1: "Default: all peers start as eager").
#[derive(Debug)]
pub struct PlumtreeState {
    /// Eager peers: receive full messages (spanning tree neighbors).
    pub eager_peers: HashSet<PeerId>,
    /// Lazy peers: receive hash-only announcements.
    pub lazy_peers: HashSet<PeerId>,
    /// Pending lazy announcements: hash → vec of (announcer_peer_id, timestamp_ms).
    /// Used for lazy timeout detection (PLT-005).
    pub lazy_queue: HashMap<Bytes32, Vec<(PeerId, u64)>>,
    /// Lazy timeout in milliseconds (default 500ms).
    /// SPEC §8.1: "lazy_timeout_ms configurable (default 500ms)."
    pub lazy_timeout_ms: u64,
}

impl PlumtreeState {
    /// Create with default lazy timeout.
    pub fn new() -> Self {
        Self {
            eager_peers: HashSet::new(),
            lazy_peers: HashSet::new(),
            lazy_queue: HashMap::new(),
            lazy_timeout_ms: PLUMTREE_LAZY_TIMEOUT_MS,
        }
    }

    /// Create with custom lazy timeout.
    pub fn with_lazy_timeout(lazy_timeout_ms: u64) -> Self {
        Self {
            lazy_timeout_ms,
            ..Self::new()
        }
    }

    /// Add peer (starts as eager per SPEC §8.1).
    ///
    /// PLT-001: "All newly connected peers MUST start in eager_peers."
    pub fn add_peer(&mut self, peer_id: PeerId) {
        self.eager_peers.insert(peer_id);
    }

    /// Remove peer from both sets (on disconnect).
    ///
    /// PLT-006: tree self-healing starts after removal.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.eager_peers.remove(peer_id);
        self.lazy_peers.remove(peer_id);
    }

    /// Demote peer from eager to lazy (PLT-004 — on duplicate detection).
    ///
    /// SPEC §8.1: "Demote sender to lazy, send PRUNE."
    pub fn demote_to_lazy(&mut self, peer_id: &PeerId) {
        self.eager_peers.remove(peer_id);
        self.lazy_peers.insert(*peer_id);
    }

    /// Promote peer from lazy to eager (PLT-005 — on GRAFT / lazy timeout).
    ///
    /// SPEC §8.1: "Promote announcer from lazy to eager via GRAFT."
    pub fn promote_to_eager(&mut self, peer_id: &PeerId) {
        self.lazy_peers.remove(peer_id);
        self.eager_peers.insert(*peer_id);
    }

    /// Record a lazy announcement for timeout tracking (PLT-005).
    ///
    /// SPEC §8.1: "Start timer: lazy_queue.insert(hash, (from, now()))."
    pub fn record_lazy_announce(&mut self, hash: Bytes32, announcer: PeerId) {
        let now_ms = metric_unix_timestamp_secs() * 1000;
        self.lazy_queue
            .entry(hash)
            .or_default()
            .push((announcer, now_ms));
    }

    /// Cancel lazy timer for a hash (received eagerly, PLT-005).
    ///
    /// SPEC §8.1: "Cancel any pending lazy timer for this hash."
    pub fn cancel_lazy_timer(&mut self, hash: &Bytes32) {
        self.lazy_queue.remove(hash);
    }

    /// Get timed-out lazy announcements (PLT-005).
    ///
    /// Returns (hash, announcer_peer_id) pairs where the announcement
    /// has been pending longer than `lazy_timeout_ms`.
    pub fn get_timed_out_lazy(&self) -> Vec<(Bytes32, PeerId)> {
        let now_ms = metric_unix_timestamp_secs() * 1000;
        let mut timed_out = Vec::new();

        for (hash, announcers) in &self.lazy_queue {
            for &(announcer, announced_at) in announcers {
                if now_ms.saturating_sub(announced_at) >= self.lazy_timeout_ms {
                    timed_out.push((*hash, announcer));
                    break; // one GRAFT per hash is enough
                }
            }
        }

        timed_out
    }

    /// Check if peer is eager.
    pub fn is_eager(&self, peer_id: &PeerId) -> bool {
        self.eager_peers.contains(peer_id)
    }

    /// Check if peer is lazy.
    pub fn is_lazy(&self, peer_id: &PeerId) -> bool {
        self.lazy_peers.contains(peer_id)
    }

    /// Total tracked peers (eager + lazy).
    pub fn peer_count(&self) -> usize {
        self.eager_peers.len() + self.lazy_peers.len()
    }

    /// Eager peer count.
    pub fn eager_count(&self) -> usize {
        self.eager_peers.len()
    }

    /// Lazy peer count.
    pub fn lazy_count(&self) -> usize {
        self.lazy_peers.len()
    }
}

impl Default for PlumtreeState {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// PLT-009 — Plumtree wire types
// =========================================================================
//
// SPEC §8.1 — LazyAnnounce, Prune, Graft, RequestByHash.
// DigMessageType IDs 214-217 defined in types/dig_messages.rs.
// These structs are the serializable message bodies.

/// Hash-only announcement sent to lazy peers (**PLT-003**, DigMessageType 214).
///
/// SPEC §8.1: "LazyAnnounce { hash, msg_type } to lazy_peers."
/// Lazy peers that don't receive the message eagerly within `lazy_timeout_ms`
/// will GRAFT this hash from the announcer.
///
/// Wire format: bincode-serialized (not JSON). `hash` is 32 raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LazyAnnounce {
    /// SHA256(msg_type || data) of the full message (32 bytes).
    pub hash: Bytes32,
    /// Original message type (so the receiver knows what to expect on GRAFT).
    pub msg_type: u8,
}

/// Tree pruning message (**PLT-004**, DigMessageType 215).
///
/// SPEC §8.1: "On receiving duplicate via eager, send PRUNE to sender."
/// Empty body — the message type ID is sufficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prune;

/// Tree grafting message (**PLT-005**, DigMessageType 216).
///
/// SPEC §8.1: "On lazy timeout, send GRAFT to announcer."
/// Includes the hash of the message to request (combined with RequestByHash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Graft {
    /// Hash of the message being requested (from LazyAnnounce).
    pub hash: Option<Bytes32>,
}

/// Request a specific message by hash (**PLT-005**, DigMessageType 217).
///
/// SPEC §8.1: "Send GRAFT + RequestByHash { hash } to announcer."
/// The receiver looks up the hash in their MessageCache and sends it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestByHash {
    /// SHA256 hash of the requested message (32 bytes).
    pub hash: Bytes32,
}
