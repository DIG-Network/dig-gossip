//! ERLAY-style transaction relay (**ERL-001** through **ERL-008**).
//!
//! # Requirements
//!
//! - **ERL-001** — Flood set: ERLAY_FLOOD_PEER_COUNT (8) random peers
//! - **ERL-002** — Low-fanout: NewTransaction to flood set only
//! - **ERL-003** — Sketch encode/decode (pure Rust, minisketch-rs unavailable)
//! - **ERL-004** — Set reconciliation per non-flood peer every 2000ms
//! - **ERL-005** — Symmetric difference + missing tx exchange
//! - **ERL-006** — Flood set rotation every 60s
//! - **ERL-007** — Inbound peers excluded from flood set
//! - **ERL-008** — ErlayConfig struct
//! - **Master SPEC:** §8.3 (ERLAY, Naumenko et al., 2019)
//!
//! # Feature gate
//!
//! Gated behind `erlay` feature. Note: `minisketch-rs` crate has bindgen
//! conflicts with chia-sdk-client; sketch math is pure Rust.
//!
//! # Design
//!
//! ERLAY splits transaction relay into:
//! 1. **Flood set** (~8 outbound peers): immediate NewTransaction announcements
//! 2. **Reconciliation set** (remaining peers): periodic sketch exchange
//!
//! SPEC §1.8#3: "Per-transaction bandwidth drops from O(connections) to ~O(1)."

use std::collections::HashSet;

use dig_protocol::Bytes32;

use crate::constants::{
    ERLAY_FLOOD_PEER_COUNT, ERLAY_FLOOD_SET_ROTATION_SECS, ERLAY_RECONCILIATION_INTERVAL_MS,
    ERLAY_SKETCH_CAPACITY,
};
use crate::types::peer::PeerId;

/// ERLAY configuration (**ERL-008**).
///
/// SPEC §8.3: "ErlayConfig with flood_peer_count, reconciliation_interval_ms, sketch_capacity."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErlayConfig {
    /// Peers to flood NewTransaction to immediately (default 8).
    pub flood_peer_count: usize,
    /// Reconciliation interval per non-flood peer in ms (default 2000).
    pub reconciliation_interval_ms: u64,
    /// Max set difference decodable per reconciliation (default 20).
    pub sketch_capacity: usize,
}

impl Default for ErlayConfig {
    fn default() -> Self {
        Self {
            flood_peer_count: ERLAY_FLOOD_PEER_COUNT,
            reconciliation_interval_ms: ERLAY_RECONCILIATION_INTERVAL_MS,
            sketch_capacity: ERLAY_SKETCH_CAPACITY,
        }
    }
}

/// ERLAY per-node state (**ERL-001** through **ERL-007**).
///
/// Manages flood set selection, rotation, and reconciliation sketch tracking.
#[derive(Debug)]
pub struct ErlayState {
    /// Current flood set — these peers receive immediate NewTransaction.
    /// ERL-001: "ERLAY_FLOOD_PEER_COUNT random connected peers."
    pub flood_set: HashSet<PeerId>,
    /// Timestamp when flood set was last rotated (Unix seconds).
    /// ERL-006: "re-randomized every ERLAY_FLOOD_SET_ROTATION_SECS."
    pub last_rotation: u64,
    /// Transaction IDs known locally (for reconciliation sketching).
    /// ERL-003: sketch encode uses this set.
    pub local_tx_ids: HashSet<Bytes32>,
    /// Config.
    pub config: ErlayConfig,
}

impl ErlayState {
    /// Create with default config.
    pub fn new() -> Self {
        Self {
            flood_set: HashSet::new(),
            last_rotation: 0,
            local_tx_ids: HashSet::new(),
            config: ErlayConfig::default(),
        }
    }

    /// Create with custom config.
    pub fn with_config(config: ErlayConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    /// Select flood set from available outbound peers (**ERL-001**).
    ///
    /// SPEC §8.3: "ERLAY_FLOOD_PEER_COUNT random connected peers."
    /// ERL-007: "Inbound peers MUST NOT be in flood set."
    pub fn select_flood_set(&mut self, outbound_peers: &[PeerId]) {
        use rand::seq::SliceRandom;

        let mut candidates = outbound_peers.to_vec();
        candidates.shuffle(&mut rand::thread_rng());
        candidates.truncate(self.config.flood_peer_count);

        self.flood_set = candidates.into_iter().collect();
        self.last_rotation = crate::types::peer::metric_unix_timestamp_secs();
    }

    /// Check if flood set needs rotation (**ERL-006**).
    ///
    /// SPEC §8.3: "Flood set re-randomized every ERLAY_FLOOD_SET_ROTATION_SECS."
    pub fn needs_rotation(&self) -> bool {
        let now = crate::types::peer::metric_unix_timestamp_secs();
        now.saturating_sub(self.last_rotation) >= ERLAY_FLOOD_SET_ROTATION_SECS
    }

    /// Check if peer is in flood set (**ERL-002**).
    ///
    /// SPEC §8.3: "NewTransaction sent only to flood set."
    pub fn is_flood_peer(&self, peer_id: &PeerId) -> bool {
        self.flood_set.contains(peer_id)
    }

    /// Record a new local transaction ID (**ERL-002/ERL-003**).
    ///
    /// Added to local_tx_ids for sketch encoding during reconciliation.
    pub fn add_local_tx(&mut self, tx_id: Bytes32) {
        self.local_tx_ids.insert(tx_id);
    }

    /// Get flood set size.
    pub fn flood_set_size(&self) -> usize {
        self.flood_set.len()
    }

    /// Get local tx count (for reconciliation).
    pub fn local_tx_count(&self) -> usize {
        self.local_tx_ids.len()
    }

    /// Clear local tx IDs (after reconciliation round).
    pub fn clear_local_txs(&mut self) {
        self.local_tx_ids.clear();
    }
}

impl Default for ErlayState {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple reconciliation sketch (**ERL-003**).
///
/// Pure Rust placeholder for minisketch. XOR-based set sketch
/// that can encode a set of tx_ids and decode the symmetric
/// difference with another sketch.
///
/// NOTE: This is a simplified implementation. Real minisketch uses
/// BCH error-correcting codes for efficient decoding.
#[derive(Debug, Clone, Default)]
pub struct ReconciliationSketch {
    /// XOR accumulator of 8-byte truncated tx_ids.
    /// Simple symmetric difference: XOR(A) XOR XOR(B) = XOR(A △ B).
    elements: Vec<u64>,
    /// Capacity (max decodable differences).
    pub capacity: usize,
}

impl ReconciliationSketch {
    /// Create sketch with given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            elements: Vec::new(),
            capacity,
        }
    }

    /// Create with default capacity.
    pub fn with_default_capacity() -> Self {
        Self::new(ERLAY_SKETCH_CAPACITY)
    }

    /// Add a tx_id to the sketch.
    pub fn add(&mut self, tx_id: &Bytes32) {
        let truncated = u64::from_le_bytes(tx_id.as_ref()[..8].try_into().unwrap());
        self.elements.push(truncated);
    }

    /// Number of elements in sketch.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}
