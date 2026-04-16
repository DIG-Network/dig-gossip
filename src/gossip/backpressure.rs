//! Adaptive backpressure (**PRI-005** through **PRI-008**).
//!
//! # Requirements
//!
//! - **PRI-005** — BackpressureConfig with configurable thresholds
//! - **PRI-006** — Tx dedup suppression at BACKPRESSURE_TX_DEDUP_THRESHOLD (25)
//! - **PRI-007** — Bulk drop at BACKPRESSURE_BULK_DROP_THRESHOLD (50)
//! - **PRI-008** — Normal delay at BACKPRESSURE_NORMAL_DELAY_THRESHOLD (100)
//! - **Master SPEC:** §8.5 (Adaptive Backpressure)
//!
//! # Design
//!
//! Monitors outbound queue depth per connection. As depth increases:
//! 0-25: normal operation
//! 25-50: duplicate NewTransaction suppressed
//! 50-100: Bulk messages dropped, ERLAY paused
//! 100+: Normal messages delayed (batched every 500ms). Critical always unaffected.
//!
//! SPEC §1.8#8: "Prevents cascading slowdowns under peak load."

use std::collections::HashSet;

use chia_protocol::Bytes32;

use crate::constants::{
    BACKPRESSURE_BULK_DROP_THRESHOLD, BACKPRESSURE_NORMAL_DELAY_THRESHOLD,
    BACKPRESSURE_TX_DEDUP_THRESHOLD,
};

/// Backpressure thresholds (**PRI-005**).
///
/// SPEC §8.5: "BackpressureConfig with normal_delay_threshold (100),
/// bulk_drop_threshold (50), tx_dedup_threshold (25)."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackpressureConfig {
    /// Queue depth for tx dedup suppression (PRI-006). Default: 25.
    pub tx_dedup_threshold: usize,
    /// Queue depth for bulk message drop (PRI-007). Default: 50.
    pub bulk_drop_threshold: usize,
    /// Queue depth for normal message delay (PRI-008). Default: 100.
    pub normal_delay_threshold: usize,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            tx_dedup_threshold: BACKPRESSURE_TX_DEDUP_THRESHOLD,
            bulk_drop_threshold: BACKPRESSURE_BULK_DROP_THRESHOLD,
            normal_delay_threshold: BACKPRESSURE_NORMAL_DELAY_THRESHOLD,
        }
    }
}

/// Current backpressure level based on queue depth.
///
/// SPEC §8.5 behavior table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackpressureLevel {
    /// Queue depth 0-24: normal operation.
    Normal,
    /// Queue depth 25-49: tx dedup active (PRI-006).
    TxDedup,
    /// Queue depth 50-99: bulk drop + ERLAY pause (PRI-007).
    BulkDrop,
    /// Queue depth 100+: normal delay (PRI-008). Critical unaffected.
    NormalDelay,
}

impl BackpressureLevel {
    /// Determine level from queue depth and config (**PRI-005**).
    pub fn from_depth(depth: usize, config: &BackpressureConfig) -> Self {
        if depth >= config.normal_delay_threshold {
            Self::NormalDelay
        } else if depth >= config.bulk_drop_threshold {
            Self::BulkDrop
        } else if depth >= config.tx_dedup_threshold {
            Self::TxDedup
        } else {
            Self::Normal
        }
    }
}

/// Per-connection backpressure state (**PRI-006** through **PRI-008**).
///
/// Tracks tx dedup filter and current level for a single connection.
#[derive(Debug)]
pub struct BackpressureState {
    /// Config thresholds.
    pub config: BackpressureConfig,
    /// Seen tx_ids for dedup suppression (PRI-006).
    /// Only active when level >= TxDedup.
    seen_tx_ids: HashSet<Bytes32>,
}

impl BackpressureState {
    pub fn new(config: BackpressureConfig) -> Self {
        Self {
            config,
            seen_tx_ids: HashSet::new(),
        }
    }

    /// Get current backpressure level from queue depth.
    pub fn level(&self, queue_depth: usize) -> BackpressureLevel {
        BackpressureLevel::from_depth(queue_depth, &self.config)
    }

    /// Check if a NewTransaction tx_id should be suppressed (**PRI-006**).
    ///
    /// SPEC §8.5: "At 25+, duplicate NewTransaction suppressed (first per tx_id only)."
    /// Returns true if the tx should be sent (not suppressed).
    pub fn should_send_tx(&mut self, tx_id: &Bytes32, queue_depth: usize) -> bool {
        if self.level(queue_depth) < BackpressureLevel::TxDedup {
            return true; // no backpressure — send everything
        }
        // Suppress duplicate: only first announcement passes
        self.seen_tx_ids.insert(*tx_id)
    }

    /// Check if a Bulk message should be dropped (**PRI-007**).
    ///
    /// SPEC §8.5: "At 50+, Bulk messages dropped silently."
    pub fn should_drop_bulk(&self, queue_depth: usize) -> bool {
        self.level(queue_depth) >= BackpressureLevel::BulkDrop
    }

    /// Check if Normal messages should be delayed (**PRI-008**).
    ///
    /// SPEC §8.5: "At 100+, Normal messages delayed (batched every 500ms)."
    pub fn should_delay_normal(&self, queue_depth: usize) -> bool {
        self.level(queue_depth) >= BackpressureLevel::NormalDelay
    }

    /// Reset tx dedup filter (e.g., on new block or period).
    pub fn reset_tx_dedup(&mut self) {
        self.seen_tx_ids.clear();
    }
}
