//! Message priority lanes and per-connection queues (**PRI-001** through **PRI-004**).
//!
//! # Requirements
//!
//! - **PRI-001** — MessagePriority enum (Critical/Normal/Bulk) + assignment
//! - **PRI-002** — PriorityOutbound: three VecDeque per connection
//! - **PRI-003** — Drain order: critical → normal → one bulk
//! - **PRI-004** — Starvation prevention: 1 bulk per PRIORITY_STARVATION_RATIO
//! - **Master SPEC:** §8.4 (Message Priority Lanes)
//!
//! # Design
//!
//! SPEC §1.8#4: "Prevents consensus-critical latency spikes during bulk sync."
//! Chia sends all messages on one WebSocket with no priority. A 50MB RespondBlocks
//! blocks a 512-byte NewPeak. Priority lanes fix this.

use std::collections::VecDeque;

use chia_protocol::{Message, ProtocolMessageTypes};

use crate::constants::PRIORITY_STARVATION_RATIO;

/// Message priority level (**PRI-001**).
///
/// SPEC §8.4: "Critical = always first. Normal = after critical. Bulk = last."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessagePriority {
    /// Consensus-critical: NewPeak, blocks, attestations. Never dropped.
    Critical = 0,
    /// Normal: transactions, requests. May be delayed under backpressure.
    Normal = 1,
    /// Bulk: mempool sync, peer exchange, historical blocks. Dropped first.
    Bulk = 2,
}

impl MessagePriority {
    /// Classify a Chia ProtocolMessageType into priority (**PRI-001**).
    ///
    /// SPEC §8.4 priority assignment table.
    pub fn from_chia_type(msg_type: ProtocolMessageTypes) -> Self {
        use ProtocolMessageTypes::*;
        match msg_type {
            // Critical: consensus-critical
            NewPeak | RespondBlock | RespondUnfinishedBlock => Self::Critical,

            // Normal: transactions, requests
            NewTransaction
            | RespondTransaction
            | NewUnfinishedBlock
            | RequestBlock
            | RequestTransaction
            | RequestUnfinishedBlock => Self::Normal,

            // Bulk: everything else (sync, peer exchange, mempool)
            RequestBlocks
            | RespondBlocks
            | RequestPeers
            | RespondPeers
            | RequestMempoolTransactions
            | RequestPeersIntroducer
            | RespondPeersIntroducer => Self::Bulk,

            // Default for any unclassified type
            _ => Self::Normal,
        }
    }

    /// Classify a DIG extension message type (u8) into priority.
    pub fn from_dig_type(msg_type: u8) -> Self {
        match msg_type {
            // NewAttestation, NewCheckpointProposal, NewCheckpointSignature → Critical
            200..=202 => Self::Critical,
            // Status, checkpoint sigs → Normal
            203..=206 => Self::Normal,
            // ValidatorAnnounce → Bulk
            208 => Self::Bulk,
            // Plumtree control → Normal
            214..=217 => Self::Normal,
            // Default
            _ => Self::Normal,
        }
    }
}

/// Per-connection priority outbound queue (**PRI-002**).
///
/// SPEC §8.4: "PriorityOutbound: three VecDeque (critical, normal, bulk)."
#[derive(Debug, Default)]
pub struct PriorityOutbound {
    critical: VecDeque<Message>,
    normal: VecDeque<Message>,
    bulk: VecDeque<Message>,
    /// Counter for starvation prevention (PRI-004).
    high_priority_since_last_bulk: usize,
}

impl PriorityOutbound {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue message into appropriate lane.
    pub fn enqueue(&mut self, msg: Message, priority: MessagePriority) {
        match priority {
            MessagePriority::Critical => self.critical.push_back(msg),
            MessagePriority::Normal => self.normal.push_back(msg),
            MessagePriority::Bulk => self.bulk.push_back(msg),
        }
    }

    /// Drain next message respecting priority order (**PRI-003**).
    ///
    /// SPEC §8.4: "exhaust critical → exhaust normal → one bulk → check critical again."
    /// PRI-004: "1 bulk per PRIORITY_STARVATION_RATIO critical/normal messages."
    pub fn drain_next(&mut self) -> Option<Message> {
        // PRI-004: starvation prevention — force one bulk message periodically.
        if self.high_priority_since_last_bulk >= PRIORITY_STARVATION_RATIO {
            if let Some(msg) = self.bulk.pop_front() {
                self.high_priority_since_last_bulk = 0;
                return Some(msg);
            }
        }

        // PRI-003: critical first
        if let Some(msg) = self.critical.pop_front() {
            self.high_priority_since_last_bulk += 1;
            return Some(msg);
        }

        // PRI-003: then normal
        if let Some(msg) = self.normal.pop_front() {
            self.high_priority_since_last_bulk += 1;
            return Some(msg);
        }

        // PRI-003: then one bulk
        if let Some(msg) = self.bulk.pop_front() {
            self.high_priority_since_last_bulk = 0;
            return Some(msg);
        }

        None
    }

    /// Total queued messages across all lanes.
    pub fn total_len(&self) -> usize {
        self.critical.len() + self.normal.len() + self.bulk.len()
    }

    /// Per-lane lengths.
    pub fn lane_lengths(&self) -> (usize, usize, usize) {
        (self.critical.len(), self.normal.len(), self.bulk.len())
    }

    /// Whether all lanes are empty.
    pub fn is_empty(&self) -> bool {
        self.critical.is_empty() && self.normal.is_empty() && self.bulk.is_empty()
    }
}
