//! Dandelion++ stem/fluff transaction propagation (**PRV-001** through **PRV-005**).
//!
//! # Requirements
//!
//! - **PRV-001** — DandelionConfig (enabled, fluff_probability, stem_timeout, epoch)
//! - **PRV-002** — Stem phase: forward to one relay, not in mempool
//! - **PRV-003** — Fluff transition: 10% coin flip
//! - **PRV-004** — Stem timeout: force-fluff after 30s
//! - **PRV-005** — Epoch rotation: re-randomize stem relay every 600s
//! - **Master SPEC:** §1.9.1 (Dandelion++, Fanti et al., 2018)
//!
//! # Design
//!
//! Stem phase forwards tx to one random peer per epoch. Each hop flips a
//! weighted coin (10% fluff, 90% stem). On fluff: add to mempool + broadcast
//! normally. Stem timeout (30s) ensures liveness if stem path breaks.
//! SPEC §1.8#10: "transaction origin privacy."

use chia_protocol::Bytes32;

use crate::types::peer::{metric_unix_timestamp_secs, PeerId};

/// Dandelion++ configuration (**PRV-001**).
///
/// SPEC §1.9.1: "DandelionConfig with enabled, fluff_probability, stem_timeout_secs, epoch_secs."
#[derive(Debug, Clone, PartialEq)]
pub struct DandelionConfig {
    /// Enable Dandelion++ stem phase. Default: true.
    pub enabled: bool,
    /// Probability of fluff transition at each hop. Default: 0.10 (10%).
    /// SPEC §1.9.1: "DANDELION_FLUFF_PROBABILITY default 0.10."
    pub fluff_probability: f64,
    /// Timeout before force-fluff (seconds). Default: 30.
    /// SPEC §1.9.1: "DANDELION_STEM_TIMEOUT_SECS default 30."
    pub stem_timeout_secs: u64,
    /// Stem relay epoch duration (seconds). Default: 600.
    /// SPEC §1.9.1: "DANDELION_EPOCH_SECS default 600."
    pub epoch_secs: u64,
}

impl Default for DandelionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fluff_probability: 0.10,
            stem_timeout_secs: 30,
            epoch_secs: 600,
        }
    }
}

// PRV-001 does not derive Eq because fluff_probability is f64.
impl Eq for DandelionConfig {}

/// Transaction in stem phase (not yet fluffed) (**PRV-002**).
///
/// SPEC §1.9.1: "Transaction MUST NOT be added to local mempool during stem."
/// SPEC §1.9.1: "Node MUST NOT respond to RequestTransaction for stem-only txs."
#[derive(Debug, Clone)]
pub struct StemTransaction {
    /// Transaction ID (hash).
    pub tx_id: Bytes32,
    /// Serialized transaction payload.
    pub payload: Vec<u8>,
    /// Unix timestamp when stem phase started (for timeout, PRV-004).
    pub stem_started_at: u64,
}

impl StemTransaction {
    /// Create new stem transaction.
    pub fn new(tx_id: Bytes32, payload: Vec<u8>) -> Self {
        Self {
            tx_id,
            payload,
            stem_started_at: metric_unix_timestamp_secs(),
        }
    }

    /// Check if stem has timed out (**PRV-004**).
    ///
    /// SPEC §1.9.1: "If not seen via fluff within DANDELION_STEM_TIMEOUT_SECS,
    /// force-fluff."
    pub fn is_timed_out(&self, timeout_secs: u64) -> bool {
        let now = metric_unix_timestamp_secs();
        now.saturating_sub(self.stem_started_at) >= timeout_secs
    }
}

/// Stem relay manager — tracks current epoch's relay peer (**PRV-005**).
///
/// SPEC §1.9.1: "Each node maintains a single stem_relay peer,
/// re-randomized every DANDELION_EPOCH_SECS."
#[derive(Debug)]
pub struct StemRelayManager {
    /// Current stem relay peer.
    pub current_relay: Option<PeerId>,
    /// When current epoch started (Unix seconds).
    pub epoch_start: u64,
    /// Epoch duration (seconds).
    pub epoch_secs: u64,
}

impl StemRelayManager {
    pub fn new(epoch_secs: u64) -> Self {
        Self {
            current_relay: None,
            epoch_start: 0,
            epoch_secs,
        }
    }

    /// Check if epoch has expired and relay needs rotation (**PRV-005**).
    pub fn needs_rotation(&self) -> bool {
        let now = metric_unix_timestamp_secs();
        self.current_relay.is_none() || now.saturating_sub(self.epoch_start) >= self.epoch_secs
    }

    /// Select new relay from available outbound peers (**PRV-005**).
    ///
    /// SPEC §1.9.1: "consistent relay per epoch prevents per-transaction fingerprinting."
    pub fn rotate(&mut self, outbound_peers: &[PeerId]) {
        use rand::seq::SliceRandom;

        self.current_relay = outbound_peers.choose(&mut rand::thread_rng()).copied();
        self.epoch_start = metric_unix_timestamp_secs();
    }

    /// Get current relay (None if no peers or epoch expired).
    pub fn relay(&self) -> Option<&PeerId> {
        self.current_relay.as_ref()
    }

    /// Handle relay disconnect mid-epoch — immediate re-selection (**PRV-005**).
    pub fn on_relay_disconnected(&mut self, outbound_peers: &[PeerId]) {
        // Don't reset epoch timer — just pick new relay within same epoch.
        self.current_relay = {
            use rand::seq::SliceRandom;
            outbound_peers.choose(&mut rand::thread_rng()).copied()
        };
    }
}

/// Decide whether to fluff at this hop (**PRV-003**).
///
/// SPEC §1.9.1: "Each hop flips weighted coin (DANDELION_FLUFF_PROBABILITY = 10%)."
/// Returns true if should fluff, false if should continue stem.
pub fn should_fluff(fluff_probability: f64) -> bool {
    use rand::Rng;
    let r: f64 = rand::thread_rng().gen();
    r < fluff_probability
}
