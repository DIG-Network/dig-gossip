//! Compact block relay types (**CBK-001** through **CBK-006**).
//!
//! # Requirements
//!
//! - **CBK-001** — CompactBlock (header + short TX IDs + prefilled)
//! - **CBK-002** — Short TX ID = SipHash(key, tx_id)[0..6]
//! - **CBK-003** — Reconstruction from mempool
//! - **CBK-004** — RequestBlockTransactions / RespondBlockTransactions
//! - **CBK-005** — Fallback to full block on >5 missing
//! - **CBK-006** — SipHash key from block header hash
//! - **Master SPEC:** §8.2 (Compact Block Relay, inspired by Bitcoin BIP 152)
//!
//! # Feature gate
//!
//! All types gated behind `compact-blocks` feature. Uses `siphasher` crate.
//!
//! # Design
//!
//! Blocks propagated as header + 6-byte short TX IDs. Receiver reconstructs
//! from mempool using SipHash matching. Missing txs requested individually.
//! Fallback to full block via RequestBlock when >5 missing.
//! SPEC §1.8#2: "90%+ block propagation bandwidth reduction."

use dig_protocol::Bytes32;

use crate::constants::{COMPACT_BLOCK_MAX_MISSING_TXS, SHORT_TX_ID_BYTES};

/// 6-byte truncated SipHash of a transaction ID (**CBK-002**).
///
/// SPEC §8.2: "short_tx_id = SipHash(sip_hash_key, tx_id)[0..6]."
/// Collision probability ~1 in 2^48 per transaction pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShortTxId(pub [u8; SHORT_TX_ID_BYTES]);

impl ShortTxId {
    /// Compute short TX ID from full tx_id and SipHash key (**CBK-002**).
    ///
    /// SPEC §8.2: "SipHash(sip_hash_key, tx_id)[0..6]."
    #[cfg(feature = "compact-blocks")]
    pub fn compute(sip_hash_key: &[u8; 16], tx_id: &Bytes32) -> Self {
        use siphasher::sip::SipHasher;
        use std::hash::{Hash, Hasher};

        let k0 = u64::from_le_bytes(sip_hash_key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(sip_hash_key[8..16].try_into().unwrap());
        let mut hasher = SipHasher::new_with_keys(k0, k1);
        tx_id.as_ref().hash(&mut hasher);
        let full_hash = hasher.finish().to_le_bytes();

        let mut short = [0u8; SHORT_TX_ID_BYTES];
        short.copy_from_slice(&full_hash[..SHORT_TX_ID_BYTES]);
        Self(short)
    }
}

/// Transaction included directly in compact block (**CBK-001**).
///
/// SPEC §8.2: "prefilled transactions the sender predicts the receiver doesn't have
/// (e.g., coinbase, very recent transactions)."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefilledTransaction {
    /// Index in block's transaction list.
    pub index: u16,
    /// Full serialized transaction bytes.
    pub tx: Vec<u8>,
}

/// Compact block representation (**CBK-001**).
///
/// SPEC §8.2: "CompactBlock: header + short_tx_ids + prefilled_txs + sip_hash_key."
/// Reduces block propagation bandwidth by 90%+.
#[derive(Debug, Clone)]
pub struct CompactBlock {
    /// Block header hash (identifies the block).
    pub header_hash: Bytes32,
    /// Block height.
    pub height: u32,
    /// Short transaction IDs (6 bytes each).
    pub short_tx_ids: Vec<ShortTxId>,
    /// Transactions included directly (coinbase + recent).
    pub prefilled_txs: Vec<PrefilledTransaction>,
    /// SipHash key derived from header hash (**CBK-006**).
    pub sip_hash_key: [u8; 16],
}

impl CompactBlock {
    /// Derive SipHash key from block header hash (**CBK-006**).
    ///
    /// SPEC §8.2: "SipHash key MUST be derived deterministically from block header hash."
    /// Uses first 16 bytes of the header hash.
    pub fn derive_sip_hash_key(header_hash: &Bytes32) -> [u8; 16] {
        let mut key = [0u8; 16];
        key.copy_from_slice(&header_hash.as_ref()[..16]);
        key
    }
}

/// Request missing transactions after compact block reconstruction (**CBK-004**).
///
/// SPEC §8.2: "Send RequestBlockTransactions { block_hash, missing_indices }."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBlockTransactions {
    /// Block being reconstructed.
    pub block_hash: Bytes32,
    /// Indices of transactions missing from mempool reconstruction.
    pub missing_indices: Vec<u16>,
}

/// Response with missing transactions (**CBK-004**).
///
/// SPEC §8.2: "Receive RespondBlockTransactions { transactions }."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespondBlockTransactions {
    /// Block hash (for correlation).
    pub block_hash: Bytes32,
    /// Full serialized transactions at the requested indices.
    pub transactions: Vec<Vec<u8>>,
}

/// Result of compact block reconstruction (**CBK-003/CBK-005**).
///
/// SPEC §8.2: "If >5 missing, fall back to full block via RequestBlock."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconstructionResult {
    /// All transactions matched from mempool + prefilled. Block complete.
    Complete,
    /// Some transactions missing. Request them individually (CBK-004).
    RequestMissing { missing_indices: Vec<u16> },
    /// Too many missing (> COMPACT_BLOCK_MAX_MISSING_TXS). Fall back to full block (CBK-005).
    FallbackToFullBlock { missing_count: usize },
}

/// Determine reconstruction result from missing count (**CBK-003/CBK-005**).
///
/// SPEC §8.2: "If >5 missing transactions, fall back to full block."
pub fn classify_reconstruction(missing_indices: Vec<u16>) -> ReconstructionResult {
    if missing_indices.is_empty() {
        ReconstructionResult::Complete
    } else if missing_indices.len() <= COMPACT_BLOCK_MAX_MISSING_TXS {
        ReconstructionResult::RequestMissing { missing_indices }
    } else {
        ReconstructionResult::FallbackToFullBlock {
            missing_count: missing_indices.len(),
        }
    }
}
