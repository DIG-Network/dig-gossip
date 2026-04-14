//! Compact block relay types (BIP-152-style) — feature `compact-blocks`.
//!
//! **Re-export:** STR-003 when `compact-blocks` is enabled.
//! **Domain:** [`docs/requirements/domains/compact_blocks/`](../../../docs/requirements/domains/compact_blocks/).

#[derive(Debug, Clone, Default)]
pub struct CompactBlock {}

/// Truncated transaction identifier (`SHORT_TX_ID_BYTES` in [`crate::constants`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct ShortTxId(pub [u8; 6]);

#[derive(Debug, Clone, Default)]
pub struct PrefilledTransaction {}

#[derive(Debug, Clone, Default)]
pub struct RequestBlockTransactions {}

#[derive(Debug, Clone, Default)]
pub struct RespondBlockTransactions {}
