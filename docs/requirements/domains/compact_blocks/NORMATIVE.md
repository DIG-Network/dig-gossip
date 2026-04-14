# Compact Blocks - Normative Requirements

> **Domain:** compact_blocks
> **Prefix:** CBK
> **Spec reference:** [SPEC.md - Section 8.2](../../resources/SPEC.md)

## Requirements

### CBK-001: CompactBlock Struct

CompactBlock MUST contain header(BlockHeader), short_tx_ids(Vec<ShortTxId>), prefilled_txs(Vec<PrefilledTransaction>), sip_hash_key([u8;16]). PrefilledTransaction MUST contain index(u16) and tx(Vec<u8>). Prefilled transactions MUST include the coinbase transaction and any transactions added within the last 2 seconds. **Note:** `BlockHeader` is imported from the `dig-block` crate (the DIG L2 block model crate). It is NOT a Chia type and is NOT defined in this crate.

**Spec reference:** SPEC Section 8.2 (Compact Block Relay)

### CBK-002: ShortTxId Computation

ShortTxId MUST be computed as SipHash(sip_hash_key, tx_id)[0..6], producing a 6-byte truncated SipHash. The implementation MUST use the siphasher crate. Collision probability is ~1 in 2^48 per transaction pair.

**Spec reference:** SPEC Section 8.2 (Short ID computation)

### CBK-003: Block Reconstruction from Mempool

Receiver MUST compute SipHash of each mempool transaction using the CompactBlock's sip_hash_key, match results against short_tx_ids, and reconstruct the full block from the block header, matched mempool transactions, and prefilled transactions.

**Spec reference:** SPEC Section 8.2 (Compact block relay protocol, Receiver steps 1-3)

### CBK-004: Missing Transaction Request

When short_tx_ids remain unmatched after mempool reconstruction, receiver MUST send RequestBlockTransactions { block_hash, missing_indices } and receive RespondBlockTransactions { transactions } to obtain the missing transactions and complete block reconstruction.

**Spec reference:** SPEC Section 8.2 (Compact block relay protocol, Receiver step 4)

### CBK-005: Fallback to Full Block

When more than COMPACT_BLOCK_MAX_MISSING_TXS (5) transactions are missing after mempool reconstruction, the receiver MUST fall back to requesting the full block via RequestBlock/RespondBlock instead of requesting individual missing transactions.

**Spec reference:** SPEC Section 8.2 (Fallback)

### CBK-006: Deterministic SipHash Key Derivation

The sip_hash_key MUST be derived deterministically from the block header hash. The same block MUST always produce the same CompactBlock. This prevents precomputed collision attacks on short transaction IDs.

**Spec reference:** SPEC Section 8.2 (Short ID computation)
