//! **PRV-002 — StemTransaction struct**
//!
//! Normative: [`docs/requirements/domains/privacy/specs/PRV-002.md`](../docs/requirements/domains/privacy/specs/PRV-002.md)
//! Master SPEC: [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 1.9.1 (Dandelion++)
//!
//! ## What this file proves
//!
//! `StemTransaction::new` creates a transaction in the stem phase with a timestamp
//! capturing "now" and the payload stored correctly. Stem-phase transactions are
//! forwarded to exactly one relay peer and MUST NOT be added to the local mempool
//! (SPEC §1.9.1).

#[cfg(feature = "dandelion")]
mod tests {
    use dig_gossip::privacy::dandelion::StemTransaction;
    use dig_gossip::{metric_unix_timestamp_secs, Bytes32};

    /// `StemTransaction::new` stores the provided `tx_id` verbatim.
    ///
    /// Proves the transaction hash carried through the stem phase is not
    /// modified or rehashed during construction.
    #[test]
    fn test_stem_transaction_stores_tx_id() {
        let tx_id = Bytes32::from([0xAB; 32]);
        let payload = vec![1, 2, 3, 4];
        let stx = StemTransaction::new(tx_id, payload.clone());
        assert_eq!(stx.tx_id, tx_id, "tx_id must be stored as-is");
    }

    /// `StemTransaction::new` stores the provided payload verbatim.
    ///
    /// The serialized transaction bytes must be recoverable for forwarding
    /// to the stem relay peer.
    #[test]
    fn test_stem_transaction_stores_payload() {
        let tx_id = Bytes32::from([0xCD; 32]);
        let payload = vec![10, 20, 30, 40, 50];
        let stx = StemTransaction::new(tx_id, payload.clone());
        assert_eq!(stx.payload, payload, "payload must be stored as-is");
    }

    /// `StemTransaction::new` records a timestamp close to "now".
    ///
    /// The `stem_started_at` field drives the stem timeout (PRV-004).
    /// We assert it is within 2 seconds of the current wall clock to prove
    /// it captures the construction time rather than a fixed or zero value.
    #[test]
    fn test_stem_transaction_has_timestamp() {
        let before = metric_unix_timestamp_secs();
        let stx = StemTransaction::new(Bytes32::default(), vec![]);
        let after = metric_unix_timestamp_secs();
        assert!(
            stx.stem_started_at >= before && stx.stem_started_at <= after,
            "stem_started_at ({}) must be between before ({}) and after ({})",
            stx.stem_started_at,
            before,
            after
        );
    }

    /// `StemTransaction::new` works with an empty payload.
    ///
    /// Edge case: a valid stem transaction can carry zero bytes of payload
    /// (the id alone is sufficient for forwarding decisions).
    #[test]
    fn test_stem_transaction_empty_payload() {
        let stx = StemTransaction::new(Bytes32::default(), vec![]);
        assert!(stx.payload.is_empty());
    }

    /// `StemTransaction` can be cloned and the clone matches the original.
    #[test]
    fn test_stem_transaction_clone() {
        let stx = StemTransaction::new(Bytes32::from([0xFF; 32]), vec![99; 100]);
        let cloned = stx.clone();
        assert_eq!(cloned.tx_id, stx.tx_id);
        assert_eq!(cloned.payload, stx.payload);
        assert_eq!(cloned.stem_started_at, stx.stem_started_at);
    }
}
