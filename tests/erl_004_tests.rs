//! Tests for **ERL-004: Periodic Set Reconciliation**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/erlay/specs/ERL-004.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.3
//!
//! Placeholder: reconciliation interval is tested via constants in ERL-008.

#[cfg(feature = "erlay")]
mod tests {
    use dig_gossip::ERLAY_RECONCILIATION_INTERVAL_MS;

    /// **ERL-004: reconciliation interval constant matches SPEC.**
    #[test]
    fn test_reconciliation_interval() {
        assert_eq!(ERLAY_RECONCILIATION_INTERVAL_MS, 2000);
    }
}
