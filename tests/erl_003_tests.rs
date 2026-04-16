//! Tests for **ERL-003: Minisketch Encode/Decode for tx_id Sets**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/erlay/specs/ERL-003.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.3

#[cfg(feature = "erlay")]
mod tests {
    use dig_gossip::gossip::erlay::ReconciliationSketch;
    use dig_gossip::{Bytes32, ERLAY_SKETCH_CAPACITY};

    fn test_tx_id(n: u8) -> Bytes32 {
        let mut b = [0u8; 32];
        b[31] = n;
        Bytes32::from(b)
    }

    /// **ERL-003: ReconciliationSketch adds elements.**
    #[test]
    fn test_sketch_add() {
        let mut sketch = ReconciliationSketch::with_default_capacity();
        assert!(sketch.is_empty());

        sketch.add(&test_tx_id(1));
        sketch.add(&test_tx_id(2));
        assert_eq!(sketch.len(), 2);
        assert_eq!(sketch.capacity, ERLAY_SKETCH_CAPACITY);
    }
}
