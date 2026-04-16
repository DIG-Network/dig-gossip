//! **PRV-003 — Fluff transition (`should_fluff`)**
//!
//! Normative: [`docs/requirements/domains/privacy/specs/PRV-003.md`](../docs/requirements/domains/privacy/specs/PRV-003.md)
//! Master SPEC: [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 1.9.1 (Dandelion++)
//!
//! ## What this file proves
//!
//! The `should_fluff` function implements the weighted coin flip at each stem hop.
//! - With probability 0.0 the result is always "stem" (never fluff).
//! - With probability 1.0 the result is always "fluff".
//! - With the default probability 0.10, approximately 10% of 1000 trials should fluff.

#[cfg(feature = "dandelion")]
mod tests {
    use dig_gossip::privacy::dandelion::should_fluff;

    /// Probability 0.0 means the coin never lands on fluff.
    ///
    /// Proves the stem path continues indefinitely (until timeout) when the
    /// fluff probability is set to zero — useful for testing stem-only paths.
    #[test]
    fn test_should_fluff_zero_always_stem() {
        for _ in 0..1000 {
            assert!(
                !should_fluff(0.0),
                "fluff_probability=0.0 must never return true"
            );
        }
    }

    /// Probability 1.0 means every hop transitions to fluff immediately.
    ///
    /// Proves that a fluff_probability of 1.0 causes immediate broadcast —
    /// the stem phase is effectively skipped.
    #[test]
    fn test_should_fluff_one_always_fluff() {
        for _ in 0..1000 {
            assert!(
                should_fluff(1.0),
                "fluff_probability=1.0 must always return true"
            );
        }
    }

    /// Statistical test: with the SPEC default of 0.10, approximately 10% of
    /// 1000 trials should return `true` (fluff).
    ///
    /// We allow a tolerance of +/- 50 (5-15%) to avoid flaky CI while still
    /// catching gross errors like always-stem or always-fluff.
    #[test]
    fn test_should_fluff_statistical_default_probability() {
        let trials = 1000;
        let fluff_count: usize = (0..trials).filter(|_| should_fluff(0.10)).count();
        assert!(
            (50..=150).contains(&fluff_count),
            "expected ~100 fluffs in {trials} trials with p=0.10, got {fluff_count}"
        );
    }

    /// Probability 0.50 should fluff roughly half the time.
    ///
    /// Secondary statistical check to confirm the coin flip scales linearly
    /// with the provided probability.
    #[test]
    fn test_should_fluff_fifty_percent() {
        let trials = 1000;
        let fluff_count: usize = (0..trials).filter(|_| should_fluff(0.50)).count();
        assert!(
            (400..=600).contains(&fluff_count),
            "expected ~500 fluffs in {trials} trials with p=0.50, got {fluff_count}"
        );
    }
}
