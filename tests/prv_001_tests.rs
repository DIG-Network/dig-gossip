//! **PRV-001 — DandelionConfig defaults**
//!
//! Normative: [`docs/requirements/domains/privacy/specs/PRV-001.md`](../docs/requirements/domains/privacy/specs/PRV-001.md)
//! Master SPEC: [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 1.9.1 (Dandelion++)
//!
//! ## What this file proves
//!
//! The `DandelionConfig` struct has the SPEC-mandated default values:
//! `enabled = true`, `fluff_probability = 0.10`, `stem_timeout_secs = 30`,
//! `epoch_secs = 600`. These constants drive the Dandelion++ privacy protocol
//! and must match the SPEC exactly so interoperability with other DIG nodes is
//! maintained.

#[cfg(feature = "dandelion")]
mod tests {
    use dig_gossip::privacy::dandelion::DandelionConfig;

    /// SPEC §1.9.1 default: `enabled = true`.
    ///
    /// Dandelion++ is on by default so transaction origin privacy is active
    /// without explicit opt-in.
    #[test]
    fn test_dandelion_config_enabled_default() {
        let cfg = DandelionConfig::default();
        assert!(cfg.enabled, "DandelionConfig default must be enabled=true");
    }

    /// SPEC §1.9.1 default: `DANDELION_FLUFF_PROBABILITY = 0.10` (10%).
    ///
    /// Each stem hop flips a weighted coin; 10% chance triggers fluff transition.
    /// Deviating from 0.10 would change the expected stem path length distribution.
    #[test]
    fn test_dandelion_config_fluff_probability_default() {
        let cfg = DandelionConfig::default();
        assert!(
            (cfg.fluff_probability - 0.10).abs() < f64::EPSILON,
            "fluff_probability default must be 0.10, got {}",
            cfg.fluff_probability
        );
    }

    /// SPEC §1.9.1 default: `DANDELION_STEM_TIMEOUT_SECS = 30`.
    ///
    /// A stem transaction that has not been seen via fluff within 30 seconds is
    /// force-fluffed. This ensures liveness if the stem path breaks.
    #[test]
    fn test_dandelion_config_stem_timeout_default() {
        let cfg = DandelionConfig::default();
        assert_eq!(
            cfg.stem_timeout_secs, 30,
            "stem_timeout_secs default must be 30"
        );
    }

    /// SPEC §1.9.1 default: `DANDELION_EPOCH_SECS = 600`.
    ///
    /// The stem relay is re-randomized every 600 seconds (10 minutes) to prevent
    /// per-transaction fingerprinting while keeping stem paths stable within an epoch.
    #[test]
    fn test_dandelion_config_epoch_secs_default() {
        let cfg = DandelionConfig::default();
        assert_eq!(cfg.epoch_secs, 600, "epoch_secs default must be 600");
    }

    /// All four defaults in a single assertion for regression coverage.
    #[test]
    fn test_dandelion_config_all_defaults() {
        let cfg = DandelionConfig::default();
        assert!(cfg.enabled);
        assert!((cfg.fluff_probability - 0.10).abs() < f64::EPSILON);
        assert_eq!(cfg.stem_timeout_secs, 30);
        assert_eq!(cfg.epoch_secs, 600);
    }

    /// DandelionConfig can be constructed with custom values.
    #[test]
    fn test_dandelion_config_custom_values() {
        let cfg = DandelionConfig {
            enabled: false,
            fluff_probability: 0.25,
            stem_timeout_secs: 60,
            epoch_secs: 300,
        };
        assert!(!cfg.enabled);
        assert!((cfg.fluff_probability - 0.25).abs() < f64::EPSILON);
        assert_eq!(cfg.stem_timeout_secs, 60);
        assert_eq!(cfg.epoch_secs, 300);
    }

    /// DandelionConfig implements Clone and the clone is equal to the original.
    #[test]
    fn test_dandelion_config_clone_eq() {
        let cfg = DandelionConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cfg, cloned);
    }
}
