//! **PRV-009 — TorConfig defaults**
//!
//! Normative: [`docs/requirements/domains/privacy/specs/PRV-009.md`](../docs/requirements/domains/privacy/specs/PRV-009.md)
//! Master SPEC: [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 1.9.3 (Tor/SOCKS5 Proxy Transport)
//!
//! ## What this file proves
//!
//! The `TorConfig` struct has SPEC-mandated defaults and its helper methods
//! (`is_active`, `has_onion_address`, `is_hybrid`) produce correct results
//! for the default configuration and various custom configurations.

#[cfg(feature = "tor")]
mod tests {
    use dig_gossip::privacy::tor::TorConfig;

    /// SPEC §1.9.3 default: `enabled = false`.
    ///
    /// Tor is opt-in only (not in default features). A default config must
    /// not attempt Tor connections.
    #[test]
    fn test_tor_config_enabled_default() {
        let cfg = TorConfig::default();
        assert!(!cfg.enabled, "TorConfig default must be enabled=false");
    }

    /// SPEC §1.9.3 default: `socks5_proxy = "127.0.0.1:9050"`.
    ///
    /// The standard Tor SOCKS5 proxy address. Custom deployments may change
    /// this but the default must match the conventional Tor daemon address.
    #[test]
    fn test_tor_config_socks5_proxy_default() {
        let cfg = TorConfig::default();
        assert_eq!(
            cfg.socks5_proxy, "127.0.0.1:9050",
            "socks5_proxy default must be 127.0.0.1:9050"
        );
    }

    /// SPEC §1.9.3 default: `onion_address = None`.
    ///
    /// No hidden service address by default — the node is outbound-only
    /// until an operator configures a .onion address.
    #[test]
    fn test_tor_config_onion_address_default() {
        let cfg = TorConfig::default();
        assert!(
            cfg.onion_address.is_none(),
            "onion_address default must be None"
        );
    }

    /// SPEC §1.9.3 default: `prefer_tor = false`.
    ///
    /// Direct P2P connections are preferred; Tor is used as a last resort
    /// or when connecting to .onion addresses.
    #[test]
    fn test_tor_config_prefer_tor_default() {
        let cfg = TorConfig::default();
        assert!(!cfg.prefer_tor, "prefer_tor default must be false");
    }

    /// `is_active()` returns `false` for the default config.
    ///
    /// The default config has `enabled = false`, so Tor transport is not active.
    #[test]
    fn test_tor_config_is_active_default() {
        let cfg = TorConfig::default();
        assert!(
            !cfg.is_active(),
            "is_active() must return false for default (disabled) config"
        );
    }

    /// `is_active()` returns `true` when enabled.
    #[test]
    fn test_tor_config_is_active_when_enabled() {
        let cfg = TorConfig {
            enabled: true,
            ..TorConfig::default()
        };
        assert!(
            cfg.is_active(),
            "is_active() must return true when enabled=true"
        );
    }

    /// `has_onion_address()` returns `false` for the default config.
    #[test]
    fn test_tor_config_has_onion_address_default() {
        let cfg = TorConfig::default();
        assert!(
            !cfg.has_onion_address(),
            "has_onion_address() must return false when onion_address is None"
        );
    }

    /// `has_onion_address()` returns `true` when an onion address is set.
    #[test]
    fn test_tor_config_has_onion_address_when_set() {
        let cfg = TorConfig {
            onion_address: Some("abcdefghijklmnop.onion".to_string()),
            ..TorConfig::default()
        };
        assert!(
            cfg.has_onion_address(),
            "has_onion_address() must return true when onion_address is Some"
        );
    }

    /// `is_hybrid()` returns `false` for the default config.
    ///
    /// Hybrid mode requires: enabled + onion_address + prefer_tor=false.
    /// Default config has enabled=false, so it cannot be hybrid.
    #[test]
    fn test_tor_config_is_hybrid_default() {
        let cfg = TorConfig::default();
        assert!(
            !cfg.is_hybrid(),
            "is_hybrid() must return false for default config"
        );
    }

    /// `is_hybrid()` returns `true` when enabled with an onion address and
    /// `prefer_tor = false`.
    ///
    /// SPEC §1.9.3: "accept both direct P2P and Tor connections simultaneously."
    #[test]
    fn test_tor_config_is_hybrid_when_configured() {
        let cfg = TorConfig {
            enabled: true,
            socks5_proxy: "127.0.0.1:9050".to_string(),
            onion_address: Some("abcdefghijklmnop.onion".to_string()),
            prefer_tor: false,
        };
        assert!(
            cfg.is_hybrid(),
            "is_hybrid() must return true with enabled + onion + prefer_tor=false"
        );
    }

    /// `is_hybrid()` returns `false` when `prefer_tor = true` even with an
    /// onion address.
    ///
    /// When prefer_tor is true, the node routes all traffic through Tor — that
    /// is Tor-only mode, not hybrid mode.
    #[test]
    fn test_tor_config_not_hybrid_when_prefer_tor() {
        let cfg = TorConfig {
            enabled: true,
            socks5_proxy: "127.0.0.1:9050".to_string(),
            onion_address: Some("abcdefghijklmnop.onion".to_string()),
            prefer_tor: true,
        };
        assert!(
            !cfg.is_hybrid(),
            "is_hybrid() must return false when prefer_tor=true"
        );
    }

    /// TorConfig implements Clone and the clone is equal to the original.
    #[test]
    fn test_tor_config_clone_eq() {
        let cfg = TorConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cfg, cloned);
    }
}
