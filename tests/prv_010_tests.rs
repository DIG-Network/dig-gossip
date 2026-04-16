//! **PRV-010 — Tor transport selection (`select_with_tor`)**
//!
//! Normative: [`docs/requirements/domains/privacy/specs/PRV-010.md`](../docs/requirements/domains/privacy/specs/PRV-010.md)
//! Master SPEC: [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 1.9.3 (Tor/SOCKS5 Proxy Transport)
//!
//! ## What this file proves
//!
//! `select_with_tor` implements SPEC §1.9.3 transport selection rules:
//! - `prefer_tor = true` forces Tor transport.
//! - `.onion` addresses always use Tor transport regardless of `prefer_tor`.
//! - Direct P2P is preferred when `prefer_tor = false`, `has_direct = true`,
//!   and the target is not a `.onion` address.
//! - When no direct path exists and `prefer_tor = false`, Tor is used as a
//!   last resort.

#[cfg(feature = "tor")]
mod tests {
    use dig_gossip::privacy::tor::{select_with_tor, TorTransportChoice};

    /// `prefer_tor = true` forces Tor transport for non-.onion addresses.
    ///
    /// SPEC §1.9.3: "prefer_tor=true -> all outbound via Tor."
    #[test]
    fn test_prefer_tor_forces_tor() {
        let choice = select_with_tor(
            true,  // prefer_tor
            false, // is_onion_address
            true,  // has_direct
        );
        assert_eq!(
            choice,
            TorTransportChoice::Tor,
            "prefer_tor=true must select Tor even when direct is available"
        );
    }

    /// `.onion` addresses always use Tor regardless of `prefer_tor` setting.
    ///
    /// SPEC §1.9.3: ".onion addresses always via Tor."
    #[test]
    fn test_onion_address_always_tor() {
        // prefer_tor = false, but target is .onion
        let choice = select_with_tor(false, true, true);
        assert_eq!(
            choice,
            TorTransportChoice::Tor,
            ".onion address must always select Tor"
        );
    }

    /// `.onion` with `prefer_tor = true` also uses Tor (consistent).
    #[test]
    fn test_onion_address_with_prefer_tor() {
        let choice = select_with_tor(true, true, true);
        assert_eq!(
            choice,
            TorTransportChoice::Tor,
            ".onion + prefer_tor must select Tor"
        );
    }

    /// `.onion` without direct path also uses Tor.
    #[test]
    fn test_onion_address_no_direct() {
        let choice = select_with_tor(false, true, false);
        assert_eq!(
            choice,
            TorTransportChoice::Tor,
            ".onion without direct must select Tor"
        );
    }

    /// Direct P2P is preferred when `prefer_tor = false` and `has_direct = true`
    /// for non-.onion targets.
    ///
    /// SPEC §1.9.3: "prefer_tor=false -> direct first -> Tor as last resort."
    #[test]
    fn test_direct_preferred_over_tor() {
        let choice = select_with_tor(false, false, true);
        assert_eq!(
            choice,
            TorTransportChoice::Direct,
            "non-.onion with prefer_tor=false and has_direct=true must select Direct"
        );
    }

    /// When no direct path and `prefer_tor = false`, Tor is the last resort.
    ///
    /// SPEC §1.9.3: "prefer_tor=false -> direct first -> Tor as last resort."
    #[test]
    fn test_tor_as_last_resort() {
        let choice = select_with_tor(false, false, false);
        assert_eq!(
            choice,
            TorTransportChoice::Tor,
            "no direct path and prefer_tor=false must fall back to Tor"
        );
    }

    /// `prefer_tor = true` without direct path uses Tor.
    #[test]
    fn test_prefer_tor_no_direct() {
        let choice = select_with_tor(true, false, false);
        assert_eq!(
            choice,
            TorTransportChoice::Tor,
            "prefer_tor=true without direct must select Tor"
        );
    }

    /// TorTransportChoice::Direct and TorTransportChoice::Tor are distinct.
    ///
    /// Sanity check: the enum variants do not collapse to the same value.
    #[test]
    fn test_transport_choice_variants_distinct() {
        assert_ne!(
            TorTransportChoice::Direct,
            TorTransportChoice::Tor,
            "Direct and Tor must be distinct enum variants"
        );
    }
}
