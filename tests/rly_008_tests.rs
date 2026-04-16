//! Tests for **RLY-008: Transport Selection**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/relay/specs/RLY-008.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS7

#[cfg(feature = "relay")]
mod tests {
    use dig_gossip::relay::relay_service::{select_transport, TransportChoice};

    /// **RLY-008: prefer_relay forces Relay.**
    ///
    /// Proves SPEC SS7: "prefer_relay overrides to always use relay."
    #[test]
    fn test_transport_prefer_relay() {
        let choice = select_transport(true, true, true);
        assert_eq!(choice, TransportChoice::Relay);
    }

    /// **RLY-008: direct connection preferred when available.**
    ///
    /// Proves SPEC SS7: "direct P2P first."
    #[test]
    fn test_transport_direct_preferred() {
        let choice = select_transport(false, true, true);
        assert_eq!(choice, TransportChoice::Direct);
    }

    /// **RLY-008: relay used as fallback.**
    ///
    /// Proves SPEC SS7: "relay fallback when direct P2P fails."
    #[test]
    fn test_transport_relay_fallback() {
        let choice = select_transport(false, false, true);
        assert_eq!(choice, TransportChoice::Relay);
    }

    /// **RLY-008: relay default when neither available.**
    #[test]
    fn test_transport_neither_defaults_relay() {
        let choice = select_transport(false, false, false);
        assert_eq!(choice, TransportChoice::Relay);
    }

    /// **RLY-008: direct only (no relay) works.**
    #[test]
    fn test_transport_direct_only() {
        let choice = select_transport(false, true, false);
        assert_eq!(choice, TransportChoice::Direct);
    }
}
