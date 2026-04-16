//! Tests for **RLY-004** (auto-reconnect), **RLY-007** (NAT traversal),
//! **RLY-008** (transport selection).
//!
//! ## Requirement traceability
//!
//! - RLY-004: `docs/requirements/domains/relay/specs/RLY-004.md`
//! - RLY-007: `docs/requirements/domains/relay/specs/RLY-007.md`
//! - RLY-008: `docs/requirements/domains/relay/specs/RLY-008.md`
//! - Master SPEC §7, §7.1

#[cfg(feature = "relay")]
mod tests {
    use dig_gossip::relay::relay_service::{
        select_transport, HolePunchState, ReconnectState, TransportChoice, HOLE_PUNCH_RETRY_SECS,
    };
    use dig_gossip::RelayConfig;

    fn test_config() -> RelayConfig {
        RelayConfig {
            endpoint: "wss://relay.example.com".to_string(),
            enabled: true,
            connection_timeout_secs: 10,
            reconnect_delay_secs: 5,
            max_reconnect_attempts: 3,
            ping_interval_secs: 30,
            prefer_relay: false,
        }
    }

    // ===================== RLY-004: Auto-Reconnect =====================

    /// **RLY-004: first failure returns Some(delay).**
    ///
    /// Proves reconnect state tracks failures and provides delay.
    #[test]
    fn test_reconnect_first_failure() {
        let config = test_config();
        let mut state = ReconnectState::new(&config);

        let delay = state.record_failure(config.max_reconnect_attempts);
        assert!(delay.is_some(), "first failure should return a delay");
        assert_eq!(state.consecutive_failures, 1);
        assert!(!state.is_exhausted());
    }

    /// **RLY-004: max attempts exceeded returns None.**
    ///
    /// Proves SPEC §7: "stop after max_reconnect_attempts (default 10)."
    #[test]
    fn test_reconnect_max_exceeded() {
        let config = test_config(); // max_attempts = 3
        let mut state = ReconnectState::new(&config);

        // 3 failures = max
        for _ in 0..3 {
            state.record_failure(config.max_reconnect_attempts);
        }
        assert!(state.is_exhausted(), "must be exhausted after max attempts");

        let delay = state.record_failure(config.max_reconnect_attempts);
        assert!(delay.is_none(), "no more retries after exhaustion");
    }

    /// **RLY-004: success resets failure count.**
    #[test]
    fn test_reconnect_success_resets() {
        let config = test_config();
        let mut state = ReconnectState::new(&config);

        state.record_failure(config.max_reconnect_attempts);
        state.record_failure(config.max_reconnect_attempts);
        assert_eq!(state.consecutive_failures, 2);

        state.record_success(&config);
        assert_eq!(state.consecutive_failures, 0);
        assert!(!state.is_exhausted());
    }

    // ===================== RLY-007: NAT Traversal =====================

    /// **RLY-007: hole punch state machine transitions.**
    ///
    /// Proves SPEC §7.1: Idle → WaitingForCoordination → Connecting → Succeeded/Failed.
    #[test]
    fn test_hole_punch_success_path() {
        let mut state = HolePunchState::Idle;
        assert!(!state.is_active());

        state.request_sent();
        assert_eq!(state, HolePunchState::WaitingForCoordination);
        assert!(state.is_active());

        state.coordination_received();
        assert_eq!(state, HolePunchState::Connecting);
        assert!(state.is_active());

        state.connect_succeeded();
        assert_eq!(state, HolePunchState::Succeeded);
        assert!(!state.is_active());
    }

    /// **RLY-007: hole punch failure sets retry delay.**
    ///
    /// Proves SPEC §7.1: "failure retry after 300s."
    #[test]
    fn test_hole_punch_failure() {
        let mut state = HolePunchState::Idle;
        state.request_sent();
        state.coordination_received();
        state.connect_failed();

        assert_eq!(
            state,
            HolePunchState::Failed {
                retry_after_secs: HOLE_PUNCH_RETRY_SECS
            }
        );
        assert_eq!(HOLE_PUNCH_RETRY_SECS, 300);
        assert!(!state.is_active());
    }

    // ===================== RLY-008: Transport Selection =====================

    /// **RLY-008: prefer_relay forces Relay.**
    ///
    /// Proves SPEC §7: "prefer_relay overrides to always use relay."
    #[test]
    fn test_transport_prefer_relay() {
        let choice = select_transport(true, true, true);
        assert_eq!(choice, TransportChoice::Relay);
    }

    /// **RLY-008: direct connection preferred when available.**
    ///
    /// Proves SPEC §7: "direct P2P first."
    #[test]
    fn test_transport_direct_preferred() {
        let choice = select_transport(false, true, true);
        assert_eq!(choice, TransportChoice::Direct);
    }

    /// **RLY-008: relay used as fallback.**
    ///
    /// Proves SPEC §7: "relay fallback when direct P2P fails."
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
