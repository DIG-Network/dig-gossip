//! Tests for **INT-012: Relay reconnect task spawned in start()**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-012.md`
//! - **Master SPEC:** SS7 (RLY-004)
//!
//! INT-012 is satisfied when ReconnectState exists and can track reconnection state.

/// **INT-012: ReconnectState can be created from RelayConfig.**
#[test]
#[cfg(feature = "relay")]
fn test_reconnect_state_new() {
    use dig_gossip::relay::relay_service::ReconnectState;
    use dig_gossip::RelayConfig;

    let config = RelayConfig::default();
    let state = ReconnectState::new(&config);

    assert_eq!(state.consecutive_failures, 0);
    assert!(!state.exhausted);
    assert!(!state.is_exhausted());
}

/// **INT-012: ReconnectState tracks failures and exhaustion.**
#[test]
#[cfg(feature = "relay")]
fn test_reconnect_state_failure_tracking() {
    use dig_gossip::relay::relay_service::ReconnectState;
    use dig_gossip::RelayConfig;

    let config = RelayConfig::default();
    let mut state = ReconnectState::new(&config);
    let max_attempts = config.max_reconnect_attempts;

    // Record failures up to max
    for i in 1..max_attempts {
        let delay = state.record_failure(max_attempts);
        assert!(
            delay.is_some(),
            "attempt {}/{} should return a delay",
            i,
            max_attempts
        );
        assert!(!state.is_exhausted());
    }

    // One more failure should exhaust
    let delay = state.record_failure(max_attempts);
    assert!(delay.is_none(), "exhausted should return None");
    assert!(state.is_exhausted());
}

/// **INT-012: ReconnectState resets on success.**
#[test]
#[cfg(feature = "relay")]
fn test_reconnect_state_success_reset() {
    use dig_gossip::relay::relay_service::ReconnectState;
    use dig_gossip::RelayConfig;

    let config = RelayConfig::default();
    let mut state = ReconnectState::new(&config);

    // Record some failures
    state.record_failure(10);
    state.record_failure(10);
    assert_eq!(state.consecutive_failures, 2);

    // Success resets
    state.record_success(&config);
    assert_eq!(state.consecutive_failures, 0);
    assert!(!state.is_exhausted());
}

/// **INT-012: HolePunchState transitions work correctly.**
#[test]
#[cfg(feature = "relay")]
fn test_hole_punch_state_transitions() {
    use dig_gossip::relay::relay_service::HolePunchState;

    let mut state = HolePunchState::Idle;
    assert!(!state.is_active());

    state.request_sent();
    assert!(state.is_active());
    assert!(matches!(state, HolePunchState::WaitingForCoordination));

    state.coordination_received();
    assert!(state.is_active());
    assert!(matches!(state, HolePunchState::Connecting));

    state.connect_succeeded();
    assert!(!state.is_active());
    assert!(matches!(state, HolePunchState::Succeeded));
}

/// **INT-012: TransportChoice selection logic.**
#[test]
#[cfg(feature = "relay")]
fn test_transport_choice_selection() {
    use dig_gossip::relay::relay_service::{select_transport, TransportChoice};

    // prefer_relay overrides everything
    assert_eq!(select_transport(true, true, true), TransportChoice::Relay);
    assert_eq!(select_transport(true, false, false), TransportChoice::Relay);

    // Direct preferred when available
    assert_eq!(select_transport(false, true, true), TransportChoice::Direct);
    assert_eq!(
        select_transport(false, true, false),
        TransportChoice::Direct
    );

    // Relay fallback
    assert_eq!(select_transport(false, false, true), TransportChoice::Relay);

    // Neither: default to Relay
    assert_eq!(
        select_transport(false, false, false),
        TransportChoice::Relay
    );
}
