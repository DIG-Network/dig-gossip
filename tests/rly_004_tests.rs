//! Tests for **RLY-004: Auto-Reconnect on Disconnect**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/relay/specs/RLY-004.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS7

#[cfg(feature = "relay")]
mod tests {
    use dig_gossip::relay::relay_client::RelayClient;
    use dig_gossip::relay::relay_service::ReconnectState;
    use dig_gossip::relay::relay_types::RelayPeerInfo;
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

    fn test_client() -> RelayClient {
        RelayClient::new("peer_a".to_string(), "net1".to_string(), 1)
    }

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
    /// Proves SPEC SS7: "stop after max_reconnect_attempts (default 10)."
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

    /// **RLY-004: reset clears registered state but keeps seq numbers.**
    #[test]
    fn test_reset() {
        let mut client = test_client();
        client.handle_register_ack(true, "ok", 0).unwrap();
        client.build_send_to_peer("peer_b", vec![1]);
        let peer = RelayPeerInfo {
            peer_id: "p1".into(),
            network_id: "n1".into(),
            protocol_version: 1,
            connected_at: 100,
            last_seen: 200,
        };
        client.handle_peer_connected(peer);

        client.reset();

        assert!(!client.is_registered(), "reset clears registered");
        assert_eq!(client.peer_count(), 0, "reset clears known peers");
        assert_eq!(
            client.seq_for_target("peer_b"),
            1,
            "seq NOT reset -- monotonic across reconnects"
        );
    }
}
