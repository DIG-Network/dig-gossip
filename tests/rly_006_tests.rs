//! Tests for **RLY-006: Relay Keepalive**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/relay/specs/RLY-006.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS7

#[cfg(feature = "relay")]
mod tests {
    use dig_gossip::relay::relay_client::RelayClient;
    use dig_gossip::relay::relay_types::RelayMessage;

    fn test_client() -> RelayClient {
        RelayClient::new("peer_a".to_string(), "net1".to_string(), 1)
    }

    /// **RLY-006: build_ping creates Ping with timestamp.**
    #[test]
    fn test_build_ping() {
        let client = test_client();
        let msg = client.build_ping();
        if let RelayMessage::Ping { timestamp } = msg {
            assert!(timestamp > 0, "ping timestamp must be positive");
        } else {
            panic!("expected Ping");
        }
    }
}
