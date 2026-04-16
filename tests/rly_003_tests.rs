//! Tests for **RLY-003: Relay Broadcast**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/relay/specs/RLY-003.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS7

#[cfg(feature = "relay")]
mod tests {
    use dig_gossip::relay::relay_client::RelayClient;
    use dig_gossip::relay::relay_types::RelayMessage;

    fn test_client() -> RelayClient {
        RelayClient::new("peer_a".to_string(), "net1".to_string(), 1)
    }

    /// **RLY-003: build_broadcast creates Broadcast with exclude list.**
    ///
    /// Proves SPEC SS7 (RLY-003): "broadcast to all relay peers."
    #[test]
    fn test_broadcast() {
        let client = test_client();
        let msg = client.build_broadcast(vec![4, 5], vec!["peer_c".to_string()]);

        if let RelayMessage::Broadcast {
            from,
            payload,
            exclude,
        } = msg
        {
            assert_eq!(from, "peer_a");
            assert_eq!(payload, vec![4, 5]);
            assert_eq!(exclude, vec!["peer_c".to_string()]);
        } else {
            panic!("expected Broadcast");
        }
    }
}
