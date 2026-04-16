//! Tests for **RLY-002: Relay Message Forwarding**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/relay/specs/RLY-002.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS7

#[cfg(feature = "relay")]
mod tests {
    use dig_gossip::relay::relay_client::RelayClient;
    use dig_gossip::relay::relay_types::RelayMessage;

    fn test_client() -> RelayClient {
        RelayClient::new("peer_a".to_string(), "net1".to_string(), 1)
    }

    /// **RLY-002: build_send_to_peer creates RelayGossipMessage with correct fields.**
    ///
    /// Proves SPEC SS7 (RLY-002): "forward message to specific peer."
    #[test]
    fn test_send_to_peer() {
        let mut client = test_client();
        let msg = client.build_send_to_peer("peer_b", vec![1, 2, 3]);

        if let RelayMessage::RelayGossipMessage {
            from,
            to,
            payload,
            seq,
        } = msg
        {
            assert_eq!(from, "peer_a");
            assert_eq!(to, "peer_b");
            assert_eq!(payload, vec![1, 2, 3]);
            assert_eq!(seq, 1, "first message seq must be 1");
        } else {
            panic!("expected RelayGossipMessage");
        }
    }

    /// **RLY-002: sequence numbers are monotonically increasing per target.**
    ///
    /// Proves SPEC SS7: "monotonically increasing seq per sender-receiver pair."
    #[test]
    fn test_seq_monotonic_per_target() {
        let mut client = test_client();

        // Two messages to peer_b
        client.build_send_to_peer("peer_b", vec![1]);
        let msg2 = client.build_send_to_peer("peer_b", vec![2]);
        if let RelayMessage::RelayGossipMessage { seq, .. } = msg2 {
            assert_eq!(seq, 2, "second message to same target must have seq=2");
        }

        // First message to peer_c starts at 1
        let msg_c = client.build_send_to_peer("peer_c", vec![3]);
        if let RelayMessage::RelayGossipMessage { seq, .. } = msg_c {
            assert_eq!(seq, 1, "first message to different target starts at 1");
        }

        assert_eq!(client.seq_for_target("peer_b"), 2);
        assert_eq!(client.seq_for_target("peer_c"), 1);
        assert_eq!(client.seq_for_target("peer_x"), 0); // never sent
    }
}
