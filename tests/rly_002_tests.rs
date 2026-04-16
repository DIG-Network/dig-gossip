//! Tests for **RLY-002** (message forwarding), **RLY-003** (broadcast),
//! **RLY-005** (peer list), **RLY-006** (keepalive).
//!
//! ## Requirement traceability
//!
//! - RLY-002: `docs/requirements/domains/relay/specs/RLY-002.md` — targeted send
//! - RLY-003: `docs/requirements/domains/relay/specs/RLY-003.md` — broadcast
//! - RLY-005: `docs/requirements/domains/relay/specs/RLY-005.md` — peer list
//! - RLY-006: `docs/requirements/domains/relay/specs/RLY-006.md` — keepalive
//! - Master SPEC §7

#[cfg(feature = "relay")]
mod tests {
    use dig_gossip::relay::relay_client::RelayClient;
    use dig_gossip::relay::relay_types::{RelayMessage, RelayPeerInfo};

    fn test_client() -> RelayClient {
        RelayClient::new("peer_a".to_string(), "net1".to_string(), 1)
    }

    // ===================== RLY-001: Registration =====================

    /// **RLY-001: build_register creates correct Register message.**
    #[test]
    fn test_build_register() {
        let client = test_client();
        let msg = client.build_register();
        if let RelayMessage::Register {
            peer_id,
            network_id,
            protocol_version,
        } = msg
        {
            assert_eq!(peer_id, "peer_a");
            assert_eq!(network_id, "net1");
            assert_eq!(protocol_version, 1);
        } else {
            panic!("expected Register");
        }
    }

    /// **RLY-001: handle_register_ack success sets registered.**
    #[test]
    fn test_register_ack_success() {
        let mut client = test_client();
        assert!(!client.is_registered());

        client.handle_register_ack(true, "ok", 5).unwrap();
        assert!(client.is_registered());
    }

    /// **RLY-001: handle_register_ack failure returns error.**
    #[test]
    fn test_register_ack_failure() {
        let mut client = test_client();
        let result = client.handle_register_ack(false, "rejected", 0);
        assert!(result.is_err());
        assert!(!client.is_registered());
    }

    // ===================== RLY-002: Targeted Send =====================

    /// **RLY-002: build_send_to_peer creates RelayGossipMessage with correct fields.**
    ///
    /// Proves SPEC §7 (RLY-002): "forward message to specific peer."
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
    /// Proves SPEC §7: "monotonically increasing seq per sender-receiver pair."
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

    // ===================== RLY-003: Broadcast =====================

    /// **RLY-003: build_broadcast creates Broadcast with exclude list.**
    ///
    /// Proves SPEC §7 (RLY-003): "broadcast to all relay peers."
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

    // ===================== RLY-005: Peer List =====================

    /// **RLY-005: handle_peers stores relay peer list.**
    #[test]
    fn test_handle_peers() {
        let mut client = test_client();
        assert_eq!(client.peer_count(), 0);

        let peers = vec![
            RelayPeerInfo {
                peer_id: "p1".into(),
                network_id: "n1".into(),
                protocol_version: 1,
                connected_at: 100,
                last_seen: 200,
            },
            RelayPeerInfo {
                peer_id: "p2".into(),
                network_id: "n1".into(),
                protocol_version: 1,
                connected_at: 100,
                last_seen: 200,
            },
        ];
        client.handle_peers(peers);

        assert_eq!(client.peer_count(), 2);
    }

    /// **RLY-005: handle_peer_connected adds to known peers.**
    #[test]
    fn test_peer_connected() {
        let mut client = test_client();
        let peer = RelayPeerInfo {
            peer_id: "new_peer".into(),
            network_id: "n1".into(),
            protocol_version: 1,
            connected_at: 100,
            last_seen: 200,
        };

        client.handle_peer_connected(peer.clone());
        assert_eq!(client.peer_count(), 1);

        // Duplicate doesn't increase count
        client.handle_peer_connected(peer);
        assert_eq!(client.peer_count(), 1);
    }

    /// **RLY-005: handle_peer_disconnected removes from known peers.**
    #[test]
    fn test_peer_disconnected() {
        let mut client = test_client();
        let peer = RelayPeerInfo {
            peer_id: "p1".into(),
            network_id: "n1".into(),
            protocol_version: 1,
            connected_at: 100,
            last_seen: 200,
        };
        client.handle_peer_connected(peer);
        assert_eq!(client.peer_count(), 1);

        client.handle_peer_disconnected("p1");
        assert_eq!(client.peer_count(), 0);
    }

    // ===================== RLY-006: Keepalive =====================

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

    // ===================== Reset =====================

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
            "seq NOT reset — monotonic across reconnects"
        );
    }
}
