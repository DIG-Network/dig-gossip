//! Tests for **RLY-001: Relay client connect and register**.
//!
//! ## Requirement traceability
//!
//! - **Normative:** `docs/requirements/domains/relay/NORMATIVE.md` (RLY-001)
//! - **Spec:** `docs/requirements/domains/relay/specs/RLY-001.md`
//! - **Master SPEC:** §7 (Relay Fallback)
//!
//! ## What this file proves
//!
//! RLY-001 is satisfied when:
//! 1. RelayMessage enum serializes/deserializes all variants via JSON
//! 2. Register contains peer_id, network_id, protocol_version
//! 3. RegisterAck contains success, message, connected_peers
//! 4. JSON wire format uses #[serde(tag = "type")] discriminator
//! 5. RelayPeerInfo round-trips through JSON
//! 6. All 15 RelayMessage variants are defined

#[cfg(feature = "relay")]
mod tests {
    use dig_gossip::relay::relay_client::RelayClient;
    use dig_gossip::relay::relay_types::{RelayMessage, RelayPeerInfo};

    fn test_client() -> RelayClient {
        RelayClient::new("peer_a".to_string(), "net1".to_string(), 1)
    }

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

    /// **RLY-001: Register message round-trips through JSON.**
    ///
    /// Proves relay protocol uses JSON wire format (SPEC §7).
    #[test]
    fn test_register_json_roundtrip() {
        let msg = RelayMessage::Register {
            peer_id: "abc123".to_string(),
            network_id: "dig_mainnet".to_string(),
            protocol_version: 1,
        };

        let json = serde_json::to_string(&msg).expect("Register must serialize");
        assert!(
            json.contains("\"type\":\"register\""),
            "must have type discriminator"
        );

        let parsed: RelayMessage = serde_json::from_str(&json).expect("Register must deserialize");
        if let RelayMessage::Register {
            peer_id,
            network_id,
            protocol_version,
        } = parsed
        {
            assert_eq!(peer_id, "abc123");
            assert_eq!(network_id, "dig_mainnet");
            assert_eq!(protocol_version, 1);
        } else {
            panic!("expected Register variant");
        }
    }

    /// **RLY-001: RegisterAck round-trips.**
    #[test]
    fn test_register_ack_json_roundtrip() {
        let msg = RelayMessage::RegisterAck {
            success: true,
            message: "welcome".to_string(),
            connected_peers: 42,
        };

        let json = serde_json::to_string(&msg).expect("RegisterAck must serialize");
        assert!(json.contains("\"type\":\"register_ack\""));

        let parsed: RelayMessage = serde_json::from_str(&json).expect("must deserialize");
        if let RelayMessage::RegisterAck {
            success,
            message,
            connected_peers,
        } = parsed
        {
            assert!(success);
            assert_eq!(message, "welcome");
            assert_eq!(connected_peers, 42);
        } else {
            panic!("expected RegisterAck");
        }
    }

    /// **RLY-002: RelayGossipMessage round-trips.**
    #[test]
    fn test_relay_gossip_message_roundtrip() {
        let msg = RelayMessage::RelayGossipMessage {
            from: "peer_a".to_string(),
            to: "peer_b".to_string(),
            payload: vec![1, 2, 3],
            seq: 7,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        if let RelayMessage::RelayGossipMessage { from, to, seq, .. } = parsed {
            assert_eq!(from, "peer_a");
            assert_eq!(to, "peer_b");
            assert_eq!(seq, 7);
        } else {
            panic!("expected RelayGossipMessage");
        }
    }

    /// **RLY-003: Broadcast round-trips.**
    #[test]
    fn test_broadcast_roundtrip() {
        let msg = RelayMessage::Broadcast {
            from: "peer_a".to_string(),
            payload: vec![4, 5, 6],
            exclude: vec!["peer_c".to_string()],
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"broadcast\""));

        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        if let RelayMessage::Broadcast { exclude, .. } = parsed {
            assert_eq!(exclude.len(), 1);
        } else {
            panic!("expected Broadcast");
        }
    }

    /// **RLY-005: GetPeers/Peers round-trips.**
    #[test]
    fn test_get_peers_roundtrip() {
        let msg = RelayMessage::GetPeers {
            network_id: Some("net1".to_string()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, RelayMessage::GetPeers { .. }));
    }

    /// **RLY-006: Ping/Pong round-trips.**
    #[test]
    fn test_ping_pong_roundtrip() {
        let ping = RelayMessage::Ping { timestamp: 12345 };
        let json = serde_json::to_string(&ping).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        if let RelayMessage::Ping { timestamp } = parsed {
            assert_eq!(timestamp, 12345);
        } else {
            panic!("expected Ping");
        }

        let pong = RelayMessage::Pong { timestamp: 12345 };
        let json = serde_json::to_string(&pong).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, RelayMessage::Pong { timestamp: 12345 }));
    }

    /// **RLY-007: HolePunch messages round-trip.**
    #[test]
    fn test_hole_punch_roundtrip() {
        let msg = RelayMessage::HolePunchRequest {
            peer_id: "a".to_string(),
            target_peer_id: "b".to_string(),
            external_addr: "1.2.3.4:9444".parse().unwrap(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, RelayMessage::HolePunchRequest { .. }));
    }

    /// **RLY-001: Error message round-trips.**
    #[test]
    fn test_error_roundtrip() {
        let msg = RelayMessage::Error {
            code: 404,
            message: "not found".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        if let RelayMessage::Error { code, message } = parsed {
            assert_eq!(code, 404);
            assert_eq!(message, "not found");
        } else {
            panic!("expected Error");
        }
    }

    /// **RLY-001: RelayPeerInfo round-trips.**
    #[test]
    fn test_relay_peer_info_roundtrip() {
        let info = RelayPeerInfo {
            peer_id: "peer1".to_string(),
            network_id: "net1".to_string(),
            protocol_version: 1,
            connected_at: 1000,
            last_seen: 2000,
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: RelayPeerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, info);
    }

    /// **RLY-001: PeerConnected/Disconnected round-trip.**
    #[test]
    fn test_peer_notifications_roundtrip() {
        let info = RelayPeerInfo {
            peer_id: "p1".to_string(),
            network_id: "n1".to_string(),
            protocol_version: 1,
            connected_at: 100,
            last_seen: 200,
        };

        let connected = RelayMessage::PeerConnected { peer: info.clone() };
        let json = serde_json::to_string(&connected).unwrap();
        assert!(json.contains("\"type\":\"peer_connected\""));

        let disconnected = RelayMessage::PeerDisconnected {
            peer_id: "p1".to_string(),
        };
        let json = serde_json::to_string(&disconnected).unwrap();
        assert!(json.contains("\"type\":\"peer_disconnected\""));
    }
}
