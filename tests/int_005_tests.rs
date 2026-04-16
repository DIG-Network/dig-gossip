//! Tests for **INT-005: Relay broadcast in Plumtree step 7**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-005.md`
//! - **Master SPEC:** SS7 (Relay Fallback)
//!
//! INT-005 is satisfied when RelayClient::build_broadcast produces a correct
//! RelayMessage::Broadcast with the right fields.

/// **INT-005: RelayClient::build_broadcast produces correct Broadcast message.**
#[test]
#[cfg(feature = "relay")]
fn test_relay_client_build_broadcast() {
    use dig_gossip::relay::relay_client::RelayClient;
    use dig_gossip::RelayMessage;

    let client = RelayClient::new("peer_abc".to_string(), "mainnet".to_string(), 1);

    let payload = vec![1u8, 2, 3, 4];
    let exclude = vec!["peer_xyz".to_string()];
    let msg = client.build_broadcast(payload.clone(), exclude.clone());

    match msg {
        RelayMessage::Broadcast {
            from,
            payload: p,
            exclude: e,
        } => {
            assert_eq!(from, "peer_abc");
            assert_eq!(p, payload);
            assert_eq!(e, exclude);
        }
        other => panic!("expected Broadcast, got {:?}", other),
    }
}

/// **INT-005: RelayClient::build_broadcast with empty exclude list.**
#[test]
#[cfg(feature = "relay")]
fn test_relay_client_build_broadcast_no_exclude() {
    use dig_gossip::relay::relay_client::RelayClient;
    use dig_gossip::RelayMessage;

    let client = RelayClient::new("my_peer".to_string(), "testnet10".to_string(), 2);

    let msg = client.build_broadcast(vec![42u8], vec![]);

    match msg {
        RelayMessage::Broadcast {
            from,
            payload,
            exclude,
        } => {
            assert_eq!(from, "my_peer");
            assert_eq!(payload, vec![42u8]);
            assert!(exclude.is_empty());
        }
        other => panic!("expected Broadcast, got {:?}", other),
    }
}

/// **INT-005: RelayClient::build_send_to_peer produces correct RelayGossipMessage.**
#[test]
#[cfg(feature = "relay")]
fn test_relay_client_build_send_to_peer() {
    use dig_gossip::relay::relay_client::RelayClient;
    use dig_gossip::RelayMessage;

    let mut client = RelayClient::new("sender".to_string(), "mainnet".to_string(), 1);

    let msg = client.build_send_to_peer("target", vec![10, 20, 30]);

    match msg {
        RelayMessage::RelayGossipMessage {
            from,
            to,
            payload,
            seq,
        } => {
            assert_eq!(from, "sender");
            assert_eq!(to, "target");
            assert_eq!(payload, vec![10, 20, 30]);
            assert_eq!(seq, 1, "first message should have seq=1");
        }
        other => panic!("expected RelayGossipMessage, got {:?}", other),
    }

    // Second message to same target increments seq
    let msg2 = client.build_send_to_peer("target", vec![]);
    match msg2 {
        RelayMessage::RelayGossipMessage { seq, .. } => {
            assert_eq!(seq, 2);
        }
        other => panic!("expected RelayGossipMessage, got {:?}", other),
    }
}

/// **INT-005: RelayClient can register and track registration state.**
#[test]
#[cfg(feature = "relay")]
fn test_relay_client_registration_flow() {
    use dig_gossip::relay::relay_client::RelayClient;
    use dig_gossip::RelayMessage;

    let mut client = RelayClient::new("peer1".to_string(), "mainnet".to_string(), 1);

    assert!(!client.is_registered());

    // Build register message
    let reg = client.build_register();
    match reg {
        RelayMessage::Register {
            peer_id,
            network_id,
            protocol_version,
        } => {
            assert_eq!(peer_id, "peer1");
            assert_eq!(network_id, "mainnet");
            assert_eq!(protocol_version, 1);
        }
        other => panic!("expected Register, got {:?}", other),
    }

    // Handle successful ack
    client.handle_register_ack(true, "welcome", 5).unwrap();
    assert!(client.is_registered());
}
