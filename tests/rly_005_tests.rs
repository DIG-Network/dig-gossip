//! Tests for **RLY-005: Relay Peer List**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/relay/specs/RLY-005.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS7

#[cfg(feature = "relay")]
mod tests {
    use dig_gossip::relay::relay_client::RelayClient;
    use dig_gossip::relay::relay_types::RelayPeerInfo;

    fn test_client() -> RelayClient {
        RelayClient::new("peer_a".to_string(), "net1".to_string(), 1)
    }

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
}
