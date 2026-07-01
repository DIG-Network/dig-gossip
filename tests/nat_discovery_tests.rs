//! INT-018 — unified multi-source peer discovery: relay introducer (RLY-005 `get_peers`) +
//! node peer-exchange (`dig.getPeers`), merged into the address book.
//!
//! The L7 spec (§4 "Peer discovery — introducer + gossip") requires a node to fill its address book
//! from BOTH the relay introducer AND asking other nodes, so discovery does not depend on any single
//! rendezvous. This suite covers the pure, network-free core of that wiring:
//!
//! - the relay-introducer `get_peers` REQUEST + `peers` RESPONSE decode (RLY-005 wire), driven over a
//!   loopback WebSocket relay stub (no real network);
//! - merging discovered [`PeerRecord`]s (from either source) into the [`AddressManager`], only
//!   placing peers that carry a dialable candidate address.

use dig_gossip::nat::{
    merge_records_into_address_manager, AddressKind, PeerAddress, PeerRecord, Via,
};
use dig_gossip::AddressManager;

#[test]
fn merge_places_only_dialable_records_into_the_address_manager() {
    let am = AddressManager::new();
    assert_eq!(am.size(), 0);

    let records = vec![
        // A node-gossiped peer with a direct address — goes into the book.
        PeerRecord {
            peer_id: String::new(),
            addresses: vec![PeerAddress {
                host: "203.0.113.10".into(),
                port: 9444,
                kind: AddressKind::Direct,
            }],
            network_id: "DIG_MAINNET".into(),
            last_seen: 1_000,
            via: Via::Direct,
        },
        // A relay-introduced peer with NO dialable address — skipped (reached via the relay, not by
        // dialing an IP).
        PeerRecord {
            peer_id: "cc".repeat(32),
            addresses: vec![],
            network_id: "DIG_MAINNET".into(),
            last_seen: 2_000,
            via: Via::Relay,
        },
    ];

    let added = merge_records_into_address_manager(&am, &records, "1.2.3.4", 9444);
    assert_eq!(
        added, 1,
        "only the record with a dialable address is merged"
    );
    assert_eq!(am.size(), 1);
}

#[test]
fn merge_with_no_dialable_records_is_a_noop() {
    let am = AddressManager::new();
    // Only relay-only records (no dialable address) — nothing is placed.
    let records = vec![PeerRecord {
        peer_id: "cc".repeat(32),
        addresses: vec![],
        network_id: "DIG_MAINNET".into(),
        last_seen: 1,
        via: Via::Relay,
    }];
    let added = merge_records_into_address_manager(&am, &records, "1.2.3.4", 9444);
    assert_eq!(added, 0);
    assert_eq!(am.size(), 0);
    // Empty input is also a clean no-op.
    assert_eq!(
        merge_records_into_address_manager(&am, &[], "1.2.3.4", 9444),
        0
    );
}

#[tokio::test]
async fn relay_get_peers_round_trips_over_a_loopback_relay() {
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;

    // A loopback WebSocket relay stub that answers one `get_peers` with a `peers` list (RLY-005).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        // RLY-001: the client MUST register before any control message (the relay rejects
        // pre-register frames with NOT_REGISTERED), so `register` arrives first.
        let reg = ws.next().await.unwrap().unwrap();
        let reg_v: serde_json::Value = serde_json::from_str(&reg.into_text().unwrap()).unwrap();
        assert_eq!(reg_v["type"], "register");
        assert_eq!(reg_v["network_id"], "DIG_MAINNET");
        // RLY-005: then the get_peers request scoped to the network.
        let msg = ws.next().await.unwrap().unwrap();
        let text = msg.into_text().unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["type"], "get_peers");
        assert_eq!(v["network_id"], "DIG_MAINNET");
        // Reply with a peers list.
        let reply = serde_json::json!({
            "type": "peers",
            "peers": [
                { "peer_id": "aa".repeat(32), "network_id": "DIG_MAINNET",
                  "protocol_version": 1, "connected_at": 10, "last_seen": 42 },
                { "peer_id": "bb".repeat(32), "network_id": "DIG_MAINNET",
                  "protocol_version": 1, "connected_at": 11, "last_seen": 43 }
            ]
        });
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            reply.to_string(),
        ))
        .await
        .unwrap();
    });

    let endpoint = format!("ws://{addr}");
    let records = dig_gossip::nat::discovery::relay_get_peers(
        &endpoint,
        "self".repeat(16),
        "DIG_MAINNET",
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("relay get_peers succeeds");

    server.await.unwrap();

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].peer_id, "aa".repeat(32));
    assert_eq!(records[0].via, Via::Relay);
    assert_eq!(records[0].last_seen, 42);
    assert!(records[0].addresses.is_empty());
    assert_eq!(records[1].peer_id, "bb".repeat(32));
}

#[tokio::test]
async fn relay_get_peers_surfaces_a_relay_error_frame() {
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;

    // The relay answers with an `error` frame (e.g. NOT_REGISTERED) — the query must surface it as an
    // error, not hang or return an empty list.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _register = ws.next().await.unwrap().unwrap();
        let _get_peers = ws.next().await.unwrap().unwrap();
        let err = serde_json::json!({ "type": "error", "code": 1, "message": "NOT_REGISTERED" });
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            err.to_string(),
        ))
        .await
        .unwrap();
    });

    let endpoint = format!("ws://{addr}");
    let result = dig_gossip::nat::discovery::relay_get_peers(
        &endpoint,
        "self".repeat(16),
        "DIG_MAINNET",
        std::time::Duration::from_secs(5),
    )
    .await;
    server.await.unwrap();
    assert!(result.is_err(), "an error frame must surface as an error");
}

#[tokio::test]
async fn relay_get_peers_times_out_when_relay_is_silent() {
    use tokio::net::TcpListener;

    // The relay accepts + upgrades the WebSocket but never replies with `peers` — the bounded query
    // must return a timeout error rather than hanging forever (graceful fallback).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        // Hold the connection open, silent, until the client times out and drops.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });

    let endpoint = format!("ws://{addr}");
    let result = dig_gossip::nat::discovery::relay_get_peers(
        &endpoint,
        "self".repeat(16),
        "DIG_MAINNET",
        std::time::Duration::from_millis(300),
    )
    .await;
    let _ = server.await;
    assert!(result.is_err(), "a silent relay must time out, not hang");
}

#[tokio::test]
async fn unified_discover_skips_the_relay_source_when_endpoint_is_empty() {
    // An empty (or whitespace) relay endpoint means "no relay source" — discovery returns an empty
    // list immediately without attempting any connection.
    let cfg = dig_gossip::UnifiedDiscoveryConfig {
        relay_endpoint: "   ".into(),
        self_peer_id_hex: "ab".repeat(32),
        network_id: "DIG_MAINNET".into(),
        timeout: std::time::Duration::from_secs(1),
    };
    let records = dig_gossip::unified_discover(&cfg).await;
    assert!(records.is_empty());
}

#[tokio::test]
async fn unified_discover_returns_empty_on_relay_failure_never_erroring() {
    // The relay is unreachable — unified_discover swallows the failure (soft) and returns empty, so a
    // node keeps running when the relay is down (graceful-fallback rule).
    let cfg = dig_gossip::UnifiedDiscoveryConfig {
        // Nothing listens here.
        relay_endpoint: "ws://127.0.0.1:1".into(),
        self_peer_id_hex: "ab".repeat(32),
        network_id: "DIG_MAINNET".into(),
        timeout: std::time::Duration::from_millis(300),
    };
    let records = dig_gossip::unified_discover(&cfg).await;
    assert!(records.is_empty());
}

#[tokio::test]
async fn unified_discover_returns_relay_peers_on_success() {
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _register = ws.next().await.unwrap().unwrap();
        let _get_peers = ws.next().await.unwrap().unwrap();
        let reply = serde_json::json!({
            "type": "peers",
            "peers": [
                { "peer_id": "ee".repeat(32), "network_id": "DIG_MAINNET",
                  "protocol_version": 1, "connected_at": 1, "last_seen": 9 }
            ]
        });
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            reply.to_string(),
        ))
        .await
        .unwrap();
    });

    let cfg = dig_gossip::UnifiedDiscoveryConfig {
        relay_endpoint: format!("ws://{addr}"),
        self_peer_id_hex: "ab".repeat(32),
        network_id: "DIG_MAINNET".into(),
        timeout: std::time::Duration::from_secs(5),
    };
    let records = dig_gossip::unified_discover(&cfg).await;
    server.await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].peer_id, "ee".repeat(32));
    assert_eq!(records[0].via, Via::Relay);
}
