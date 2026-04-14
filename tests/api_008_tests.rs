//! Tests for **API-008: [`GossipStats`] and [`RelayStats`]**.
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`API-008.md`](../docs/requirements/domains/crate_api/specs/API-008.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/crate_api/NORMATIVE.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §3.4
//!
//! ## Proof strategy
//!
//! Unit tests lock down **type shape**, **`Default`**, **`Debug`/`Clone`**, and **field round-trip**.
//! Integration tests exercise [`dig_gossip::GossipHandle::stats`] / [`dig_gossip::GossipHandle::relay_stats`]
//! against the pre–CON-001 stub so counters move in predictable ways without real TLS peers.

mod common;

use std::net::SocketAddr;

use dig_gossip::{
    Bytes32, ChiaProtocolMessage, GossipHandle, GossipService, GossipStats, Message, NewPeak,
    NodeType, RelayConfig, RelayStats, RequestPeers, Streamable,
};

async fn running_handle() -> (GossipService, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    (svc, h)
}

fn sample_new_peak() -> NewPeak {
    let z = Bytes32::default();
    NewPeak::new(z, 1, 1, 0, z)
}

fn assert_gossip_stats_equal(a: &GossipStats, b: &GossipStats) {
    assert_eq!(a.total_connections, b.total_connections);
    assert_eq!(a.connected_peers, b.connected_peers);
    assert_eq!(a.inbound_connections, b.inbound_connections);
    assert_eq!(a.outbound_connections, b.outbound_connections);
    assert_eq!(a.messages_sent, b.messages_sent);
    assert_eq!(a.messages_received, b.messages_received);
    assert_eq!(a.bytes_sent, b.bytes_sent);
    assert_eq!(a.bytes_received, b.bytes_received);
    assert_eq!(a.known_addresses, b.known_addresses);
    assert_eq!(a.seen_messages, b.seen_messages);
    assert_eq!(a.relay_connected, b.relay_connected);
    assert_eq!(a.relay_peer_count, b.relay_peer_count);
}

fn assert_relay_stats_equal(a: &RelayStats, b: &RelayStats) {
    assert_eq!(a.connected, b.connected);
    assert_eq!(a.messages_sent, b.messages_sent);
    assert_eq!(a.messages_received, b.messages_received);
    assert_eq!(a.bytes_sent, b.bytes_sent);
    assert_eq!(a.bytes_received, b.bytes_received);
    assert_eq!(a.reconnect_attempts, b.reconnect_attempts);
    assert_eq!(a.last_connected_at, b.last_connected_at);
    assert_eq!(a.relay_peer_count, b.relay_peer_count);
    assert_eq!(a.latency_ms, b.latency_ms);
}

/// **Row:** `test_gossip_stats_default` — API-008 default field values.
#[test]
fn test_gossip_stats_default() {
    let s = GossipStats::default();
    assert_eq!(s.total_connections, 0);
    assert_eq!(s.connected_peers, 0);
    assert_eq!(s.inbound_connections, 0);
    assert_eq!(s.outbound_connections, 0);
    assert_eq!(s.messages_sent, 0);
    assert_eq!(s.messages_received, 0);
    assert_eq!(s.bytes_sent, 0);
    assert_eq!(s.bytes_received, 0);
    assert_eq!(s.known_addresses, 0);
    assert_eq!(s.seen_messages, 0);
    assert!(!s.relay_connected);
    assert_eq!(s.relay_peer_count, 0);
}

/// **Row:** `test_relay_stats_default`
#[test]
fn test_relay_stats_default() {
    let r = RelayStats::default();
    assert!(!r.connected);
    assert_eq!(r.messages_sent, 0);
    assert_eq!(r.messages_received, 0);
    assert_eq!(r.bytes_sent, 0);
    assert_eq!(r.bytes_received, 0);
    assert_eq!(r.reconnect_attempts, 0);
    assert_eq!(r.last_connected_at, None);
    assert_eq!(r.relay_peer_count, 0);
    assert_eq!(r.latency_ms, None);
}

/// **Row:** `test_gossip_stats_debug`
#[test]
fn test_gossip_stats_debug() {
    let s = GossipStats {
        connected_peers: 3,
        messages_sent: 9,
        ..Default::default()
    };
    let t = format!("{s:?}");
    assert!(t.contains("connected_peers") && t.contains('3'), "{t}");
}

/// **Row:** `test_relay_stats_debug`
#[test]
fn test_relay_stats_debug() {
    let r = RelayStats {
        reconnect_attempts: 2,
        last_connected_at: Some(1_700_000_000),
        ..Default::default()
    };
    let t = format!("{r:?}");
    assert!(t.contains("reconnect_attempts"), "{t}");
}

/// **Row:** `test_gossip_stats_clone`
#[test]
fn test_gossip_stats_clone() {
    let s = GossipStats {
        total_connections: 5,
        inbound_connections: 1,
        outbound_connections: 4,
        seen_messages: 10,
        ..Default::default()
    };
    let c = s.clone();
    assert_gossip_stats_equal(&s, &c);
}

/// **Row:** `test_relay_stats_clone`
#[test]
fn test_relay_stats_clone() {
    let r = RelayStats {
        messages_sent: 1,
        latency_ms: Some(42),
        ..Default::default()
    };
    let c = r.clone();
    assert_relay_stats_equal(&r, &c);
}

/// **Row:** `test_gossip_stats_populated` — every public field is writable and readable.
#[test]
fn test_gossip_stats_populated() {
    let s = GossipStats {
        total_connections: 100,
        connected_peers: 8,
        inbound_connections: 3,
        outbound_connections: 5,
        messages_sent: 1_000,
        messages_received: 2_000,
        bytes_sent: 3_000,
        bytes_received: 4_000,
        known_addresses: 50,
        seen_messages: 99,
        relay_connected: true,
        relay_peer_count: 7,
    };
    assert_eq!(
        s.connected_peers,
        s.inbound_connections + s.outbound_connections
    );
}

/// **Row:** `test_relay_stats_populated`
#[test]
fn test_relay_stats_populated() {
    let _ = RelayStats {
        connected: true,
        messages_sent: 11,
        messages_received: 22,
        bytes_sent: 33,
        bytes_received: 44,
        reconnect_attempts: 3,
        last_connected_at: Some(99),
        relay_peer_count: 5,
        latency_ms: Some(12),
    };
}

/// **Row:** `test_stats_from_running_service` — snapshot reflects stub peer topology.
#[tokio::test]
async fn test_stats_from_running_service() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:18001".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:18002".parse().unwrap();
    h.connect_to(a).await.unwrap();
    h.connect_to(b).await.unwrap();
    let st = h.stats().await;
    assert_eq!(st.connected_peers, 2);
    assert_eq!(st.outbound_connections, 2);
    assert_eq!(st.inbound_connections, 0);
    assert_eq!(
        st.connected_peers,
        st.inbound_connections + st.outbound_connections
    );
    assert_eq!(st.total_connections, 2);
}

/// **Row:** `test_relay_stats_none_without_relay`
#[tokio::test]
async fn test_relay_stats_none_without_relay() {
    let (_s, h) = running_handle().await;
    assert!(h.relay_stats().await.is_none());
}

/// **Row:** `test_relay_stats_some_with_relay`
#[tokio::test]
async fn test_relay_stats_some_with_relay() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.relay = Some(RelayConfig::default());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    let rs = h.relay_stats().await.expect("relay configured");
    assert_relay_stats_equal(&rs, &RelayStats::default());
    let gs = h.stats().await;
    assert!(!gs.relay_connected);
    assert!(!rs.connected);
}

/// **Row:** `test_stats_cumulative_messages` — broadcast fan-out increases `messages_sent`.
#[tokio::test]
async fn test_stats_cumulative_messages() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:18101".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:18102".parse().unwrap();
    h.connect_to(a).await.unwrap();
    h.connect_to(b).await.unwrap();
    let before = h.stats().await.messages_sent;
    let n = h.broadcast_typed(sample_new_peak(), None).await.unwrap();
    assert_eq!(n, 2);
    let after = h.stats().await.messages_sent;
    assert_eq!(after, before + 2, "two stub peers → two counted deliveries");
}

/// **Extension:** `send_to` contributes one to `messages_sent` (API-008 cumulative “sent” messages).
#[tokio::test]
async fn test_stats_send_to_increments_messages_sent() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:18201".parse().unwrap();
    let pid = h.connect_to(a).await.unwrap();
    let before = h.stats().await.messages_sent;
    h.send_to(pid, RequestPeers::new()).await.unwrap();
    let after = h.stats().await.messages_sent;
    assert_eq!(after, before + 1);
}

/// **Extension:** synthetic inbound inject increments `messages_received`.
#[tokio::test]
async fn test_stats_inject_increments_messages_received() {
    let (_s, h) = running_handle().await;
    let sender = Bytes32::from([9u8; 32]);
    let before = h.stats().await.messages_received;
    let msg = Message {
        msg_type: RequestPeers::msg_type(),
        id: None,
        data: RequestPeers::new().to_bytes().unwrap().into(),
    };
    h.__inject_inbound_for_tests(sender, msg).unwrap();
    let after = h.stats().await.messages_received;
    assert_eq!(after, before + 1);
}

/// **Extension:** `total_connections` stays cumulative after disconnect (API-008 implementation notes).
#[tokio::test]
async fn test_total_connections_monotonic_across_disconnect() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:18301".parse().unwrap();
    let pid = h.connect_to(a).await.unwrap();
    assert_eq!(h.stats().await.total_connections, 1);
    h.disconnect(&pid).await.unwrap();
    let st = h.stats().await;
    assert_eq!(st.connected_peers, 0);
    assert_eq!(st.total_connections, 1);
}

/// **Extension:** mixed-direction stub peers count toward inbound vs outbound split.
#[tokio::test]
async fn test_stats_inbound_outbound_split() {
    let (_s, h) = running_handle().await;
    let out: SocketAddr = "127.0.0.1:18401".parse().unwrap();
    let inc: SocketAddr = "127.0.0.1:18402".parse().unwrap();
    h.connect_to(out).await.unwrap();
    h.__connect_stub_peer_with_direction(inc, NodeType::FullNode, false)
        .await
        .unwrap();
    let st = h.stats().await;
    assert_eq!(st.outbound_connections, 1);
    assert_eq!(st.inbound_connections, 1);
    assert_eq!(st.connected_peers, 2);
}
