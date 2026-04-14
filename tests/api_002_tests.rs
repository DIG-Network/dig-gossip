//! Integration tests for **API-002: `GossipHandle` RPC surface**.
//!
//! ## Traceability
//!
//! - **Spec + matrix:** [`API-002.md`](../docs/requirements/domains/crate_api/specs/API-002.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/crate_api/NORMATIVE.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §3.2–3.3
//!
//! ## Scope (this commit)
//!
//! Many rows in the API-002 table assume **live `Peer` handles** (CON-001) or introducer I/O
//! (DSC-*). Those flows are exercised with **stub peers** stored in [`dig_gossip::GossipHandle`]'s
//! shared state, documented deviations (empty [`PeerConnection`] lists), or `#[ignore]` where only
//! real networking can satisfy the assertion.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use dig_gossip::{
    Bytes32, ChiaProtocolMessage, GossipError, GossipHandle, GossipService, IntroducerConfig,
    Message, NewPeak, NodeType, ProtocolMessageTypes, RelayConfig, RequestPeers, RespondBlock,
    RespondPeers, Streamable,
};

fn sample_new_peak() -> NewPeak {
    let z = Bytes32::default();
    NewPeak::new(z, 1, 1, 0, z)
}

async fn running_handle() -> (GossipService, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    (svc, h)
}

/// **Row:** `test_handle_is_cloneable` — [`GossipHandle`] is `Clone` + `Arc` backed (API-002 summary).
#[tokio::test]
async fn test_handle_is_cloneable() {
    let (_s, h) = running_handle().await;
    let g = h.clone();
    h.health_check().await.unwrap();
    g.health_check().await.unwrap();
}

/// **Row:** `test_broadcast_returns_peer_count` — three stub peers ⇒ broadcast fan-out count 3.
#[tokio::test]
async fn test_broadcast_returns_peer_count() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9101".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:9102".parse().unwrap();
    let c: SocketAddr = "127.0.0.1:9103".parse().unwrap();
    h.connect_to(a).await.unwrap();
    h.connect_to(b).await.unwrap();
    h.connect_to(c).await.unwrap();
    let dummy = Message {
        msg_type: ProtocolMessageTypes::RequestPeers,
        id: None,
        data: RequestPeers::new().to_bytes().unwrap().into(),
    };
    let n = h.broadcast(dummy, None).await.unwrap();
    assert_eq!(n, 3);
}

/// **Row:** `test_broadcast_with_exclude` — excluded stub peer reduces delivery count by one.
#[tokio::test]
async fn test_broadcast_with_exclude() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9201".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:9202".parse().unwrap();
    let c: SocketAddr = "127.0.0.1:9203".parse().unwrap();
    let id_b = h.connect_to(b).await.unwrap();
    h.connect_to(a).await.unwrap();
    h.connect_to(c).await.unwrap();
    let dummy = Message {
        msg_type: ProtocolMessageTypes::RequestPeers,
        id: None,
        data: RequestPeers::new().to_bytes().unwrap().into(),
    };
    let n = h.broadcast(dummy, Some(id_b)).await.unwrap();
    assert_eq!(n, 2);
}

/// **Row:** `test_broadcast_typed_serializes` — `broadcast_typed` exercises `Streamable` + `ChiaProtocolMessage`.
///
/// **Proof:** [`NewPeak::msg_type`] must match the wire enum (serialization would fail if types were wrong).
#[tokio::test]
async fn test_broadcast_typed_serializes() {
    assert_eq!(NewPeak::msg_type(), ProtocolMessageTypes::NewPeak);
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9301".parse().unwrap();
    h.connect_to(a).await.unwrap();
    let n = h.broadcast_typed(sample_new_peak(), None).await.unwrap();
    assert_eq!(n, 1);
    let st = h.stats().await;
    assert!(st.messages_sent >= 1);
}

/// **Row:** `test_send_to_connected_peer` / `test_send_to_unknown_peer`.
#[tokio::test]
async fn test_send_to_connected_peer() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9401".parse().unwrap();
    let pid = h.connect_to(a).await.unwrap();
    h.send_to(pid, RequestPeers::new()).await.unwrap();
}

#[tokio::test]
async fn test_send_to_unknown_peer() {
    let (_s, h) = running_handle().await;
    let unknown = Bytes32::from([7u8; 32]);
    let err = h.send_to(unknown, RequestPeers::new()).await.unwrap_err();
    assert!(matches!(err, GossipError::PeerNotConnected(_)));
}

/// **Row:** `test_request_response` — stub `RequestPeers → RespondPeers` path (TypeId branch in handle).
#[tokio::test]
async fn test_request_response() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9501".parse().unwrap();
    let pid = h.connect_to(a).await.unwrap();
    let r: RespondPeers = h.request(pid, RequestPeers::new()).await.unwrap();
    assert!(r.peer_list.is_empty());
}

/// **Row:** `test_request_timeout` — mismatched request/response pair hits fast `RequestTimeout`.
#[tokio::test]
async fn test_request_timeout() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9601".parse().unwrap();
    let pid = h.connect_to(a).await.unwrap();
    let err = h
        .request::<RespondBlock, RequestPeers>(pid, RequestPeers::new())
        .await
        .unwrap_err();
    assert!(matches!(err, GossipError::RequestTimeout));
}

/// **Row:** `test_inbound_receiver` — subscribe on broadcast hub, inject synthetic tuple, receive it.
#[tokio::test]
async fn test_inbound_receiver() {
    let (_s, h) = running_handle().await;
    let mut rx = h.inbound_receiver().expect("subscribe");
    let sender = Bytes32::from([9u8; 32]);
    let msg = Message {
        msg_type: ProtocolMessageTypes::NewPeak,
        id: None,
        data: sample_new_peak().to_bytes().unwrap().into(),
    };
    h.__inject_inbound_for_tests(sender, msg.clone())
        .expect("inject");
    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("recv");
    assert_eq!(got.0, sender);
    assert_eq!(got.1.msg_type, ProtocolMessageTypes::NewPeak);
}

/// **Row:** `test_connected_peers` — returns empty until CON-001 can build [`PeerConnection`] (module rustdoc).
#[tokio::test]
async fn test_connected_peers() {
    let (_s, h) = running_handle().await;
    assert!(h.connected_peers().await.is_empty());
}

/// **Row:** `test_peer_count`.
#[tokio::test]
async fn test_peer_count() {
    let (_s, h) = running_handle().await;
    for i in 0..5u16 {
        let addr = SocketAddr::from(([127, 0, 0, 1], 9700 + i));
        h.connect_to(addr).await.unwrap();
    }
    assert_eq!(h.peer_count().await, 5);
}

/// **Row:** `test_get_connections_filter_type` / `test_get_connections_outbound_only` — filter logic on stubs.
#[tokio::test]
async fn test_get_connections_filter_type() {
    let (_s, h) = running_handle().await;
    h.__connect_stub_peer_with_direction(
        "127.0.0.1:9801".parse().unwrap(),
        NodeType::FullNode,
        true,
    )
    .await
    .unwrap();
    h.__connect_stub_peer_with_direction("127.0.0.1:9802".parse().unwrap(), NodeType::Wallet, true)
        .await
        .unwrap();
    assert_eq!(
        h.__stub_filter_count_for_tests(Some(NodeType::FullNode), false)
            .await,
        1
    );
    assert!(h
        .get_connections(Some(NodeType::FullNode), false)
        .await
        .is_empty());
}

#[tokio::test]
async fn test_get_connections_outbound_only() {
    let (_s, h) = running_handle().await;
    h.__connect_stub_peer_with_direction(
        "127.0.0.1:9901".parse().unwrap(),
        NodeType::FullNode,
        true,
    )
    .await
    .unwrap();
    h.__connect_stub_peer_with_direction(
        "127.0.0.1:9902".parse().unwrap(),
        NodeType::FullNode,
        false,
    )
    .await
    .unwrap();
    assert_eq!(h.__stub_filter_count_for_tests(None, true).await, 1);
}

/// **Row:** `test_connect_to_success`.
#[tokio::test]
async fn test_connect_to_success() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let pid = h.connect_to(a).await.unwrap();
    assert_eq!(h.peer_count().await, 1);
    assert_ne!(pid, Bytes32::default());
}

/// **Row:** `test_connect_to_max_connections`.
#[tokio::test]
async fn test_connect_to_max_connections() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 2;
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    h.connect_to("127.0.0.1:10101".parse().unwrap())
        .await
        .unwrap();
    h.connect_to("127.0.0.1:10102".parse().unwrap())
        .await
        .unwrap();
    let err = h
        .connect_to("127.0.0.1:10103".parse().unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, GossipError::MaxConnectionsReached(2)));
}

/// **Row:** `test_connect_to_duplicate`.
#[tokio::test]
async fn test_connect_to_duplicate() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10201".parse().unwrap();
    let first = h.connect_to(a).await.unwrap();
    let err = h.connect_to(a).await.unwrap_err();
    assert!(matches!(err, GossipError::DuplicateConnection(p) if p == first));
}

/// **Row:** `test_connect_to_self`.
#[tokio::test]
async fn test_connect_to_self() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let self_addr = cfg.listen_addr;
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    let err = h.connect_to(self_addr).await.unwrap_err();
    assert!(matches!(err, GossipError::SelfConnection));
}

/// **Row:** `test_disconnect_peer`.
#[tokio::test]
async fn test_disconnect_peer() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10301".parse().unwrap();
    let pid = h.connect_to(a).await.unwrap();
    h.disconnect(&pid).await.unwrap();
    assert_eq!(h.peer_count().await, 0);
}

/// **Row:** `test_ban_peer`.
#[tokio::test]
async fn test_ban_peer() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10401".parse().unwrap();
    let pid = h.connect_to(a).await.unwrap();
    h.ban_peer(&pid, dig_gossip::PenaltyReason::ProtocolViolation)
        .await
        .unwrap();
    assert_eq!(h.peer_count().await, 0);
    let err = h.send_to(pid, RequestPeers::new()).await.unwrap_err();
    assert!(matches!(err, GossipError::PeerBanned(_)));
}

/// **Row:** `test_penalize_peer_below_threshold` / `test_penalize_peer_auto_ban`.
#[tokio::test]
async fn test_penalize_peer_below_threshold() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10501".parse().unwrap();
    let pid = h.connect_to(a).await.unwrap();
    h.penalize_peer(&pid, dig_gossip::PenaltyReason::ConnectionIssue)
        .await
        .unwrap();
    assert_eq!(h.peer_count().await, 1);
}

#[tokio::test]
async fn test_penalize_peer_auto_ban() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10601".parse().unwrap();
    let pid = h.connect_to(a).await.unwrap();
    // 4 × Spam (25) = 100 → threshold ban (API-006 / CON-007 weights).
    for _ in 0..4 {
        h.penalize_peer(&pid, dig_gossip::PenaltyReason::Spam)
            .await
            .unwrap();
    }
    assert_eq!(h.peer_count().await, 0);
    let err = h.send_to(pid, RequestPeers::new()).await.unwrap_err();
    assert!(matches!(err, GossipError::PeerBanned(_)));
}

/// **Row:** `test_discover_no_introducer`.
#[tokio::test]
async fn test_discover_no_introducer() {
    let (_s, h) = running_handle().await;
    let err = h.discover_from_introducer().await.unwrap_err();
    assert!(matches!(err, GossipError::IntroducerNotConfigured));
}

/// **Row:** `test_discover_from_introducer` (stub Ok when configured).
#[tokio::test]
async fn test_discover_from_introducer() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.introducer = Some(IntroducerConfig::default());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    let v = h.discover_from_introducer().await.unwrap();
    assert!(v.is_empty());
}

/// **Row:** `test_register_with_introducer`.
#[tokio::test]
async fn test_register_with_introducer() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.introducer = Some(IntroducerConfig::default());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    h.register_with_introducer().await.unwrap();
}

/// **Row:** `test_request_peers_from`.
#[tokio::test]
async fn test_request_peers_from() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10701".parse().unwrap();
    let pid = h.connect_to(a).await.unwrap();
    let r = h.request_peers_from(&pid).await.unwrap();
    assert!(r.peer_list.is_empty());
}

/// **Row:** `test_stats`.
#[tokio::test]
async fn test_stats() {
    let (_s, h) = running_handle().await;
    let st = h.stats().await;
    assert_eq!(st.connected_peers, 0);
}

/// **Row:** `test_relay_stats_none` / configured stub returns `Some`.
#[tokio::test]
async fn test_relay_stats_none() {
    let (_s, h) = running_handle().await;
    assert!(h.relay_stats().await.is_none());
}

#[tokio::test]
async fn test_relay_stats_some_when_configured() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.relay = Some(RelayConfig::default());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    assert!(h.relay_stats().await.is_some());
}

/// **Row:** `test_methods_after_stop`.
#[tokio::test]
async fn test_methods_after_stop() {
    let (s, h) = running_handle().await;
    s.stop().await.unwrap();
    let err = h.health_check().await.unwrap_err();
    assert!(matches!(err, GossipError::ServiceNotStarted));
}
