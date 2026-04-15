//! Integration tests for **CON-002: inbound connection listener**.
//!
//! ## Traceability
//!
//! - **Spec + matrix:** [`CON-002.md`](../docs/requirements/domains/connection/specs/CON-002.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/connection/NORMATIVE.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §5.2
//!
//! ## Proof strategy
//!
//! Each test name maps to a **Test Plan** row in CON-002. We start a real [`GossipService`] (TLS from
//! [`dig_gossip::load_ssl_cert`]), call [`GossipService::start`] so [`TcpListener`] binds and
//! [`dig_gossip::connection::listener::accept_loop`] runs, then drive one or more outbound
//! [`GossipHandle::connect_to`] (or a raw WSS client where we must send invalid handshake bytes).
//!
//! **Hooks:** [`GossipHandle::__listen_bound_addr_for_tests`], [`GossipHandle::__con002_live_peer_meta_for_tests`],
//! [`GossipHandle::__con001_last_address_batch_for_tests`] map to observable CON-002 side effects.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use chia_traits::Streamable;
use dig_gossip::{
    create_native_tls_connector, load_ssl_cert, Bytes32, GossipHandle, GossipService, Handshake,
    Message, NodeType, PeerId, ProtocolMessageTypes, RespondPeers,
};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMsg;

#[cfg(not(target_os = "windows"))]
use dig_gossip::peer_id_from_tls_spki_der;
#[cfg(not(target_os = "windows"))]
use dig_gossip::{ChiaCertificate, GossipConfig};
#[cfg(not(target_os = "windows"))]
use x509_parser::pem::Pem;

/// Decode first X.509 cert in PEM and derive the gossip [`PeerId`] (same rule as live TLS peers — API-005).
#[cfg(not(target_os = "windows"))]
fn peer_id_from_chia_cert(cert: &ChiaCertificate) -> PeerId {
    let pem = Pem::iter_from_buffer(cert.cert_pem.as_bytes())
        .next()
        .expect("at least one PEM block")
        .expect("parse pem");
    let (_, x509) = x509_parser::parse_x509_certificate(&pem.contents).expect("parse x509");
    peer_id_from_tls_spki_der(x509.tbs_certificate.subject_pki.raw)
}

#[cfg(not(target_os = "windows"))]
fn server_config_with_peer_id(temp_dir: &std::path::Path, peer_id: PeerId) -> GossipConfig {
    let mut cfg = common::test_gossip_config(temp_dir);
    cfg.peer_id = peer_id;
    cfg
}

async fn running_server() -> (tempfile::TempDir, GossipService, GossipHandle, SocketAddr) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("GossipService::new");
    let h = svc.start().await.expect("start");
    let bound = h
        .__listen_bound_addr_for_tests()
        .expect("listen addr after start");
    (dir, svc, h, bound)
}

async fn outbound_client_handle() -> (tempfile::TempDir, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("client new");
    let h = svc.start().await.expect("client start");
    (dir, h)
}

/// **Row:** `test_inbound_listener_bind` — OS assigns port when `listen_addr` uses `:0`.
#[tokio::test]
async fn test_inbound_listener_bind() {
    let (_d, _svc, _h, bound) = running_server().await;
    assert_ne!(
        bound.port(),
        0,
        "binding to 127.0.0.1:0 must yield ephemeral port"
    );
    assert_eq!(bound.ip().to_string(), "127.0.0.1");
}

/// **Row:** `test_inbound_tls_handshake` + `test_inbound_websocket_upgrade` + `test_inbound_handshake_exchange` —
/// outbound `wss://` completes Chia [`Handshake`] against our listener (TLS + WS + bidirectional handshake).
///
/// **Note:** [`GossipHandle::connect_to`] returns the **remote** peer’s [`PeerId`] (here: the **server’s** TLS id).
/// The server’s peer map is keyed by the **inbound** client’s id — use [`GossipHandle::__peer_ids_for_tests`] on the
/// listener handle, not the returned `pid`.
#[tokio::test]
async fn test_inbound_tls_websocket_and_handshake() {
    let (_ds, _svc, server_h, bound) = running_server().await;
    let (_dc, client_h) = outbound_client_handle().await;
    let remote_pid = client_h
        .connect_to(bound)
        .await
        .expect("inbound full flow accepts outbound peer");
    assert_ne!(remote_pid, PeerId::default());
    let keys = server_h.__peer_ids_for_tests();
    assert_eq!(
        keys.len(),
        1,
        "server should register exactly one inbound peer"
    );
    let meta = server_h
        .__con002_live_peer_meta_for_tests(keys[0])
        .expect("server registered live slot");
    assert_eq!(meta.0.ip(), bound.ip());
    assert!(!meta.1, "inbound slot must set is_outbound = false");
}

/// **Row:** `test_inbound_network_id_reject` — server closes session when [`Handshake::network_id`] mismatches.
#[tokio::test]
async fn test_inbound_network_id_reject() {
    let (_ds, _svc, server_h, bound) = running_server().await;
    let client_dir = common::test_temp_dir();
    let (c, k) = common::generate_test_certs(client_dir.path());
    let client_tls = load_ssl_cert(&c, &k).expect("client tls");
    let connector = create_native_tls_connector(&client_tls).expect("connector");
    let uri = format!("wss://{bound}/ws");
    let (mut ws, _) = tokio_tungstenite::connect_async_tls_with_config(
        uri.as_str(),
        None,
        false,
        Some(connector),
    )
    .await
    .expect("tls + ws connect");

    let bad_net = Bytes32::from([0x42u8; 32]).to_string();
    let hs = Handshake {
        network_id: bad_net.clone(),
        protocol_version: "0.0.37".to_string(),
        software_version: "test/1".to_string(),
        server_port: 0,
        node_type: NodeType::FullNode,
        capabilities: vec![],
    };
    let wire = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: hs.to_bytes().expect("hs").into(),
    };
    ws.send(WsMsg::Binary(wire.to_bytes().expect("msg")))
        .await
        .ok();

    let _ = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .ok();

    assert_eq!(
        server_h.peer_count().await,
        0,
        "server must not register peer after WrongNetwork"
    );
}

/// **Row:** `test_inbound_peer_connection_wrapping` — [`__con002_live_peer_meta_for_tests`] shows inbound direction.
#[tokio::test]
async fn test_inbound_peer_connection_wrapping() {
    let (_ds, _svc, server_h, bound) = running_server().await;
    let (_dc, client_h) = outbound_client_handle().await;
    client_h.connect_to(bound).await.expect("connect");
    let keys = server_h.__peer_ids_for_tests();
    let (_, is_out) = server_h
        .__con002_live_peer_meta_for_tests(keys[0])
        .expect("wrapped peer");
    assert!(
        !is_out,
        "CON-002 requires PeerConnection-style metadata with is_outbound=false for inbound"
    );
}

/// **Row:** `test_inbound_address_manager_add` — inbound peer row reaches [`AddressManager::add_to_new_table`].
#[tokio::test]
async fn test_inbound_address_manager_add() {
    let (_ds, _svc, server_h, bound) = running_server().await;
    let (_dc, client_h) = outbound_client_handle().await;
    client_h.connect_to(bound).await.expect("connect");

    let (batch, src) = server_h
        .__con001_last_address_batch_for_tests()
        .expect("inbound should call add_to_new_table");

    assert_eq!(src.host, bound.ip().to_string());
    assert_eq!(src.port, bound.port());
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].host, "127.0.0.1");
}

/// **Row:** `test_inbound_peer_info_relay` — existing live peer receives [`RespondPeers`] with the newcomer.
#[tokio::test]
async fn test_inbound_peer_info_relay() {
    let (_ds, _svc, _server_h, bound) = running_server().await;
    let (_db, hb) = outbound_client_handle().await;
    hb.connect_to(bound).await.expect("first peer");

    let mut sub = hb.inbound_receiver().expect("subscribe");

    let (_dc, hc) = outbound_client_handle().await;
    hc.connect_to(bound).await.expect("second peer");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut saw_relay = false;
    while tokio::time::Instant::now() < deadline {
        let Ok((_sender, msg)) = sub.recv().await else {
            break;
        };
        if msg.msg_type == ProtocolMessageTypes::RespondPeers {
            let body = RespondPeers::from_bytes(&msg.data).expect("RespondPeers");
            if body.peer_list.len() == 1 && body.peer_list[0].host == "127.0.0.1" {
                saw_relay = true;
                break;
            }
        }
    }
    assert!(
        saw_relay,
        "first peer should receive RespondPeers relay per CON-002 Peer Info Relay"
    );
}

/// **Row:** `test_inbound_max_connections` — at capacity, further inbound attempts do not increase `peer_count`.
#[tokio::test]
async fn test_inbound_max_connections() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 1;
    cfg.target_outbound_count = 1;
    let svc = GossipService::new(cfg).expect("new");
    let server_h = svc.start().await.expect("start");
    let bound = server_h.__listen_bound_addr_for_tests().unwrap();

    let (_d1, h1) = outbound_client_handle().await;
    h1.connect_to(bound).await.expect("first allowed");
    assert_eq!(server_h.peer_count().await, 1);

    let (_d2, h2) = outbound_client_handle().await;
    let _ = h2.connect_to(bound).await;
    // Server drops excess TCP accepts before TLS; client may see [`GossipError::ClientError`] or I/O failure.
    assert!(
        server_h.peer_count().await <= 1,
        "server must not exceed max_connections"
    );
}

/// **Row:** `test_inbound_self_connection_reject` — TLS `PeerId` cannot equal configured local `peer_id`.
///
/// **Platform:** Skipped on Windows — SChannel does not expose remote leaf certs without client-auth
/// negotiation; see listener module docs and CON-009.
#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn test_inbound_self_connection_reject() {
    let server_dir = common::test_temp_dir();
    let (sc, sk) = common::generate_test_certs(server_dir.path());
    let client_dir = common::test_temp_dir();
    let (cc, ck) = common::generate_test_certs(client_dir.path());
    let client_tls = load_ssl_cert(&cc, &ck).expect("client tls");
    let client_derived_id = peer_id_from_chia_cert(&client_tls);

    let mut cfg = server_config_with_peer_id(server_dir.path(), client_derived_id);
    cfg.cert_path = sc;
    cfg.key_path = sk;

    let svc = GossipService::new(cfg).expect("new");
    let server_h = svc.start().await.expect("start");
    let bound = server_h.__listen_bound_addr_for_tests().unwrap();

    let connector = create_native_tls_connector(&client_tls).expect("connector");
    let uri = format!("wss://{bound}/ws");
    let connect = tokio_tungstenite::connect_async_tls_with_config(
        uri.as_str(),
        None,
        false,
        Some(connector),
    );
    let res = tokio::time::timeout(Duration::from_secs(5), connect).await;
    assert!(
        res.is_err() || res.unwrap().is_err(),
        "self-id inbound must fail TLS or handshake path"
    );
    assert_eq!(server_h.peer_count().await, 0);
}
