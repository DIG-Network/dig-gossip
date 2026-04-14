//! Integration tests for **API-005: `PeerConnection`** (field layout, defaults, TLS-derived [`PeerId`],
//! inbound channel wiring).
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`API-005.md`](../docs/requirements/domains/crate_api/specs/API-005.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/crate_api/NORMATIVE.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) Section 2.4
//!
//! ## Proof strategy
//!
//! Structural tests use STR-005’s [`common::mock_peer_connection`] for a real [`Peer`] + [`mpsc::Receiver`].
//! TLS / SPKI tests use [`ChiaCertificate::generate`] and `x509-parser` **only in this integration crate**
//! (dev-dependency) to extract `SubjectPublicKeyInfo` DER matching production [`peer_id_from_tls_spki_der`].
//! The WebSocket loopback test proves bytes sent with [`Peer::send`] surface on the peer’s paired
//! [`PeerConnection::inbound_rx`] — the same channel edge CON-001 will drive under TLS.

mod common;

use std::time::Duration;

use chia_ssl::ChiaCertificate;
use dig_gossip::{
    peer_id_from_tls_spki_der, Message, NodeType, Peer, PeerId, PeerOptions, PeerReputation,
    ProtocolMessageTypes, RequestPeers,
};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, connect_async, MaybeTlsStream};
use x509_parser::pem::parse_x509_pem;

/// Two [`Peer`] halves over a plain loopback WebSocket (STR-005 pattern — **not** production TLS).
///
/// Returns `((server_peer, server_inbound), (client_peer, client_inbound))` so tests can send from one
/// side and assert receive on the other.
async fn loopback_ws_peers() -> (
    (Peer, tokio::sync::mpsc::Receiver<Message>),
    (Peer, tokio::sync::mpsc::Receiver<Message>),
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");

    let server = async {
        let (tcp, _) = listener.accept().await.expect("accept");
        let ws = accept_async(MaybeTlsStream::Plain(tcp))
            .await
            .expect("ws accept");
        Peer::from_websocket(ws, PeerOptions::default()).expect("server Peer::from_websocket")
    };

    let client = async {
        let url = format!("ws://127.0.0.1:{}/", addr.port());
        let (ws, _) = connect_async(url.as_str()).await.expect("ws connect");
        Peer::from_websocket(ws, PeerOptions::default()).expect("client Peer::from_websocket")
    };

    let (server_res, client_res) = tokio::join!(server, client);
    (server_res, client_res)
}

/// **Row:** `test_peer_connection_all_fields` — every public field is readable (API-005 struct contract).
#[tokio::test]
async fn test_peer_connection_all_fields() {
    let pc = common::mock_peer_connection(true).await;
    let _: Peer = pc.peer;
    let _: PeerId = pc.peer_id;
    let _ = pc.address;
    assert!(pc.is_outbound);
    let _: NodeType = pc.node_type;
    let _: String = pc.protocol_version.clone();
    let _: String = pc.software_version.clone();
    let _: u16 = pc.peer_server_port;
    let _: Vec<(u16, String)> = pc.capabilities.clone();
    let _: u64 = pc.creation_time;
    let _: u64 = pc.bytes_read;
    let _: u64 = pc.bytes_written;
    let _: u64 = pc.last_message_time;
    let _: PeerReputation = pc.reputation.clone();
    let _: tokio::sync::mpsc::Receiver<Message> = pc.inbound_rx;
}

/// **Row:** `test_peer_connection_initial_bytes`
#[tokio::test]
async fn test_peer_connection_initial_bytes() {
    let pc = common::mock_peer_connection(false).await;
    assert_eq!(pc.bytes_read, 0);
    assert_eq!(pc.bytes_written, 0);
}

/// **Row:** `test_peer_connection_initial_reputation`
#[tokio::test]
async fn test_peer_connection_initial_reputation() {
    let pc = common::mock_peer_connection(true).await;
    assert_eq!(pc.reputation, PeerReputation::default());
}

/// **Row:** `test_peer_connection_is_outbound`
#[tokio::test]
async fn test_peer_connection_is_outbound() {
    let pc = common::mock_peer_connection(true).await;
    assert!(pc.is_outbound);
}

/// **Row:** `test_peer_connection_is_inbound`
#[tokio::test]
async fn test_peer_connection_is_inbound() {
    let pc = common::mock_peer_connection(false).await;
    assert!(!pc.is_outbound);
}

/// **Row:** `test_peer_connection_node_type` — harness uses [`NodeType::FullNode`] as stand-in handshake.
#[tokio::test]
async fn test_peer_connection_node_type() {
    let pc = common::mock_peer_connection(true).await;
    assert_eq!(pc.node_type, NodeType::FullNode);
}

/// **Row:** `test_peer_connection_capabilities` — empty capabilities vector is valid (handshake stub).
#[tokio::test]
async fn test_peer_connection_capabilities() {
    let pc = common::mock_peer_connection(false).await;
    assert!(pc.capabilities.is_empty());
}

/// **Row:** `test_peer_connection_creation_time` — Unix seconds, non-zero for real clocks.
#[tokio::test]
async fn test_peer_connection_creation_time() {
    let pc = common::mock_peer_connection(true).await;
    assert!(
        pc.creation_time > 1_000_000_000,
        "creation_time should be plausible unix seconds"
    );
}

/// **Row:** `test_peer_id_from_tls_key` — SHA256(SPKI DER) matches [`peer_id_from_tls_spki_der`].
#[test]
fn test_peer_id_from_tls_key() {
    let cert = ChiaCertificate::generate().expect("ChiaCertificate::generate");
    let (_, pem) = parse_x509_pem(cert.cert_pem.as_bytes()).expect("parse PEM");
    let x509 = pem.parse_x509().expect("parse X509");
    let spki_der = x509.tbs_certificate.subject_pki.raw;
    let id = peer_id_from_tls_spki_der(spki_der);
    assert_ne!(id, PeerId::default(), "hash must be non-zero for real cert");

    let cert2 = ChiaCertificate::generate().expect("second cert");
    let (_, pem2) = parse_x509_pem(cert2.cert_pem.as_bytes()).expect("parse PEM 2");
    let x5092 = pem2.parse_x509().expect("parse X509 2");
    let id2 = peer_id_from_tls_spki_der(x5092.tbs_certificate.subject_pki.raw);
    assert_ne!(id, id2, "different TLS keys must yield different peer ids");

    // Same cert → same id (stable derivation).
    let id_again = peer_id_from_tls_spki_der(spki_der);
    assert_eq!(id, id_again);
}

/// **Row:** `test_inbound_rx_receives_messages` — wire send/recv across paired [`Peer`] handles.
#[tokio::test]
async fn test_inbound_rx_receives_messages() {
    let ((sp, mut srx), (cp, _crx)) = loopback_ws_peers().await;
    cp.send(RequestPeers::new())
        .await
        .expect("client send RequestPeers");

    let msg = tokio::time::timeout(Duration::from_secs(5), srx.recv())
        .await
        .expect("recv timed out")
        .expect("inbound channel must stay open");

    assert_eq!(msg.msg_type, ProtocolMessageTypes::RequestPeers);

    drop(sp);
    drop(cp);
}
