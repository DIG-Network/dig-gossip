//! **DSC-005 — Introducer registration (`RegisterPeer` / `RegisterAck`)**
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`DSC-005.md`](../docs/requirements/domains/discovery/specs/DSC-005.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/discovery/NORMATIVE.md)
//! - **Verification:** [`VERIFICATION.md`](../docs/requirements/domains/discovery/VERIFICATION.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §6.5
//!
//! ## What this file proves
//!
//! DSC-005 defines a **DIG-only** introducer extension: after the standard Chia [`Handshake`](dig_gossip::Handshake),
//! the client sends [`RegisterPeer`](dig_gossip::RegisterPeer) and must receive [`RegisterAck`](dig_gossip::RegisterAck)
//! on the same mutually-authenticated WSS session. Unlike DSC-004 (opcodes **63/64** already present in upstream
//! [`ProtocolMessageTypes`](dig_gossip::ProtocolMessageTypes)), **218/219** require the vendored `chia-protocol` fork
//! so [`Message::from_bytes`](dig_gossip::Message::from_bytes) can decode replies — see `vendor/chia-protocol/README.dig-gossip.md`.
//!
//! ## Causal chain (examples)
//!
//! - `test_register_introducer_wire_message_types` — if [`ChiaProtocolMessage::msg_type`] drifted from the enum
//!   discriminants patched into `vendor/chia-protocol`, [`Peer::request_infallible`](dig_gossip::Peer::request_infallible)
//!   would serialize the wrong opcode and the mock introducer would reject the frame.
//! - `test_register_introducer_success` — end-to-end TLS + handshake + RPC proves [`IntroducerClient::register_with_introducer`]
//!   matches the acceptance table row *test_register_success*.
//! - `test_register_introducer_rejected` — `RegisterAck { success: false }` must still deserialize as `Ok` so operators
//!   can branch on policy without conflating transport errors (DSC-005 implementation notes).

mod common;

use std::time::Duration;

use chia_traits::Streamable;
use dig_gossip::{
    load_ssl_cert, ChiaCertificate, ChiaProtocolMessage, GossipError, IntroducerClient, NodeType,
    PeerOptions, PeerRegistration, ProtocolMessageTypes, RegisterAck, RegisterPeer,
};

/// **Row:** `test_register_introducer_wire_message_types` — wire structs bind to **218** / **219**.
///
/// **Proof:** [`Peer::request_infallible`] compares inbound [`Message::msg_type`](dig_gossip::Message) to
/// [`RegisterAck::msg_type`]; a mismatch surfaces [`ClientError::InvalidResponse`](dig_gossip::ClientError) and would
/// fail integration tests even if payloads accidentally round-tripped.
#[test]
fn test_register_introducer_wire_message_types() {
    assert_eq!(RegisterPeer::msg_type(), ProtocolMessageTypes::RegisterPeer);
    assert_eq!(RegisterAck::msg_type(), ProtocolMessageTypes::RegisterAck);
}

/// **Row:** `test_register_message_type_in_dig_band` — opcodes stay in the documented DIG extension range (≥200).
#[test]
fn test_register_message_type_in_dig_band() {
    assert!(u32::from(RegisterPeer::msg_type() as u8) >= 200);
    assert!(u32::from(RegisterAck::msg_type() as u8) >= 200);
}

/// **Row:** `test_register_peer_payload_roundtrip` — [`Streamable`] body encoding matches the mock server’s [`RegisterPeer::from_bytes`].
#[test]
fn test_register_peer_payload_roundtrip() {
    let original = RegisterPeer::new("192.0.2.88".into(), 9555, NodeType::FullNode);
    let bytes = original.to_bytes().expect("stream");
    let back = RegisterPeer::from_bytes(&bytes).expect("parse");
    assert_eq!(back, original);
}

fn client_cert(dir: &std::path::Path) -> ChiaCertificate {
    let (c, k) = common::generate_test_certs(dir);
    load_ssl_cert(&c, &k).expect("client load_ssl_cert")
}

/// **Row:** `test_register_introducer_success` — introducer accepts registration (`success: true`).
#[tokio::test]
async fn test_register_introducer_success() {
    let client_dir = common::test_temp_dir();
    let cert = client_cert(client_dir.path());
    let server_dir = common::test_temp_dir();
    let (sc, sk) = common::generate_test_certs(server_dir.path());
    let server_cert = load_ssl_cert(&sc, &sk).expect("server cert");
    let net = common::test_network_id().to_string();
    let reg = PeerRegistration {
        ip: "192.0.2.5".into(),
        port: 9555,
        node_type: NodeType::FullNode,
    };
    let (addr, jh) = common::wss_full_node::spawn_one_shot_introducer_register(
        server_cert,
        net.clone(),
        net,
        Some((reg.ip.clone(), reg.port, reg.node_type)),
        true,
        false,
    )
    .await;
    let uri = format!("wss://127.0.0.1:{}/ws", addr.port());
    let ack = IntroducerClient::register_with_introducer(
        &uri,
        &cert,
        common::test_network_id(),
        PeerOptions::default(),
        Duration::from_secs(10),
        &reg,
    )
    .await
    .expect("register");
    assert!(ack.success, "introducer accepted registration");
    jh.await.expect("join").expect("server");
}

/// **Row:** `test_register_introducer_rejected` — `success: false` is a normal [`RegisterAck`] payload.
#[tokio::test]
async fn test_register_introducer_rejected() {
    let client_dir = common::test_temp_dir();
    let cert = client_cert(client_dir.path());
    let server_dir = common::test_temp_dir();
    let (sc, sk) = common::generate_test_certs(server_dir.path());
    let server_cert = load_ssl_cert(&sc, &sk).expect("server cert");
    let net = common::test_network_id().to_string();
    let reg = PeerRegistration {
        ip: "192.0.2.6".into(),
        port: 9556,
        node_type: NodeType::FullNode,
    };
    let (addr, jh) = common::wss_full_node::spawn_one_shot_introducer_register(
        server_cert,
        net.clone(),
        net,
        Some((reg.ip.clone(), reg.port, reg.node_type)),
        false, // policy rejection
        false,
    )
    .await;
    let uri = format!("wss://127.0.0.1:{}/ws", addr.port());
    let ack = IntroducerClient::register_with_introducer(
        &uri,
        &cert,
        common::test_network_id(),
        PeerOptions::default(),
        Duration::from_secs(10),
        &reg,
    )
    .await
    .expect("wire ok");
    assert!(!ack.success, "introducer declined registration");
    jh.await.expect("join").expect("server");
}

/// **Row:** `test_register_introducer_timeout` — whole-operation timeout maps to [`GossipError::IntroducerError`].
#[tokio::test]
async fn test_register_introducer_timeout() {
    let client_dir = common::test_temp_dir();
    let cert = client_cert(client_dir.path());
    let server_dir = common::test_temp_dir();
    let (sc, sk) = common::generate_test_certs(server_dir.path());
    let server_cert = load_ssl_cert(&sc, &sk).expect("server cert");
    let net = common::test_network_id().to_string();
    let reg = PeerRegistration {
        ip: "192.0.2.7".into(),
        port: 9557,
        node_type: NodeType::FullNode,
    };
    let (addr, jh) = common::wss_full_node::spawn_one_shot_introducer_register(
        server_cert,
        net.clone(),
        net,
        None,
        true,
        true, // stall — never answer RegisterAck
    )
    .await;
    let uri = format!("wss://127.0.0.1:{}/ws", addr.port());
    let err = IntroducerClient::register_with_introducer(
        &uri,
        &cert,
        common::test_network_id(),
        PeerOptions::default(),
        Duration::from_millis(500),
        &reg,
    )
    .await
    .expect_err("timeout");
    match err {
        GossipError::IntroducerError(msg) => assert!(
            msg.contains("timed out"),
            "unexpected introducer error: {msg}"
        ),
        other => panic!("expected IntroducerError, got {other:?}"),
    }
    jh.abort();
}

/// **Row:** `test_register_introducer_connect_fail` — unreachable introducer never panics.
#[tokio::test]
async fn test_register_introducer_connect_fail() {
    let client_dir = common::test_temp_dir();
    let cert = client_cert(client_dir.path());
    let uri = "wss://127.0.0.1:7/ws";
    let reg = PeerRegistration {
        ip: "192.0.2.1".into(),
        port: 9444,
        node_type: NodeType::FullNode,
    };
    let err = IntroducerClient::register_with_introducer(
        uri,
        &cert,
        common::test_network_id(),
        PeerOptions::default(),
        Duration::from_secs(2),
        &reg,
    )
    .await
    .expect_err("connect should fail");
    match err {
        GossipError::ClientError(_) | GossipError::IntroducerError(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}
