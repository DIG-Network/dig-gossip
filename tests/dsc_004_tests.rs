//! **DSC-004 — Introducer query (`RequestPeersIntroducer` / `RespondPeersIntroducer`)**
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`DSC-004.md`](../docs/requirements/domains/discovery/specs/DSC-004.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/discovery/NORMATIVE.md)
//! - **Verification:** [`VERIFICATION.md`](../docs/requirements/domains/discovery/VERIFICATION.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §6.5
//!
//! ## What this file proves
//!
//! DSC-004 mandates a **short-lived WSS session**: mutual TLS, Chia [`Handshake`](dig_gossip::Handshake),
//! [`RequestPeersIntroducer`](dig_gossip::RequestPeersIntroducer), [`RespondPeersIntroducer`](dig_gossip::RespondPeersIntroducer),
//! then teardown. [`IntroducerClient::query_peers`](dig_gossip::IntroducerClient::query_peers) is the
//! canonical implementation; tests pair it with [`common::wss_full_node::spawn_one_shot_introducer`]
//! (STR-005 harness) so CI exercises real TLS + wire framing (not mocks of `Peer` internals).
//!
//! ## Causal chain (examples)
//!
//! - `test_query_introducer_success` — if `request_infallible` targeted the wrong opcode or body shape,
//!   the mock would not decode the client request and the join handle would return `Err` — proving
//!   opcode **63** / **64** alignment with Chia introducer semantics.
//! - `test_query_introducer_timeout` — [`tokio::time::timeout`] inside [`IntroducerClient::query_peers`]
//!   must surface [`GossipError::IntroducerError`] when the server stalls after receiving the request;
//!   otherwise discovery could hang forever (violates DSC-004 acceptance).
//! - `test_query_introducer_handshake_wrong_network` — handshake validation mirrors
//!   [`chia_sdk_client::connect_peer`]; a spoofed `network_id` in the server [`Handshake`] must abort
//!   before any introducer RPC is sent.

mod common;

use std::time::Duration;

use dig_gossip::{
    load_ssl_cert, ChiaCertificate, ChiaProtocolMessage, GossipError, IntroducerClient,
    PeerOptions, ProtocolMessageTypes, RequestPeersIntroducer, RespondPeersIntroducer,
    TimestampedPeerInfo,
};

/// **Row:** `test_introducer_wire_message_types` — wire structs map to protocol IDs **63** / **64**.
///
/// **Proof:** [`ChiaProtocolMessage::msg_type`] is what [`Peer::request_infallible`](dig_gossip::Peer::request_infallible)
/// uses to build outbound frames; a typo here would send the wrong opcode while still “compiling”.
#[test]
fn test_introducer_wire_message_types() {
    assert_eq!(
        RequestPeersIntroducer::msg_type(),
        ProtocolMessageTypes::RequestPeersIntroducer
    );
    assert_eq!(
        RespondPeersIntroducer::msg_type(),
        ProtocolMessageTypes::RespondPeersIntroducer
    );
}

fn client_cert(dir: &std::path::Path) -> ChiaCertificate {
    let (c, k) = common::generate_test_certs(dir);
    load_ssl_cert(&c, &k).expect("client load_ssl_cert")
}

/// **Row:** `test_query_introducer_success` — full flow returns the server’s [`TimestampedPeerInfo`] rows.
#[tokio::test]
async fn test_query_introducer_success() {
    let client_dir = common::test_temp_dir();
    let cert = client_cert(client_dir.path());
    let server_dir = common::test_temp_dir();
    let (sc, sk) = common::generate_test_certs(server_dir.path());
    let server_cert = load_ssl_cert(&sc, &sk).expect("server cert");
    let net = common::test_network_id().to_string();
    let p1 = TimestampedPeerInfo::new("192.0.2.10".into(), 9444, 1_700_000_100);
    let p2 = TimestampedPeerInfo::new("192.0.2.11".into(), 9444, 1_700_000_101);
    let (addr, jh) = common::wss_full_node::spawn_one_shot_introducer(
        server_cert,
        net.clone(),
        net.clone(),
        vec![p1.clone(), p2.clone()],
        false,
    )
    .await;
    let uri = format!("wss://127.0.0.1:{}/ws", addr.port());
    let peers = IntroducerClient::query_peers(
        &uri,
        &cert,
        common::test_network_id(),
        PeerOptions::default(),
        Duration::from_secs(10),
    )
    .await
    .expect("query_peers");
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].host, p1.host);
    assert_eq!(peers[1].host, p2.host);
    jh.await.expect("join server").expect("server ok");
}

/// **Row:** `test_query_introducer_empty_list` — introducer may legitimately return zero peers.
#[tokio::test]
async fn test_query_introducer_empty_list() {
    let client_dir = common::test_temp_dir();
    let cert = client_cert(client_dir.path());
    let server_dir = common::test_temp_dir();
    let (sc, sk) = common::generate_test_certs(server_dir.path());
    let server_cert = load_ssl_cert(&sc, &sk).expect("server cert");
    let net = common::test_network_id().to_string();
    let (addr, jh) = common::wss_full_node::spawn_one_shot_introducer(
        server_cert,
        net.clone(),
        net,
        vec![],
        false,
    )
    .await;
    let uri = format!("wss://127.0.0.1:{}/ws", addr.port());
    let peers = IntroducerClient::query_peers(
        &uri,
        &cert,
        common::test_network_id(),
        PeerOptions::default(),
        Duration::from_secs(10),
    )
    .await
    .expect("empty list is Ok");
    assert!(peers.is_empty());
    jh.await.expect("join").expect("server");
}

/// **Row:** `test_query_introducer_timeout` — server stalls after request → [`GossipError::IntroducerError`].
#[tokio::test]
async fn test_query_introducer_timeout() {
    let client_dir = common::test_temp_dir();
    let cert = client_cert(client_dir.path());
    let server_dir = common::test_temp_dir();
    let (sc, sk) = common::generate_test_certs(server_dir.path());
    let server_cert = load_ssl_cert(&sc, &sk).expect("server cert");
    let net = common::test_network_id().to_string();
    let (addr, jh) = common::wss_full_node::spawn_one_shot_introducer(
        server_cert,
        net.clone(),
        net,
        vec![],
        true, // stall — never send RespondPeersIntroducer
    )
    .await;
    let uri = format!("wss://127.0.0.1:{}/ws", addr.port());
    let err = IntroducerClient::query_peers(
        &uri,
        &cert,
        common::test_network_id(),
        PeerOptions::default(),
        Duration::from_millis(400),
    )
    .await
    .expect_err("must time out");
    match err {
        GossipError::IntroducerError(msg) => {
            assert!(
                msg.contains("timed out"),
                "unexpected introducer error: {msg}"
            );
        }
        other => panic!("expected IntroducerError timeout, got {other:?}"),
    }
    jh.abort();
}

/// **Row:** `test_query_introducer_connect_fail` — bad target surfaces [`GossipError`] (no panic).
///
/// **Note:** Some hosts OS-stack TCP “connection refused” quickly; others may spin until the
/// DSC-004 **whole-operation** deadline — both [`GossipError::ClientError`] and
/// [`GossipError::IntroducerError`] (`… timed out`) prove we never panic on unreachable introducers.
#[tokio::test]
async fn test_query_introducer_connect_fail() {
    let client_dir = common::test_temp_dir();
    let cert = client_cert(client_dir.path());
    let uri = "wss://127.0.0.1:7/ws";
    let err = IntroducerClient::query_peers(
        uri,
        &cert,
        common::test_network_id(),
        PeerOptions::default(),
        Duration::from_secs(2),
    )
    .await
    .expect_err("nothing listens on :7");
    match err {
        GossipError::ClientError(_) | GossipError::IoError(_) => {}
        GossipError::IntroducerError(msg) if msg.contains("timed out") => {}
        other => panic!("unexpected err: {other:?}"),
    }
}

/// **Row:** `test_query_introducer_handshake_wrong_network` — bad server [`Handshake::network_id`] fails closed.
#[tokio::test]
async fn test_query_introducer_handshake_wrong_network() {
    let client_dir = common::test_temp_dir();
    let cert = client_cert(client_dir.path());
    let server_dir = common::test_temp_dir();
    let (sc, sk) = common::generate_test_certs(server_dir.path());
    let server_cert = load_ssl_cert(&sc, &sk).expect("server cert");
    let good = common::test_network_id().to_string();
    let bad = "not-the-test-network-id".to_string();
    let (addr, jh) = common::wss_full_node::spawn_one_shot_introducer(
        server_cert,
        good.clone(),
        bad,
        vec![],
        false,
    )
    .await;
    let uri = format!("wss://127.0.0.1:{}/ws", addr.port());
    let err = IntroducerClient::query_peers(
        &uri,
        &cert,
        common::test_network_id(),
        PeerOptions::default(),
        Duration::from_secs(5),
    )
    .await
    .expect_err("wrong network must fail handshake validation");
    assert!(
        matches!(err, GossipError::ClientError(_)),
        "expected ClientError from WrongNetwork, got {err:?}"
    );
    let _ = jh.await;
}
