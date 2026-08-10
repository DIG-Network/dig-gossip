//! One-shot **Chia-shaped WSS full node** for CON-001 integration tests.
//!
//! **Why not `Peer::from_websocket` on the server?** Upstream [`chia_sdk_client::Peer`]’s inbound
//! dispatcher routes messages with `id` as **responses to this peer’s outbound requests**, not as
//! requests *from* the remote client. A minimal full node that answers `RequestPeers` is therefore
//! implemented with raw [`tokio_tungstenite`] binary frames + [`chia_protocol::Message`] parsing.
//!
//! **Traceability:** [`CON-001.md`](../../docs/requirements/domains/connection/specs/CON-001.md) —
//! `test_outbound_connect_handshake` / `test_request_peers_after_connect`.
//!
//! ## SPEC citations
//!
//! - SPEC §5.1 steps 1-7 — outbound connection lifecycle (this mock is the server half).
//! - SPEC §5.2 steps 1-6 — inbound connection: receive Handshake, validate network_id, send reply.
//! - SPEC §1.5#1 — Handshake with capabilities (capabilities list passed in Handshake struct).
//! - SPEC §1.5#7 — network_id validation: connect_peer() rejects peers with mismatched network_id.
//! - SPEC §1.6#1 — peer exchange on outbound connect: send RequestPeers after handshake.
//! - SPEC §5.3 — mandatory mutual TLS: ChiaCertificate identity for both client and server.

use std::net::SocketAddr;

use dig_gossip::ChiaCertificate;
use dig_gossip::Streamable;
use dig_gossip::{
    Handshake, Message, NodeType, ProtocolMessageTypes, RespondPeers, TimestampedPeerInfo,
};
use dig_gossip::{RegisterAck, RegisterPeer, RequestPeersIntroducer, RespondPeersIntroducer};
use futures_util::{SinkExt, StreamExt};
use native_tls::{Identity, TlsAcceptor};
use tokio::net::TcpListener;
use tokio_native_tls::TlsAcceptor as TokioTlsAcceptor;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tokio_tungstenite::{accept_async, WebSocketStream};

/// Type alias for a TLS-wrapped WebSocket stream used by the test full-node acceptor.
type Ws = WebSocketStream<tokio_native_tls::TlsStream<tokio::net::TcpStream>>;

/// Read the next Chia [`Message`] from a WebSocket stream, handling Ping/Pong transparently.
///
/// Binary frames are decoded as `Message::from_bytes`; Ping frames receive automatic Pong
/// replies (WebSocket keepalive). Close frames and unexpected frame types are treated as errors.
///
/// Used internally by [`serve_one_client`] to drive the handshake + RequestPeers sequence.
async fn next_chia_message(ws: &mut Ws) -> Result<Message, String> {
    loop {
        let raw = ws
            .next()
            .await
            .ok_or_else(|| "websocket closed".to_string())?
            .map_err(|e| e.to_string())?;
        match raw {
            WsMsg::Binary(bin) => {
                return Message::from_bytes(&bin).map_err(|e| e.to_string());
            }
            WsMsg::Ping(p) => {
                ws.send(WsMsg::Pong(p)).await.map_err(|e| e.to_string())?;
            }
            WsMsg::Close(_) => return Err("websocket close".to_string()),
            _ => {}
        }
    }
}

/// Handle a single inbound TLS+WS client connection: validate the Handshake, reply with a
/// server Handshake, then answer the expected `RequestPeers` with `RespondPeers`.
///
/// Proves SPEC §5.2 steps 1-6: receive Handshake, validate network_id, send Handshake reply.
/// Proves SPEC §5.1 step 6: client sends RequestPeers for discovery (node_discovery.py:135-136).
///
/// This models the minimal Chia full-node behavior that CON-001's outbound connect path
/// expects. The sequence is:
/// 1. Receive client Handshake, verify `network_id` matches.
/// 2. Send server Handshake reply (FullNode, protocol 0.0.37).
/// 3. Receive `RequestPeers` from client.
/// 4. Send `RespondPeers` with the provided `peer_list`.
///
/// Any deviation from this sequence returns an error string for test diagnostics.
async fn serve_one_client(
    mut ws: Ws,
    network_id: &str,
    peer_list: Vec<TimestampedPeerInfo>,
) -> Result<(), String> {
    // Step 1: Receive and validate the client's Handshake.
    // SPEC §5.2 step 5 — receive Handshake, validate network_id.
    let first = next_chia_message(&mut ws).await?;
    if first.msg_type != ProtocolMessageTypes::Handshake {
        return Err(format!("expected Handshake, got {:?}", first.msg_type));
    }
    let hs = Handshake::from_bytes(&first.data).map_err(|e| e.to_string())?;
    if hs.network_id != network_id {
        return Err(format!(
            "network_id mismatch: client {} server expect {}",
            hs.network_id, network_id
        ));
    }

    // Step 2: Reply with server's Handshake (matching network_id, FullNode identity).
    // SPEC §5.2 step 6 — send Handshake response.
    // SPEC §1.5#1 — Handshake with capabilities list (empty here for test simplicity).
    let reply_hs = Handshake {
        network_id: network_id.to_string(),
        protocol_version: "0.0.37".to_string(),
        software_version: "dig-gossip-test-fullnode/0".to_string(),
        server_port: 0,
        node_type: NodeType::FullNode,
        capabilities: vec![],
    };
    let out = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: reply_hs.to_bytes().map_err(|e| e.to_string())?.into(),
    };
    ws.send(WsMsg::Binary(out.to_bytes().map_err(|e| e.to_string())?))
        .await
        .map_err(|e| e.to_string())?;

    // Step 3: Receive RequestPeers from client (CON-001 sends this immediately after handshake).
    // SPEC §1.6#1 — peer exchange on outbound connect: send RequestPeers to discover more peers.
    let second = next_chia_message(&mut ws).await?;
    if second.msg_type != ProtocolMessageTypes::RequestPeers {
        return Err(format!("expected RequestPeers, got {:?}", second.msg_type));
    }
    // Step 4: Reply with RespondPeers containing the test's peer_list.
    // SPEC §6.6 — peer exchange via chia-protocol::RequestPeers / RespondPeers.
    // SPEC §1.5#5 — request/response correlation: id field MUST match for SDK's RequestMap.
    let resp = RespondPeers::new(peer_list);
    let out = Message {
        msg_type: ProtocolMessageTypes::RespondPeers,
        id: second.id,
        data: resp.to_bytes().map_err(|e| e.to_string())?.into(),
    };
    ws.send(WsMsg::Binary(out.to_bytes().map_err(|e| e.to_string())?))
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Bind `127.0.0.1:0`, spawn a task that accepts **one** TLS+WS client, performs handshake + answers `RequestPeers`.
///
/// SPEC §5.3 — mandatory mutual TLS: both sides present chia-ssl certificates.
/// SPEC §5.3 — PeerId = SHA256(remote TLS certificate public key), so server needs its own cert.
///
/// **Certs:** use a [`ChiaCertificate`] distinct from the **client** identity so `PeerId` reflects the server SPKI.
pub async fn spawn_one_shot_full_node(
    cert: ChiaCertificate,
    network_id: String,
    peer_list: Vec<TimestampedPeerInfo>,
) -> (SocketAddr, tokio::task::JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wss test listener");
    let addr = listener.local_addr().expect("local_addr");
    // Spawned task: accept one TCP connection, upgrade to TLS, then to WebSocket,
    // and run the handshake + RequestPeers protocol. The task completes (Ok or Err)
    // after serving the single client, at which point the JoinHandle resolves.
    let jh = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.map_err(|e| e.to_string())?;
        // Build a PKCS#8 identity from the PEM cert+key for the TLS acceptor.
        let identity = Identity::from_pkcs8(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .map_err(|e| e.to_string())?;
        let acceptor = TlsAcceptor::builder(identity)
            .build()
            .map_err(|e| e.to_string())?;
        let acceptor = TokioTlsAcceptor::from(acceptor);
        let tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
        let ws = accept_async(tls).await.map_err(|e| e.to_string())?;
        serve_one_client(ws, &network_id, peer_list).await
    });
    (addr, jh)
}

/// A single anomalous frame a peer may inject after the handshake (dig_ecosystem#2391).
///
/// Both variants are frames a *correct* transport must survive, and both were fatal on the
/// `chia-sdk-client` receive loop: one killed the link at `Message::from_bytes`, the other at the
/// correlation-id lookup. They are modelled as data rather than as two harnesses so a single
/// server implementation proves both, differing only in the bytes it emits.
#[derive(Debug, Clone, Copy)]
pub enum HostileFrame {
    /// A well-formed `RespondPeers` carrying a correlation id nobody is waiting on.
    ///
    /// This is not only an attack: ids are chosen independently by each side, so a peer's own
    /// *request* id collides with one of ours routinely.
    UnmatchedCorrelationId,

    /// A frame whose opcode has no `ProtocolMessageTypes` variant in this build.
    ///
    /// Opcode 223 is the next unallocated slot in the 220-255 DIG free band (this build knows
    /// 220 `DigMessage`, 221 `StoreMelted`, 222 `HoldingsAnnounce`), so it is exactly what a peer
    /// running a newer dig-node emits — the realistic case, not a synthetic one.
    UnknownOpcode,
}

/// The unallocated DIG free-band opcode used by [`HostileFrame::UnknownOpcode`].
const UNALLOCATED_DIG_OPCODE: u8 = 223;

impl HostileFrame {
    /// The exact wire bytes this frame puts on the socket.
    ///
    /// Encoded by hand rather than through `Message::to_bytes` because an unallocated opcode has
    /// no `ProtocolMessageTypes` variant to name — the same closed-enum limitation that makes the
    /// frame fatal upstream. The layout is `Message`'s: `u8` opcode, `u8` id-present flag, then
    /// the big-endian `u16` id when present, then a big-endian `u32` length-prefixed body.
    fn to_wire_bytes(self) -> Vec<u8> {
        match self {
            Self::UnmatchedCorrelationId => {
                let body = RespondPeers::new(vec![])
                    .to_bytes()
                    .expect("encode RespondPeers");
                let mut out = vec![ProtocolMessageTypes::RespondPeers as u8, 1];
                // 0xBEEF is far outside the small ids a fresh link allocates, so it cannot
                // accidentally match a real outstanding request.
                out.extend_from_slice(&0xBEEF_u16.to_be_bytes());
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(&body);
                out
            }
            Self::UnknownOpcode => {
                let body = b"a body this build cannot interpret".to_vec();
                let mut out = vec![UNALLOCATED_DIG_OPCODE, 0];
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(&body);
                out
            }
        }
    }
}

/// Handshake, inject one [`HostileFrame`], then answer `RequestPeers` normally.
///
/// The `RequestPeers` exchange after the hostile frame is the whole point: it is the control that
/// distinguishes "the link tolerated the frame" from "the link died quietly". A test that only
/// asserted the frame was accepted would pass against a torn-down link.
async fn serve_one_hostile_client(
    mut ws: Ws,
    network_id: &str,
    hostile: HostileFrame,
    peer_list: Vec<TimestampedPeerInfo>,
) -> Result<(), String> {
    let first = next_chia_message(&mut ws).await?;
    if first.msg_type != ProtocolMessageTypes::Handshake {
        return Err(format!("expected Handshake, got {:?}", first.msg_type));
    }
    let hs = Handshake::from_bytes(&first.data).map_err(|e| e.to_string())?;
    if hs.network_id != network_id {
        return Err(format!("network_id mismatch: client {}", hs.network_id));
    }

    let reply_hs = Handshake {
        network_id: network_id.to_string(),
        protocol_version: "0.0.37".to_string(),
        software_version: "dig-gossip-test-fullnode/0".to_string(),
        server_port: 0,
        node_type: NodeType::FullNode,
        capabilities: vec![],
    };
    let out = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: reply_hs.to_bytes().map_err(|e| e.to_string())?.into(),
    };
    ws.send(WsMsg::Binary(out.to_bytes().map_err(|e| e.to_string())?))
        .await
        .map_err(|e| e.to_string())?;

    ws.send(WsMsg::Binary(hostile.to_wire_bytes()))
        .await
        .map_err(|e| e.to_string())?;

    let second = next_chia_message(&mut ws).await?;
    if second.msg_type != ProtocolMessageTypes::RequestPeers {
        return Err(format!("expected RequestPeers, got {:?}", second.msg_type));
    }
    let resp = RespondPeers::new(peer_list);
    let out = Message {
        msg_type: ProtocolMessageTypes::RespondPeers,
        id: second.id,
        data: resp.to_bytes().map_err(|e| e.to_string())?.into(),
    };
    ws.send(WsMsg::Binary(out.to_bytes().map_err(|e| e.to_string())?))
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Bind `127.0.0.1:0` and serve one client the [`serve_one_hostile_client`] sequence.
pub async fn spawn_one_shot_hostile_full_node(
    cert: ChiaCertificate,
    network_id: String,
    hostile: HostileFrame,
    peer_list: Vec<TimestampedPeerInfo>,
) -> (SocketAddr, tokio::task::JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hostile wss test listener");
    let addr = listener.local_addr().expect("local_addr");
    let jh = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let identity = Identity::from_pkcs8(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .map_err(|e| e.to_string())?;
        let acceptor = TlsAcceptor::builder(identity)
            .build()
            .map_err(|e| e.to_string())?;
        let acceptor = TokioTlsAcceptor::from(acceptor);
        let tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
        let ws = accept_async(tls).await.map_err(|e| e.to_string())?;
        serve_one_hostile_client(ws, &network_id, hostile, peer_list).await
    });
    (addr, jh)
}

/// One-shot **introducer** acceptor for DSC-004: handshake, then `RequestPeersIntroducer` → `RespondPeersIntroducer`.
///
/// * `client_expected_network_id` — must match the client’s outbound [`Handshake::network_id`].
/// * `server_handshake_network_id` — placed in the server’s [`Handshake`] reply; use a **different**
///   string than `client_expected_network_id` to force a [`chia_sdk_client::ClientError::WrongNetwork`]
///   failure path in tests.
/// * `stall_after_request_peers_introducer` — after reading [`RequestPeersIntroducer`], sleep instead
///   of replying so client-side timeouts can be exercised.
async fn serve_introducer_one_client(
    mut ws: Ws,
    client_expected_network_id: &str,
    server_handshake_network_id: &str,
    peer_list: Vec<TimestampedPeerInfo>,
    stall_after_request_peers_introducer: bool,
) -> Result<(), String> {
    let first = next_chia_message(&mut ws).await?;
    if first.msg_type != ProtocolMessageTypes::Handshake {
        return Err(format!("expected Handshake, got {:?}", first.msg_type));
    }
    let hs = Handshake::from_bytes(&first.data).map_err(|e| e.to_string())?;
    if hs.network_id != client_expected_network_id {
        return Err(format!(
            "client network_id mismatch: got {} expect {}",
            hs.network_id, client_expected_network_id
        ));
    }
    // #2215: the two introducer dial paths used to hardcode `"0.0.0"` instead of the configured
    // build, exactly as the peer dial path did. Rejecting anything but the harness's configured
    // value makes every DSC-004/DSC-005 test a real-wire guard on those send sites: if either one
    // stops forwarding its `software_version` argument, this handshake fails and they go red.
    if hs.software_version != super::TEST_SOFTWARE_VERSION {
        return Err(format!(
            "client software_version mismatch: got {:?} expect {:?} — an introducer dial site is not advertising the configured build",
            hs.software_version, super::TEST_SOFTWARE_VERSION
        ));
    }

    let reply_hs = Handshake {
        network_id: server_handshake_network_id.to_string(),
        protocol_version: "0.0.37".to_string(),
        software_version: "dig-gossip-test-introducer/0".to_string(),
        server_port: 0,
        node_type: NodeType::FullNode,
        capabilities: vec![],
    };
    let out = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: reply_hs.to_bytes().map_err(|e| e.to_string())?.into(),
    };
    ws.send(WsMsg::Binary(out.to_bytes().map_err(|e| e.to_string())?))
        .await
        .map_err(|e| e.to_string())?;

    let third = next_chia_message(&mut ws).await?;
    if third.msg_type != ProtocolMessageTypes::RequestPeersIntroducer {
        return Err(format!(
            "expected RequestPeersIntroducer, got {:?}",
            third.msg_type
        ));
    }
    let _req = RequestPeersIntroducer::from_bytes(&third.data).map_err(|e| e.to_string())?;

    if stall_after_request_peers_introducer {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        return Ok(());
    }

    let resp = RespondPeersIntroducer::new(peer_list);
    let out = Message {
        msg_type: ProtocolMessageTypes::RespondPeersIntroducer,
        id: third.id,
        data: resp.to_bytes().map_err(|e| e.to_string())?.into(),
    };
    ws.send(WsMsg::Binary(out.to_bytes().map_err(|e| e.to_string())?))
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Bind `127.0.0.1:0`, accept one TLS+WS client, run the DSC-004 introducer wire sequence.
///
/// Returns the bound [`SocketAddr`] (use `wss://127.0.0.1:{port}/ws` on the client) and a join handle
/// for the server task.
pub async fn spawn_one_shot_introducer(
    cert: ChiaCertificate,
    client_expected_network_id: String,
    server_handshake_network_id: String,
    peer_list: Vec<TimestampedPeerInfo>,
    stall_after_request_peers_introducer: bool,
) -> (SocketAddr, tokio::task::JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind introducer test listener");
    let addr = listener.local_addr().expect("local_addr");
    let jh = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let identity = Identity::from_pkcs8(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .map_err(|e| e.to_string())?;
        let acceptor = TlsAcceptor::builder(identity)
            .build()
            .map_err(|e| e.to_string())?;
        let acceptor = TokioTlsAcceptor::from(acceptor);
        let tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
        let ws = accept_async(tls).await.map_err(|e| e.to_string())?;
        serve_introducer_one_client(
            ws,
            &client_expected_network_id,
            &server_handshake_network_id,
            peer_list,
            stall_after_request_peers_introducer,
        )
        .await
    });
    (addr, jh)
}

/// One-shot introducer that completes **DSC-005** registration: handshake then `RegisterPeer` → `RegisterAck`.
///
/// * `expected_registration` — when `Some`, asserts decoded [`RegisterPeer`] fields match (proves the client sent the configured tuple).
/// * `ack_success` — forwarded into [`RegisterAck::new`].
/// * `stall_after_register_peer` — never sends the ack so client timeouts can be exercised.
async fn serve_introducer_register_one_client(
    mut ws: Ws,
    client_expected_network_id: &str,
    server_handshake_network_id: &str,
    expected_registration: Option<(String, u16, NodeType)>,
    ack_success: bool,
    stall_after_register_peer: bool,
) -> Result<(), String> {
    let first = next_chia_message(&mut ws).await?;
    if first.msg_type != ProtocolMessageTypes::Handshake {
        return Err(format!("expected Handshake, got {:?}", first.msg_type));
    }
    let hs = Handshake::from_bytes(&first.data).map_err(|e| e.to_string())?;
    if hs.network_id != client_expected_network_id {
        return Err(format!(
            "client network_id mismatch: got {} expect {}",
            hs.network_id, client_expected_network_id
        ));
    }
    // #2215: the two introducer dial paths used to hardcode `"0.0.0"` instead of the configured
    // build, exactly as the peer dial path did. Rejecting anything but the harness's configured
    // value makes every DSC-004/DSC-005 test a real-wire guard on those send sites: if either one
    // stops forwarding its `software_version` argument, this handshake fails and they go red.
    if hs.software_version != super::TEST_SOFTWARE_VERSION {
        return Err(format!(
            "client software_version mismatch: got {:?} expect {:?} — an introducer dial site is not advertising the configured build",
            hs.software_version, super::TEST_SOFTWARE_VERSION
        ));
    }

    let reply_hs = Handshake {
        network_id: server_handshake_network_id.to_string(),
        protocol_version: "0.0.37".to_string(),
        software_version: "dig-gossip-test-introducer-register/0".to_string(),
        server_port: 0,
        node_type: NodeType::FullNode,
        capabilities: vec![],
    };
    let out = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: reply_hs.to_bytes().map_err(|e| e.to_string())?.into(),
    };
    ws.send(WsMsg::Binary(out.to_bytes().map_err(|e| e.to_string())?))
        .await
        .map_err(|e| e.to_string())?;

    let third = next_chia_message(&mut ws).await?;
    if third.msg_type != ProtocolMessageTypes::RegisterPeer {
        return Err(format!("expected RegisterPeer, got {:?}", third.msg_type));
    }
    let req = RegisterPeer::from_bytes(&third.data).map_err(|e| e.to_string())?;
    if let Some((ip, port, nt)) = expected_registration {
        if req.ip != ip || req.port != port || req.node_type != nt {
            return Err(format!(
                "RegisterPeer mismatch: got {}:{} {:?} want {}:{} {:?}",
                req.ip, req.port, req.node_type, ip, port, nt
            ));
        }
    }

    if stall_after_register_peer {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        return Ok(());
    }

    let resp = RegisterAck::new(ack_success);
    let out = Message {
        msg_type: ProtocolMessageTypes::RegisterAck,
        id: third.id,
        data: resp.to_bytes().map_err(|e| e.to_string())?.into(),
    };
    ws.send(WsMsg::Binary(out.to_bytes().map_err(|e| e.to_string())?))
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Bind `127.0.0.1:0`, accept one client, run the DSC-005 introducer registration wire sequence.
pub async fn spawn_one_shot_introducer_register(
    cert: ChiaCertificate,
    client_expected_network_id: String,
    server_handshake_network_id: String,
    expected_registration: Option<(String, u16, NodeType)>,
    ack_success: bool,
    stall_after_register_peer: bool,
) -> (SocketAddr, tokio::task::JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind introducer register test listener");
    let addr = listener.local_addr().expect("local_addr");
    let jh = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let identity = Identity::from_pkcs8(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .map_err(|e| e.to_string())?;
        let acceptor = TlsAcceptor::builder(identity)
            .build()
            .map_err(|e| e.to_string())?;
        let acceptor = TokioTlsAcceptor::from(acceptor);
        let tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
        let ws = accept_async(tls).await.map_err(|e| e.to_string())?;
        serve_introducer_register_one_client(
            ws,
            &client_expected_network_id,
            &server_handshake_network_id,
            expected_registration,
            ack_success,
            stall_after_register_peer,
        )
        .await
    });
    (addr, jh)
}
