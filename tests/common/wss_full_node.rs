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

use chia_protocol::{
    Handshake, Message, NodeType, ProtocolMessageTypes, RespondPeers, TimestampedPeerInfo,
};
use chia_ssl::ChiaCertificate;
use chia_traits::Streamable;
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
