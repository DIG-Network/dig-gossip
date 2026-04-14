//! One-shot **Chia-shaped WSS full node** for CON-001 integration tests.
//!
//! **Why not `Peer::from_websocket` on the server?** Upstream [`chia_sdk_client::Peer`]’s inbound
//! dispatcher routes messages with `id` as **responses to this peer’s outbound requests**, not as
//! requests *from* the remote client. A minimal full node that answers `RequestPeers` is therefore
//! implemented with raw [`tokio_tungstenite`] binary frames + [`chia_protocol::Message`] parsing.
//!
//! **Traceability:** [`CON-001.md`](../../docs/requirements/domains/connection/specs/CON-001.md) —
//! `test_outbound_connect_handshake` / `test_request_peers_after_connect`.

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

type Ws = WebSocketStream<tokio_native_tls::TlsStream<tokio::net::TcpStream>>;

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

async fn serve_one_client(
    mut ws: Ws,
    network_id: &str,
    peer_list: Vec<TimestampedPeerInfo>,
) -> Result<(), String> {
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

/// Bind `127.0.0.1:0`, spawn a task that accepts **one** TLS+WS client, performs handshake + answers `RequestPeers`.
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
        serve_one_client(ws, &network_id, peer_list).await
    });
    (addr, jh)
}
