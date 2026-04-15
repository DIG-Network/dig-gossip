//! Inbound P2P acceptance: [`tokio::net::TcpListener`] → TLS → WebSocket → [`chia_sdk_client::Peer`].
//!
//! **Normative:** [CON-002](../../../docs/requirements/domains/connection/specs/CON-002.md) /
//! [NORMATIVE.md](../../../docs/requirements/domains/connection/NORMATIVE.md).
//!
//! ## Why this is not `chia_sdk_client::connect_peer`
//!
//! Upstream [`Peer`](chia_sdk_client::Peer) is built for **outbound** `wss://` clients. DIG must
//! **listen** on [`crate::types::config::GossipConfig::listen_addr`], terminate TLS with the node
//! [`chia_ssl::ChiaCertificate`], run [`tokio_tungstenite::accept_async`], then call
//! [`Peer::from_websocket`](chia_sdk_client::Peer::from_websocket) — mirroring the pseudo-code in
//! CON-002 and [`SPEC.md`](../../../docs/resources/SPEC.md) §5.2.
//!
//! ## TLS backends (STR-004)
//!
//! - **`native-tls` (default):** [`native_tls::TlsAcceptor`] + [`tokio_native_tls`], matching
//!   CON-001 integration tests ([`tests/common/wss_full_node.rs`](../../../tests/common/wss_full_node.rs)).
//! - **`rustls` without `native-tls` (outbound):** [`chia_sdk_client`] uses rustls for `wss://` dials.
//!   **Inbound** still uses [`native_tls::TlsAcceptor`] so [`MaybeTlsStream::NativeTls`] matches
//!   [`Peer::from_websocket`] (upstream only types **client** `MaybeTlsStream::Rustls`).
//! - **CON-009 (mTLS `CERT_REQUIRED`):** not enforced here yet. **Windows note:** `native_tls` uses
//!   SChannel, which exposes no API to *request* client certificates; `peer_certificate()` may be
//!   `None` even when the outbound peer presents a Chia identity. Until CON-009 lands with an
//!   OpenSSL/rustls server configuration that forces client auth, we fall back to
//!   [`crate::service::state::peer_id_for_addr`] (deterministic, **test / dev only** shape) so the
//!   WebSocket upgrade and [`Peer::from_websocket`] path can complete on Windows CI machines.
//!   Linux/OpenSSL `native_tls` typically still receives the leaf cert when the client uses
//!   [`TlsConnector`](native_tls::TlsConnector) identity material.
//!
//! ## `software_version` sanitization
//!
//! CON-008 will add [`sanitize_version`](../../../docs/requirements/domains/connection/specs/CON-008.md);
//! until then we **pass through** the remote [`Handshake::software_version`] string when recording
//! metadata (same interim choice as outbound CON-001 notes).

#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chia_protocol::{
    Handshake, Message, NodeType, ProtocolMessageTypes, RespondPeers, TimestampedPeerInfo,
};
use chia_sdk_client::{ClientError, Peer, PeerOptions};
use chia_ssl::ChiaCertificate;
use chia_traits::Streamable;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::sync::Notify;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tokio_tungstenite::{accept_async, MaybeTlsStream, WebSocketStream};

use crate::connection::outbound::{network_id_handshake_string, spki_der_from_leaf_cert_der};
use crate::service::state::{peer_id_for_addr, LiveSlot, PeerSlot, ServiceState, StubPeer};
use crate::types::peer::{peer_id_from_tls_spki_der, PeerId, PeerInfo};

/// Chia protocol string carried in [`Handshake::protocol_version`] for DIG acceptance tests.
///
/// **Rationale:** Matches [`crate::connection::outbound::connect_outbound_peer`] so mixed-version
/// policy (CON-003) can tighten both directions from one constant later.
const HANDSHAKE_PROTOCOL_VERSION: &str = "0.0.37";

/// If the remote never sends [`ProtocolMessageTypes::Handshake`], drop the session (CON-002 notes).
const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Inbound TLS (`native_tls::TlsAcceptor`) — used for **both** `native-tls` and `rustls` features.
// ---------------------------------------------------------------------------

#[cfg(any(feature = "native-tls", feature = "rustls"))]
use native_tls::Identity;
#[cfg(any(feature = "native-tls", feature = "rustls"))]
use tokio_native_tls::TlsAcceptor as TokioNativeTlsAcceptor;

#[cfg(any(feature = "native-tls", feature = "rustls"))]
fn native_tls_acceptor(cert: &ChiaCertificate) -> Result<TokioNativeTlsAcceptor, ClientError> {
    let ident =
        Identity::from_pkcs8(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).map_err(|e| {
            ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("native-tls identity: {e}"),
            ))
        })?;
    let acc = native_tls::TlsAcceptor::builder(ident)
        .build()
        .map_err(|e| {
            ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("native-tls acceptor: {e}"),
            ))
        })?;
    Ok(TokioNativeTlsAcceptor::from(acc))
}

#[cfg(any(feature = "native-tls", feature = "rustls"))]
fn remote_spki_from_native_tls_stream(
    tls: &tokio_native_tls::TlsStream<TcpStream>,
) -> Result<Vec<u8>, ClientError> {
    let cert = tls
        .get_ref()
        .peer_certificate()
        .map_err(|e| ClientError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?
        .ok_or(ClientError::MissingHandshake)?;
    let der = cert.to_der().map_err(|e| {
        ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("peer cert der: {e}"),
        ))
    })?;
    spki_der_from_leaf_cert_der(&der)
}

#[cfg(any(feature = "native-tls", feature = "rustls"))]
async fn handle_inbound_native(
    state: Arc<ServiceState>,
    tcp: TcpStream,
    remote_addr: SocketAddr,
    acceptor: TokioNativeTlsAcceptor,
) {
    if let Err(e) = handle_inbound_native_inner(state, tcp, remote_addr, acceptor).await {
        tracing::debug!(target: "dig_gossip::listener", "inbound native session ended: {e}");
    }
}

#[cfg(any(feature = "native-tls", feature = "rustls"))]
async fn handle_inbound_native_inner(
    state: Arc<ServiceState>,
    tcp: TcpStream,
    remote_addr: SocketAddr,
    acceptor: TokioNativeTlsAcceptor,
) -> Result<(), ClientError> {
    if !state.is_running() {
        return Ok(());
    }
    let tls = acceptor
        .accept(tcp)
        .await
        .map_err(|e| ClientError::Io(std::io::Error::other(format!("tls accept: {e}"))))?;
    let peer_id = match remote_spki_from_native_tls_stream(&tls) {
        Ok(spki) => peer_id_from_tls_spki_der(&spki),
        Err(e) => {
            if cfg!(target_os = "windows") {
                tracing::warn!(
                    target: "dig_gossip::listener",
                    "no remote TLS leaf cert after accept (SChannel — see CON-009); using peer_id_for_addr fallback: {e}"
                );
                peer_id_for_addr(remote_addr)
            } else {
                return Err(e);
            }
        }
    };
    if peer_id == state.config.peer_id {
        return Err(ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "inbound self-connection (remote PeerId equals local config.peer_id)",
        )));
    }
    if state
        .banned
        .lock()
        .map_err(|_| ClientError::Io(std::io::Error::from(std::io::ErrorKind::Other)))?
        .contains(&peer_id)
    {
        return Err(ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "inbound peer is banned",
        )));
    }
    {
        let peers = state
            .peers
            .lock()
            .map_err(|_| ClientError::Io(std::io::Error::from(std::io::ErrorKind::Other)))?;
        if peers.contains_key(&peer_id) {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "duplicate inbound PeerId",
            )));
        }
    }

    let ws = accept_async(MaybeTlsStream::NativeTls(tls))
        .await
        .map_err(ws_err)?;
    negotiate_inbound_over_ws(state, remote_addr, ws, peer_id).await
}

// ---------------------------------------------------------------------------
// Shared WebSocket + Chia handshake
// ---------------------------------------------------------------------------

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> ClientError {
    ClientError::Io(std::io::Error::other(e.to_string()))
}

fn listen_port_for_handshake(state: &ServiceState) -> u16 {
    state
        .listen_bound_addr
        .lock()
        .ok()
        .and_then(|g| *g)
        .map(|a| a.port())
        .unwrap_or_else(|| state.config.listen_addr.port())
}

fn our_listen_peer_info(state: &ServiceState) -> PeerInfo {
    let addr = state
        .listen_bound_addr
        .lock()
        .ok()
        .and_then(|g| *g)
        .unwrap_or(state.config.listen_addr);
    PeerInfo {
        host: addr.ip().to_string(),
        port: addr.port(),
    }
}

fn unix_secs_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Relay the inbound peer’s [`TimestampedPeerInfo`] to every **existing** live connection (CON-002 §Peer Info Relay).
///
/// **Mechanism:** Chia nodes often learn addresses via [`RespondPeers`]; we push a one-row list so
/// address managers on already-connected peers can merge the newcomer (see Python `node_discovery.py`
/// references in CON-002).
async fn relay_new_peer_to_live_peers(
    state: &ServiceState,
    new_row: TimestampedPeerInfo,
) -> Result<(), ClientError> {
    let peers: Vec<Peer> = {
        let g = state
            .peers
            .lock()
            .map_err(|_| ClientError::Io(std::io::Error::from(std::io::ErrorKind::Other)))?;
        g.values()
            .filter_map(|slot| match slot {
                PeerSlot::Live(l) => Some(l.peer.clone()),
                PeerSlot::Stub(_) => None,
            })
            .collect()
    };
    for p in peers {
        let resp = RespondPeers::new(vec![new_row.clone()]);
        let _ = p.send(resp).await;
    }
    Ok(())
}

/// Read the next Chia [`Message`] from a raw [`WebSocketStream`] (ping/pong passthrough).
///
/// **Why not [`Peer::from_websocket`] immediately?** Upstream [`chia_sdk_client::Peer`]'s background
/// reader routes `id: Some` wire messages through an outbound [`RequestMap`](chia_sdk_client::request_map::RequestMap).
/// Outbound [`GossipHandle::connect_to`](crate::service::gossip_handle::GossipHandle::connect_to) sends
/// [`RequestPeers`](chia_protocol::RequestPeers) with a non-`None` correlation id; the server must answer on the
/// **raw WebSocket** *before* handing the stream to `Peer::from_websocket`, or the reader errors with
/// [`ClientError::UnexpectedMessage`](chia_sdk_client::ClientError::UnexpectedMessage) (same lesson as
/// [`tests/common/wss_full_node.rs`](../../../tests/common/wss_full_node.rs) for CON-001).
async fn read_next_wire_message(
    ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> Result<Message, ClientError> {
    loop {
        let raw = ws.next().await.ok_or(ClientError::MissingHandshake)??;
        match raw {
            WsMsg::Binary(bin) => {
                return Message::from_bytes(&bin).map_err(ClientError::Streamable);
            }
            WsMsg::Ping(p) => {
                ws.send(WsMsg::Pong(p))
                    .await
                    .map_err(|e| ClientError::Io(std::io::Error::other(e.to_string())))?;
            }
            WsMsg::Close(_) => return Err(ClientError::MissingHandshake),
            _ => {}
        }
    }
}

async fn negotiate_inbound_over_ws(
    state: Arc<ServiceState>,
    remote_addr: SocketAddr,
    mut ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    peer_id: PeerId,
) -> Result<(), ClientError> {
    let opts: PeerOptions = state.config.peer_options;

    let first = tokio::time::timeout(INBOUND_HANDSHAKE_TIMEOUT, read_next_wire_message(&mut ws))
        .await
        .map_err(|_| {
            ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "inbound handshake timeout",
            ))
        })??;

    if first.msg_type != ProtocolMessageTypes::Handshake {
        return Err(ClientError::InvalidResponse(
            vec![ProtocolMessageTypes::Handshake],
            first.msg_type,
        ));
    }
    let their_handshake = Handshake::from_bytes(&first.data)?;
    let net = network_id_handshake_string(state.config.network_id);
    if their_handshake.network_id != net {
        return Err(ClientError::WrongNetwork(net, their_handshake.network_id));
    }

    let our_handshake = Handshake {
        network_id: net.clone(),
        protocol_version: HANDSHAKE_PROTOCOL_VERSION.to_string(),
        software_version: format!("dig-gossip/{}", env!("CARGO_PKG_VERSION")),
        server_port: listen_port_for_handshake(&state),
        node_type: NodeType::FullNode,
        capabilities: vec![
            (1, "1".to_string()),
            (2, "1".to_string()),
            (3, "1".to_string()),
        ],
    };
    let reply = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: our_handshake
            .to_bytes()
            .map_err(ClientError::Streamable)?
            .into(),
    };
    ws.send(WsMsg::Binary(
        reply.to_bytes().map_err(ClientError::Streamable)?,
    ))
    .await
    .map_err(|e| ClientError::Io(std::io::Error::other(e.to_string())))?;

    // CON-008 will sanitize; see module rustdoc.
    let _software_version_stored = their_handshake.software_version.clone();

    // CON-001 outbound `connect_to` issues `RequestPeers` immediately after the handshake exchange.
    let second = tokio::time::timeout(INBOUND_HANDSHAKE_TIMEOUT, read_next_wire_message(&mut ws))
        .await
        .map_err(|_| {
            ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "inbound RequestPeers timeout",
            ))
        })??;
    if second.msg_type == ProtocolMessageTypes::RequestPeers {
        let resp = RespondPeers::new(vec![]);
        let out = Message {
            msg_type: ProtocolMessageTypes::RespondPeers,
            id: second.id,
            data: resp.to_bytes().map_err(ClientError::Streamable)?.into(),
        };
        ws.send(WsMsg::Binary(
            out.to_bytes().map_err(ClientError::Streamable)?,
        ))
        .await
        .map_err(|e| ClientError::Io(std::io::Error::other(e.to_string())))?;
    }

    let ts = unix_secs_u64();
    let new_row = TimestampedPeerInfo::new(
        remote_addr.ip().to_string(),
        their_handshake.server_port,
        ts,
    );
    let src = our_listen_peer_info(&state);
    state
        .address_manager
        .add_to_new_table(std::slice::from_ref(&new_row), &src, 0);

    relay_new_peer_to_live_peers(&state, new_row).await?;

    let (peer, mut inbound_rx) = Peer::from_websocket(ws, opts)?;

    if let Ok(guard) = state.inbound_tx.lock() {
        if let Some(tx_b) = guard.as_ref() {
            let tx: broadcast::Sender<(PeerId, Message)> = tx_b.clone();
            let pid_task = peer_id;
            tokio::spawn(async move {
                while let Some(msg) = inbound_rx.recv().await {
                    let _ = tx.send((pid_task, msg));
                }
            });
        }
    }

    let meta = StubPeer {
        remote: remote_addr,
        node_type: their_handshake.node_type,
        is_outbound: false,
    };
    let mut peers = state
        .peers
        .lock()
        .map_err(|_| ClientError::Io(std::io::Error::from(std::io::ErrorKind::Other)))?;
    peers.insert(peer_id, PeerSlot::Live(LiveSlot { meta, peer }));
    drop(peers);

    state
        .total_connections
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Main accept loop: one OS listener, many spawned per-connection tasks (CON-002 acceptance matrix).
#[cfg(any(feature = "native-tls", feature = "rustls"))]
pub(crate) async fn accept_loop(
    state: Arc<ServiceState>,
    listener: TcpListener,
    stop: Arc<Notify>,
) {
    let tls_acceptor = match native_tls_acceptor(&state.tls) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(target: "dig_gossip::listener", "failed to build inbound TLS acceptor: {e}");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = stop.notified() => {
                tracing::debug!(target: "dig_gossip::listener", "stop notification received; exiting accept loop");
                break;
            }
            accept_res = listener.accept() => {
                let (tcp, remote_addr) = match accept_res {
                    Ok(x) => x,
                    Err(e) => {
                        if state.is_running() {
                            tracing::warn!(target: "dig_gossip::listener", "accept() error: {e}");
                        }
                        continue;
                    }
                };
                if !state.is_running() {
                    drop(tcp);
                    break;
                }
                let count = state
                    .peers
                    .lock()
                    .map(|g| g.len())
                    .unwrap_or(usize::MAX);
                if count >= state.config.max_connections {
                    drop(tcp);
                    continue;
                }
                let st = state.clone();
                let acc = tls_acceptor.clone();
                tokio::spawn(async move {
                    handle_inbound_native(st, tcp, remote_addr, acc).await;
                });
            }
        }
    }
}
