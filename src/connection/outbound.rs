//! Outbound peer establishment via `chia-sdk-client` TLS + WebSocket + Chia handshake.
//!
//! **Normative:** [CON-001](../../../docs/requirements/domains/connection/specs/CON-001.md) /
//! [NORMATIVE.md](../../../docs/requirements/domains/connection/NORMATIVE.md) — outbound MUST use
//! `connect_peer()` semantics (TLS connector, `Handshake`, `FullNode` peer validation, DIG
//! `network_id` as the Chia **string** field).
//!
//! ## Why this module exists (vs calling `chia_sdk_client::connect_peer` directly)
//!
//! Upstream [`chia_sdk_client::connect_peer`](https://docs.rs/chia-sdk-client/latest/chia_sdk_client/fn.connect_peer.html)
//! validates the handshake but **drops** the parsed [`Handshake`] and never exposes the remote TLS
//! **SubjectPublicKeyInfo** bytes. DIG [`PeerConnection`](crate::types::peer::PeerConnection) and
//! [`PeerId`](crate::types::peer::PeerId) (API-005) require:
//!
//! 1. Metadata from the responder’s [`Handshake`] (`protocol_version`, `software_version`, …).
//! 2. `PeerId = SHA256(remote SPKI DER)` via [`crate::types::peer::peer_id_from_tls_spki_der`].
//!
//! We therefore mirror the small `connect.rs` flow from `chia-sdk-client` **after** capturing
//! `remote_spki_der` from the pre-`Peer::from_websocket` [`WebSocketStream`] (see upstream
//! [`chia-sdk-client/src/connect.rs`](https://github.com/Chia-Network/chia-wallet-sdk) — keep in sync
//! when bumping `chia-sdk-client`).
//!
//! ## `network_id` typing
//!
//! [`crate::types::config::GossipConfig`] stores `network_id` as [`chia_protocol::Bytes32`]. Chia’s
//! wire [`Handshake::network_id`](chia_protocol::Handshake) is a [`String`]; the conventional
//! encoding is the **lowercase hex** of the 32 bytes (matches [`Bytes32`’s `Display`](chia_protocol::Bytes32)).
#![allow(clippy::result_large_err)]
// Upstream [`ClientError`] is wide; we propagate it verbatim per API-004 `GossipError::ClientError`.

use std::net::SocketAddr;

use chia_protocol::{Handshake, Message, NodeType, ProtocolMessageTypes};
use chia_ssl::ChiaCertificate;
use chia_traits::Streamable;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use chia_sdk_client::{ClientError, Peer, PeerOptions};

#[cfg(any(feature = "native-tls", feature = "rustls"))]
use chia_sdk_client::Connector;

/// Successful outbound dial: live [`Peer`], inbound wire channel, parsed remote handshake, SPKI DER.
///
/// `remote_spki_der` is the **SubjectPublicKeyInfo** raw bytes inside the peer’s leaf certificate
/// (same slice API-005 tests take from `x509-parser`).
pub struct OutboundConnectResult {
    pub peer: Peer,
    pub inbound_rx: mpsc::Receiver<Message>,
    pub their_handshake: Handshake,
    /// Raw SPKI DER bytes for [`crate::types::peer::peer_id_from_tls_spki_der`].
    pub remote_spki_der: Vec<u8>,
}

/// Build a TLS connector from persisted/generated [`ChiaCertificate`] (CON-001 / `tls.rs`).
///
/// **Feature gating:** matches dig-gossip STR-004 — prefer `native-tls` when both features are
/// enabled (default CI graph).
#[cfg(any(feature = "native-tls", feature = "rustls"))]
pub(crate) fn tls_connector_for_cert(cert: &ChiaCertificate) -> Result<Connector, ClientError> {
    #[cfg(feature = "native-tls")]
    {
        chia_sdk_client::create_native_tls_connector(cert)
    }
    #[cfg(all(feature = "rustls", not(feature = "native-tls")))]
    {
        chia_sdk_client::create_rustls_connector(cert)
    }
}

/// Map configured genesis id to the Chia handshake string (`Display` = hex).
pub(crate) fn network_id_handshake_string(network_id: chia_protocol::Bytes32) -> String {
    network_id.to_string()
}

/// Extract remote **SubjectPublicKeyInfo DER** before [`Peer::from_websocket`] consumes the stream.
///
/// **Rationale:** `Peer::from_websocket` splits the socket and spawns the reader; certificate
/// inspection must happen on the intact [`WebSocketStream`] returned from
/// `connect_async_tls_with_config`.
fn remote_spki_der_from_ws(
    ws: &WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> Result<Vec<u8>, ClientError> {
    match ws.get_ref() {
        #[cfg(feature = "native-tls")]
        MaybeTlsStream::NativeTls(tls) => {
            let cert = tls
                .get_ref()
                .peer_certificate()?
                .ok_or(ClientError::MissingHandshake)?;
            let der = cert.to_der()?;
            spki_der_from_leaf_cert_der(&der)
        }
        #[cfg(feature = "rustls")]
        MaybeTlsStream::Rustls(tls) => {
            let certs = tls
                .get_ref()
                .1
                .peer_certificates()
                .ok_or(ClientError::MissingHandshake)?;
            let first = certs.first().ok_or(ClientError::MissingHandshake)?;
            spki_der_from_leaf_cert_der(first.as_ref())
        }
        MaybeTlsStream::Plain(_) => Err(ClientError::UnsupportedTls),
        #[allow(unreachable_patterns)]
        _ => Err(ClientError::UnsupportedTls),
    }
}

fn spki_der_from_leaf_cert_der(der: &[u8]) -> Result<Vec<u8>, ClientError> {
    let (_, x509) = x509_parser::parse_x509_certificate(der).map_err(|e| {
        ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("peer x509 parse: {e}"),
        ))
    })?;
    Ok(x509.tbs_certificate.subject_pki.raw.to_vec())
}

/// Full outbound flow: WSS dial, capture SPKI, Chia handshake, return handles.
///
/// **Spec link:** CON-001 — equivalent to `connect_peer(network_id, connector, addr, options)` with
/// extra return data for DIG wrappers.
///
/// **TLS features:** requires `native-tls` and/or `rustls` on this crate (STR-004).
#[cfg(any(feature = "native-tls", feature = "rustls"))]
pub(crate) async fn connect_outbound_peer(
    network_id: String,
    connector: Connector,
    socket_addr: SocketAddr,
    options: PeerOptions,
) -> Result<OutboundConnectResult, ClientError> {
    let uri = format!("wss://{socket_addr}/ws");
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
        uri.as_str(),
        None,
        false,
        Some(connector),
    )
    .await?;

    let remote_spki_der = remote_spki_der_from_ws(&ws)?;
    let (peer, mut receiver) = Peer::from_websocket(ws, options)?;

    peer.send(Handshake {
        network_id: network_id.clone(),
        protocol_version: "0.0.37".to_string(),
        software_version: "0.0.0".to_string(),
        server_port: 0,
        node_type: NodeType::Wallet,
        capabilities: vec![
            (1, "1".to_string()),
            (2, "1".to_string()),
            (3, "1".to_string()),
        ],
    })
    .await?;

    let Some(message) = receiver.recv().await else {
        return Err(ClientError::MissingHandshake);
    };

    if message.msg_type != ProtocolMessageTypes::Handshake {
        return Err(ClientError::InvalidResponse(
            vec![ProtocolMessageTypes::Handshake],
            message.msg_type,
        ));
    }

    let handshake = Handshake::from_bytes(&message.data)?;

    if handshake.node_type != NodeType::FullNode {
        return Err(ClientError::WrongNodeType(
            NodeType::FullNode,
            handshake.node_type,
        ));
    }

    if handshake.network_id != network_id {
        return Err(ClientError::WrongNetwork(network_id, handshake.network_id));
    }

    Ok(OutboundConnectResult {
        peer,
        inbound_rx: receiver,
        their_handshake: handshake,
        remote_spki_der,
    })
}
