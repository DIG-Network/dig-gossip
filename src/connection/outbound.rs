//! Outbound peer establishment via `chia-sdk-client` TLS + WebSocket + Chia handshake.
//!
//! ## SPEC traceability
//!
//! - **SPEC §5.1** — full outbound connection sequence:
//!   1. Load TLS cert via `load_ssl_cert()` / `ChiaCertificate::generate()`
//!   2. Create connector via `create_native_tls_connector()` or `create_rustls_connector()`
//!   3. Call `connect_peer(network_id, connector, socket_addr, options)`
//!   4. Wrap in `PeerConnection` with gossip metadata
//!   5. Add peer to address manager
//!   6. Send `RequestPeers` for discovery (`node_discovery.py:135-136`)
//!   7. Spawn per-connection message loop task
//! - **SPEC §5.3** — mandatory mutual TLS via `chia-ssl`: both sides present certificates,
//!   `PeerId = SHA256(remote_TLS_certificate_public_key)`.
//! - **SPEC §1.5 #1** — handshake with capabilities via `connect_peer()`.
//! - **SPEC §1.6 #1** — peer exchange on outbound connect: after connecting, send
//!   `RequestPeers` to discover more peers (`node_discovery.py:135-136`).
//! - **SPEC §1.4** — `Handshake`, `Message`, `NodeType` used directly from `chia-protocol`.
//!
//! **Normative:** [CON-001](../../../docs/requirements/domains/connection/specs/CON-001.md) /
//! [NORMATIVE.md](../../../docs/requirements/domains/connection/NORMATIVE.md) — outbound MUST use
//! `connect_peer()` semantics (TLS connector, `Handshake`, `FullNode` peer validation, DIG
//! `network_id` as the Chia **string** field).
//!
//! ## Why this module exists (vs calling `dig_protocol::connect_peer` directly)
//!
//! Upstream [`dig_protocol::connect_peer`](https://docs.rs/chia-sdk-client/latest/chia_sdk_client/fn.connect_peer.html)
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
//! [`crate::types::config::GossipConfig`] stores `network_id` as [`dig_protocol::Bytes32`]. Chia’s
//! wire [`Handshake::network_id`](chia_protocol::Handshake) is a [`String`]; the conventional
//! encoding is the **lowercase hex** of the 32 bytes (matches [`Bytes32`’s `Display`](dig_protocol::Bytes32)).
#![allow(clippy::result_large_err)]
// Upstream [`ClientError`] is wide; we propagate it verbatim per API-004 `GossipError::ClientError`.

use std::net::SocketAddr;

use dig_protocol::ChiaCertificate;
use dig_protocol::Streamable;
use dig_protocol::{Handshake, Message, NodeType, ProtocolMessageTypes};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use dig_protocol::{ClientError, Peer, PeerOptions};

use crate::connection::handshake::{validate_remote_handshake, ADVERTISED_PROTOCOL_VERSION};

#[cfg(any(feature = "native-tls", feature = "rustls"))]
use dig_protocol::Connector;

/// Successful outbound dial: live [`Peer`], inbound wire channel, parsed remote handshake, SPKI DER.
///
/// SPEC §5.1 step 4 — "Wrap in PeerConnection with gossip metadata." This struct carries
/// the raw materials needed to build a [`crate::types::peer::PeerConnection`].
/// SPEC §5.3 — `remote_spki_der` enables `PeerId = SHA256(remote SPKI DER)`.
///
/// `remote_spki_der` is the **SubjectPublicKeyInfo** raw bytes inside the peer’s leaf certificate
/// (same slice API-005 tests take from `x509-parser`).
pub struct OutboundConnectResult {
    pub peer: Peer,
    pub inbound_rx: mpsc::Receiver<Message>,
    pub their_handshake: Handshake,
    /// Raw SPKI DER bytes for [`crate::types::peer::peer_id_from_tls_spki_der`].
    pub remote_spki_der: Vec<u8>,
    /// CON-003 / **CON-008**: [`Handshake::software_version`] after Cc/Cf sanitization via
    /// [`validate_remote_handshake`](crate::connection::handshake::validate_remote_handshake) — same
    /// string stored on the live peer slot (`remote_software_version_sanitized`, see `tests/con_008_tests.rs`).
    pub remote_software_version_sanitized: String,
}

/// Build a TLS connector from persisted/generated [`ChiaCertificate`] (CON-001 / `tls.rs`).
///
/// SPEC §5.1 step 2 — "Create connector via `create_native_tls_connector()` or
/// `create_rustls_connector()`."
/// SPEC §5.3 — "Outbound mTLS: `create_native_tls_connector()` or `create_rustls_connector()`
/// creates a TLS connector that includes the node's own certificate (client cert) for mutual
/// authentication. This connector is passed to `connect_peer()`."
/// SPEC §1.5 #3 — TLS mutual authentication via `chia-ssl`.
///
/// **Feature gating:** matches dig-gossip STR-004 — prefer `native-tls` when both features are
/// enabled (default CI graph).
#[cfg(any(feature = "native-tls", feature = "rustls"))]
pub(crate) fn tls_connector_for_cert(cert: &ChiaCertificate) -> Result<Connector, ClientError> {
    #[cfg(feature = "native-tls")]
    {
        dig_protocol::create_native_tls_connector(cert)
    }
    #[cfg(all(feature = "rustls", not(feature = "native-tls")))]
    {
        dig_protocol::create_rustls_connector(cert)
    }
}

/// Map configured genesis id to the Chia handshake string (`Display` = hex).
pub(crate) fn network_id_handshake_string(network_id: dig_protocol::Bytes32) -> String {
    network_id.to_string()
}

/// Extract remote **SubjectPublicKeyInfo DER** before [`Peer::from_websocket`] consumes the stream.
///
/// SPEC §5.3 — "Peer identity from mTLS: `PeerId = SHA256(remote_TLS_certificate_public_key)`."
/// Because mTLS guarantees both sides present certificates, each side can derive the other's
/// `PeerId` from the certificate exchanged during the TLS handshake. Matches Chia's
/// `peer_node_id` derivation from certificate hash (`ws_connection.py:95`).
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

/// Reused by CON-002 inbound TLS (server-side peer cert) and outbound SPKI capture (CON-001).
pub(crate) fn spki_der_from_leaf_cert_der(der: &[u8]) -> Result<Vec<u8>, ClientError> {
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
/// SPEC §5.1 — outbound connection via `connect_peer()`:
///   step 1: TLS cert loaded before this call;
///   step 2: connector passed in;
///   step 3: WSS dial + handshake exchange;
///   step 4-7: caller wraps result, adds to address manager, sends `RequestPeers`, spawns loop.
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

    // SPEC §5.1 step 3 — "Sends chia-protocol::Handshake with DIG network_id."
    // SPEC §1.5 #1 — "connect_peer() sends chia-protocol::Handshake with capabilities list."
    // SPEC §1.4 — Handshake type used directly from chia-protocol (not redefined).
    peer.send(Handshake {
        network_id: network_id.clone(),
        protocol_version: ADVERTISED_PROTOCOL_VERSION.to_string(),
        software_version: "0.0.0".to_string(),
        server_port: 0,
        node_type: NodeType::Wallet,
        capabilities: vec![
            (1, "1".to_string()), // SPEC §1.5 #1 — BASE protocol capability
            (2, "1".to_string()), // BLOCK_HEADERS capability
            (3, "1".to_string()), // RATE_LIMITS_V2 capability
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

    let remote_software_version_sanitized =
        validate_remote_handshake(&handshake, &network_id).map_err(ClientError::from)?;

    Ok(OutboundConnectResult {
        peer,
        inbound_rx: receiver,
        their_handshake: handshake,
        remote_spki_der,
        remote_software_version_sanitized,
    })
}
