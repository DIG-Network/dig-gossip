//! Introducer WebSocket client — **DSC-004** query and (future) **DSC-005** registration.
//!
//! # Requirements
//!
//! - **DSC-004** — [`docs/requirements/domains/discovery/specs/DSC-004.md`](../../../docs/requirements/domains/discovery/specs/DSC-004.md):
//!   connect with mutual TLS, complete the Chia [`Handshake`](chia_protocol::Handshake), send
//!   [`RequestPeersIntroducer`](chia_protocol::RequestPeersIntroducer), await
//!   [`RespondPeersIntroducer`](chia_protocol::RespondPeersIntroducer), return `peer_list`.
//! - **NORMATIVE:** [`NORMATIVE.md`](../../../docs/requirements/domains/discovery/NORMATIVE.md).
//! - **API-002 / SPEC §3.3:** [`GossipHandle::discover_from_introducer`](crate::service::gossip_handle::GossipHandle::discover_from_introducer)
//!   delegates here when [`crate::types::config::IntroducerConfig::endpoint`] is set.
//!
//! # Design decisions
//!
//! - **Mirror `chia_sdk_client::connect_peer` handshake:** Upstream
//!   [`connect_peer`](chia_sdk_client::connect_peer) only accepts a [`std::net::SocketAddr`].
//!   Introducers advertise a full `wss://…/ws` URL ([`IntroducerConfig::endpoint`](crate::types::config::IntroducerConfig)),
//!   so we call [`Peer::connect_full_uri`](chia_sdk_client::Peer::connect_full_uri) then replay the same
//!   outbound [`Handshake`] + FullNode validation as `vendor/chia-sdk-client/src/connect.rs` —
//!   any drift vs upstream should be fixed in lockstep when bumping `chia-sdk-client`.
//! - **Whole-operation timeout:** DSC-004 requires one timeout covering connect + handshake + RPC.
//!   We wrap the async block in [`tokio::time::timeout`]; on expiry we return
//!   [`GossipError::IntroducerError`](crate::error::GossipError::IntroducerError) with a stable substring
//!   so tests can distinguish timeout from transport failures.
//! - **TLS feature gate:** Without `native-tls` / `rustls`, [`Peer::connect_full_uri`] does not exist;
//!   [`IntroducerClient::query_peers`] returns [`GossipError::ClientError`](crate::error::GossipError::ClientError)
//!   (`UnsupportedTls`) so `--no-default-features` builds remain coherent.

use std::time::Duration;

use chia_protocol::{Bytes32, Handshake, NodeType, ProtocolMessageTypes, TimestampedPeerInfo};

use crate::discovery::introducer_wire::{RequestPeersIntroducer, RespondPeersIntroducer};
use chia_sdk_client::{load_ssl_cert, ClientError, Peer, PeerOptions};
use chia_ssl::ChiaCertificate;
use chia_traits::Streamable;

use crate::connection::handshake::ADVERTISED_PROTOCOL_VERSION;
#[cfg(any(feature = "native-tls", feature = "rustls"))]
use crate::connection::outbound::{network_id_handshake_string, tls_connector_for_cert};
use crate::error::GossipError;

/// Introducer RPC façade — today only **DSC-004** [`IntroducerClient::query_peers`].
///
/// **Why a unit type:** DSC-005 will add `register_with_introducer` helpers on the same type so
/// `GossipHandle` and the discovery loop share one module-level entry point (matches the spec’s
/// `IntroducerClient` naming without forcing stateful handles before DSC-006).
#[derive(Debug, Default, Clone, Copy)]
pub struct IntroducerClient;

impl IntroducerClient {
    /// Query an introducer for its peer list (DSC-004).
    ///
    /// # Arguments
    ///
    /// * `wss_uri` — full WebSocket URI (`wss://host:port/ws`, …) from [`IntroducerConfig::endpoint`](crate::types::config::IntroducerConfig).
    /// * `local_certificate` — this node’s TLS identity (mutual TLS with the introducer).
    /// * `network_id` — DIG genesis id; encoded for the Chia handshake string via [`network_id_handshake_string`].
    /// * `peer_options` — forwarded to [`Peer::connect_full_uri`](chia_sdk_client::Peer::connect_full_uri) (rate limits, etc.).
    /// * `operation_timeout` — hard cap for **connect + handshake + introducer request** (DSC-004 acceptance).
    ///
    /// # Returns
    ///
    /// * `Ok(peer_list)` — possibly **empty** (valid introducer response).
    /// * `Err(GossipError::IntroducerError { timeout })` — deadline exceeded.
    /// * `Err(GossipError::ClientError(_))` — TLS / WebSocket / wire errors from `chia-sdk-client`.
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    pub async fn query_peers(
        wss_uri: &str,
        local_certificate: &ChiaCertificate,
        network_id: Bytes32,
        peer_options: PeerOptions,
        operation_timeout: Duration,
    ) -> Result<Vec<TimestampedPeerInfo>, GossipError> {
        let network_string = network_id_handshake_string(network_id);

        let work = async {
            let connector = tls_connector_for_cert(local_certificate)?;
            let (peer, mut receiver) =
                Peer::connect_full_uri(wss_uri, connector, peer_options).await?;

            peer.send(Handshake {
                network_id: network_string.clone(),
                protocol_version: ADVERTISED_PROTOCOL_VERSION.to_string(),
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

            if handshake.network_id != network_string {
                return Err(ClientError::WrongNetwork(
                    network_string,
                    handshake.network_id,
                ));
            }

            let response: RespondPeersIntroducer = peer
                .request_infallible(RequestPeersIntroducer::new())
                .await?;

            Ok(response.peer_list)
        };

        match tokio::time::timeout(operation_timeout, work).await {
            Ok(inner) => inner.map_err(GossipError::from),
            Err(_) => Err(GossipError::IntroducerError(
                "introducer query timed out".into(),
            )),
        }
    }

    /// TLS-disabled builds cannot dial introducers — fail fast with the same error shape other
    /// transports use when TLS is unavailable.
    #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
    pub async fn query_peers(
        _wss_uri: &str,
        _local_certificate: &ChiaCertificate,
        _network_id: Bytes32,
        _peer_options: PeerOptions,
        _operation_timeout: Duration,
    ) -> Result<Vec<TimestampedPeerInfo>, GossipError> {
        Err(ClientError::UnsupportedTls.into())
    }
}

/// Load node TLS material for introducer dials — thin wrapper so call sites share [`load_ssl_cert`]
/// error mapping with [`crate::service::gossip_service::GossipService::new`].
pub(crate) fn load_local_certificate_for_introducer(
    cert_path: &str,
    key_path: &str,
) -> Result<ChiaCertificate, GossipError> {
    load_ssl_cert(cert_path, key_path).map_err(|e| match e {
        ClientError::Io(io) => GossipError::IoError(io.to_string()),
        other => other.into(),
    })
}
