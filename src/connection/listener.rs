//! Inbound P2P acceptance: [`tokio::net::TcpListener`] -> TLS -> WebSocket -> [`dig_protocol::Peer`].
//!
//! ## SPEC traceability
//!
//! - **SPEC §5.2** — full inbound connection sequence:
//!   1. `TcpListener::accept()`
//!   2. TLS handshake (using `chia-ssl` certificate)
//!   3. `tokio_tungstenite::accept_async()`
//!   4. `Peer::from_websocket(ws, options)`
//!   5. Receive Handshake, validate `network_id`
//!   6. Send Handshake response
//!   7. Wrap in `PeerConnection`
//!   8. Add to address manager "new" table (`node_discovery.py:120-125`)
//!   9. Relay peer info (`node_discovery.py:126-127`)
//! - **SPEC §5.3** — mandatory mutual TLS (mTLS) via `chia-ssl`:
//!   "ALL peer-to-peer connections MUST use mutual TLS. Both client and server present
//!   certificates." Matches Chia `server.py:54-71`, `server.py:67 verify_mode = ssl.CERT_REQUIRED`.
//! - **SPEC §1.7 #4** — "Inbound connection listener": `chia-sdk-client`'s `Peer` only does
//!   outbound connections; we add a `TcpListener` accepting inbound.
//! - **SPEC §1.6 #2** — "Inbound peer relay": when an inbound connection arrives, add peer
//!   to address manager and relay to other peers (`node_discovery.py:112-127`).
//! - **SPEC §1.5 #8** — peer ban/trust: `ClientState::ban()` / `is_banned()` checked before
//!   accepting inbound connections.
//!
//! **Normative:** [CON-002](../../../docs/requirements/domains/connection/specs/CON-002.md) /
//! [NORMATIVE.md](../../../docs/requirements/domains/connection/NORMATIVE.md).
//!
//! ## Why this is not `dig_protocol::connect_peer`
//!
//! Upstream [`Peer`](dig_protocol::Peer) is built for **outbound** `wss://` clients. DIG must
//! **listen** on [`crate::types::config::GossipConfig::listen_addr`], terminate TLS with the node
//! [`dig_protocol::ChiaCertificate`], run [`tokio_tungstenite::accept_async`], then call
//! [`Peer::from_websocket`](dig_protocol::Peer::from_websocket) — mirroring the pseudo-code in
//! CON-002 and [`SPEC.md`](../../../docs/resources/SPEC.md) §5.2.
//!
//! ## TLS backends (STR-004)
//!
//! - **`native-tls` (default):** [`native_tls::TlsAcceptor`] + [`tokio_native_tls`], matching
//!   CON-001 integration tests ([`tests/common/wss_full_node.rs`](../../../tests/common/wss_full_node.rs)).
//! - **`rustls` without `native-tls` (outbound):** [`chia_sdk_client`] uses rustls for `wss://` dials.
//!   **Inbound** still uses [`native_tls::TlsAcceptor`] so [`MaybeTlsStream::NativeTls`] matches
//!   [`Peer::from_websocket`] (upstream only types **client** `MaybeTlsStream::Rustls`).
//! - **CON-009 (mTLS):** On **Linux / non-Apple Unix** (OpenSSL-backed `native-tls`), we use a
//!   **vendored** [`native-tls`](../../../vendor/native-tls/README.dig-gossip.md) fork that sets
//!   `CERT_REQUIRED` + Chia CA trust (Chia `server.py:67`). **Windows (SChannel)** and **macOS
//!   (SecureTransport)** often hide the peer leaf from `peer_certificate()` even for legitimate
//!   mutual TLS sessions, so we retain a **fallback** to [`peer_id_for_addr`] there (CON-002 / dev
//!   ergonomics) while OpenSSL-backed production Linux gets strict SPKI binding.
//!
//! ## `software_version` sanitization (CON-003 / CON-008)
//!
//! Inbound path calls [`crate::connection::handshake::validate_remote_handshake`] before the
//! Handshake reply; the returned string is stored on the live peer slot’s
//! `remote_software_version_sanitized` field ([`crate::service::state::LiveSlot`]). **CON-008** is verified by
//! `tests/con_008_tests.rs` (matrix + “matches Chia category policy”); **CON-003** adds protocol /
//! network gates around the same helper (`tests/con_003_tests.rs`).

// CON-002: Large `ClientError` payloads are intentional — they propagate upstream
// `chia_sdk_client` variants verbatim, matching the API-004 `GossipError::ClientError` wrapper.
#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dig_protocol::{
    Handshake, Message, NodeType, ProtocolMessageTypes, RespondPeers, TimestampedPeerInfo,
};
use dig_protocol::{ClientError, Peer, PeerOptions};
use dig_protocol::ChiaCertificate;
use dig_protocol::Streamable;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::sync::Notify;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tokio_tungstenite::{accept_async, MaybeTlsStream, WebSocketStream};

use crate::connection::handshake::ADVERTISED_PROTOCOL_VERSION;
use crate::connection::outbound::{network_id_handshake_string, spki_der_from_leaf_cert_der};
use crate::service::state::{
    apply_inbound_rate_limit_violation, peer_id_for_addr, record_live_peer_inbound_bytes,
    record_live_peer_outbound_bytes, LiveSlot, PeerSlot, ServiceState, StubPeer,
};
use crate::types::peer::{
    message_wire_len, metric_unix_timestamp_secs, peer_id_from_tls_spki_der,
    PeerConnectionWireMetrics, PeerId, PeerInfo,
};

/// Maximum time we wait for the remote peer to send a [`ProtocolMessageTypes::Handshake`]
/// message before we abort the inbound session.
///
/// **Spec:** CON-002 notes — "If the remote does not complete the handshake within a reasonable
/// time, drop the session." 30 seconds aligns with Chia `full_node_server.py` behavior.
///
/// **Security:** prevents slow-loris style attacks where an adversary opens a TLS connection
/// but never completes the application-level handshake, tying up a slot in
/// [`ServiceState::peers`](crate::service::state::ServiceState).
const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Inbound TLS (`native_tls::TlsAcceptor`) — used for **both** `native-tls` and `rustls` features.
//
// Why `native_tls` for *inbound* even when `rustls` is enabled:
// Upstream `dig_protocol::Peer::from_websocket` types the stream as
// `MaybeTlsStream::NativeTls` on the server side. The `rustls` feature only
// affects *outbound* dialing (CON-001). Using `native_tls` here keeps the
// type system happy without forking upstream abstractions. See module-level
// doc § "TLS backends (STR-004)" for the full story.
// ---------------------------------------------------------------------------

#[cfg(any(feature = "native-tls", feature = "rustls"))]
use native_tls::Identity;
#[cfg(any(feature = "native-tls", feature = "rustls"))]
use tokio_native_tls::TlsAcceptor as TokioNativeTlsAcceptor;

/// Build a [`TokioNativeTlsAcceptor`] from the node's [`ChiaCertificate`] (PEM key + cert).
///
/// SPEC §5.3 — "Certificate management: exclusively via `chia-ssl`. `ChiaCertificate::generate()`
/// creates new node certificates on first run. `load_ssl_cert()` loads existing certificates."
/// See also SPEC §1.5 #3 — TLS mutual authentication via `chia-ssl`.
///
/// **CON-009 (OpenSSL targets):** this crate patches crates.io `native-tls` (see
/// `vendor/native-tls/README.dig-gossip.md`) so the OpenSSL server acceptor sets **client certificate
/// required** + Chia CA trust — matching Chia `server.py:67` (`CERT_REQUIRED`).
///
/// This is the **server-side** TLS identity used when accepting inbound connections on
/// [`crate::types::config::GossipConfig::listen_addr`]. The certificate is typically generated
/// by [`chia_ssl`] at node startup (API-001 lifecycle) and stored in
/// [`ServiceState::tls`](crate::service::state::ServiceState).
///
/// # Errors
///
/// Returns [`ClientError::Io`] if the PEM material cannot be parsed into a PKCS#8 identity
/// or if the platform TLS library rejects the certificate (e.g., expired, unsupported algo).
#[cfg(any(feature = "native-tls", feature = "rustls"))]
fn native_tls_acceptor(cert: &ChiaCertificate) -> Result<TokioNativeTlsAcceptor, ClientError> {
    // PKCS#8 is the Chia default PEM format produced by `dig_protocol::ChiaCertificate`.
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

/// Extract the remote peer's **SubjectPublicKeyInfo** (SPKI) DER bytes from a server-side
/// `native_tls` TLS stream after the TLS handshake completes.
///
/// SPEC §5.3 — "Peer identity from mTLS: `PeerId = SHA256(remote_TLS_certificate_public_key)`."
/// Matches Chia's `peer_node_id` derivation from certificate hash (`ws_connection.py:95`).
///
/// The SPKI is the raw ASN.1 blob containing the peer's public key algorithm + key material.
/// We feed it into [`peer_id_from_tls_spki_der`] to derive the deterministic [`PeerId`]
/// (SHA-256 of the SPKI DER — see API-005 / API-007).
///
/// # Errors
///
/// - [`ClientError::MissingHandshake`] — the remote did not present a client certificate, or the
///   OS TLS stack cannot expose it. On **Windows** the caller may fall back to [`peer_id_for_addr`]
///   (see [`handle_inbound_native_inner`]); on **OpenSSL** backends anonymous clients fail earlier.
/// - [`ClientError::Io`] — the leaf cert DER could not be extracted or parsed.
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
    // Delegate to shared helper also used by outbound CON-001 SPKI capture.
    spki_der_from_leaf_cert_der(&der)
}

/// Top-level wrapper for a single inbound connection attempt using `native_tls`.
///
/// This is the entry point spawned by [`accept_loop`] for each accepted TCP connection.
/// It delegates to [`handle_inbound_native_inner`] and catches any errors, logging them
/// at `debug` level. Errors here are **expected** for normal rejections (banned peers,
/// duplicate connections, TLS failures) — they do not indicate bugs.
///
/// # Arguments
///
/// - `state` — shared [`ServiceState`] holding peer map, ban list, config, and TLS identity.
/// - `tcp` — the raw TCP stream from `TcpListener::accept()`, before TLS negotiation.
/// - `remote_addr` — the peer's socket address as reported by the OS.
/// - `acceptor` — the pre-built [`TokioNativeTlsAcceptor`] from [`native_tls_acceptor`].
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

/// Inner implementation of the inbound connection pipeline using `native_tls`.
///
/// **CON-002 acceptance flow (in order):**
///
/// 1. **TLS accept** — negotiate server-side TLS with the node's [`ChiaCertificate`].
/// 2. **SPKI extraction** — read the remote peer's leaf certificate to derive [`PeerId`] (CON-009).
///    Windows-only: may fall back to [`peer_id_for_addr`] when SChannel hides the leaf.
/// 3. **Self-connection guard** — reject if the derived `peer_id` matches our own
///    [`GossipConfig::peer_id`](crate::types::config::GossipConfig::peer_id).
/// 4. **Ban check** — reject peers in the [`ServiceState::banned`] set.
/// 5. **Duplicate check** — reject peers already present in [`ServiceState::peers`].
/// 6. **WebSocket upgrade** — [`accept_async`] over the TLS stream.
/// 7. **Chia handshake** — delegated to [`negotiate_inbound_over_ws`].
///
/// # Errors
///
/// Any failure returns [`ClientError`]; the outer [`handle_inbound_native`] logs and drops it.
#[cfg(any(feature = "native-tls", feature = "rustls"))]
async fn handle_inbound_native_inner(
    state: Arc<ServiceState>,
    tcp: TcpStream,
    remote_addr: SocketAddr,
    acceptor: TokioNativeTlsAcceptor,
) -> Result<(), ClientError> {
    // Early exit: no point doing TLS if the service is shutting down.
    if !state.is_running() {
        return Ok(());
    }

    // Step 1: TLS accept — negotiate server-side TLS.
    let tls = acceptor
        .accept(tcp)
        .await
        .map_err(|e| ClientError::Io(std::io::Error::other(format!("tls accept: {e}"))))?;

    // Step 2: Derive PeerId from the remote's TLS certificate SPKI (CON-009 / API-005).
    //
    // **OpenSSL (Linux, etc.):** vendored `native-tls` requires a client cert; missing SPKI after
    // a successful accept is unexpected. **Windows (SChannel):** `peer_certificate()` may be
    // `None` even for legitimate Chia peers — keep the historical `peer_id_for_addr` fallback so
    // CON-002 integration tests and developer laptops keep working (see module TLS note above).
    let peer_id = match remote_spki_from_native_tls_stream(&tls) {
        Ok(spki) => peer_id_from_tls_spki_der(&spki),
        Err(e) => {
            if cfg!(target_os = "windows") || cfg!(target_vendor = "apple") {
                tracing::warn!(
                    target: "dig_gossip::listener",
                    "no remote TLS leaf cert after accept (non-OpenSSL native-tls); using peer_id_for_addr fallback: {e}"
                );
                peer_id_for_addr(remote_addr)
            } else {
                return Err(e);
            }
        }
    };

    // Step 3: Self-connection guard — SPEC §4 `GossipError::SelfConnection`.
    // Chia `full_node_server.py` drops connections to self.
    if peer_id == state.config.peer_id {
        return Err(ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "inbound self-connection (remote PeerId equals local config.peer_id)",
        )));
    }

    // CON-007: expire timed bans before the lookup so a peer can reconnect exactly when `until`
    // elapses (inclusive boundary, same as [`PeerReputation::refresh_ban_status`]).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    state.prune_expired_dig_bans(now).await;

    // Step 4: Ban check — reject peers penalized past the threshold (CON-007 / API-006).
    if state
        .banned
        .lock()
        .map_err(|_| ClientError::Io(std::io::Error::from(std::io::ErrorKind::Other)))?
        .contains_key(&peer_id)
    {
        return Err(ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "inbound peer is banned",
        )));
    }

    // Step 5: Duplicate check — only one slot per PeerId in the peer map.
    // The lock scope is intentionally narrow to avoid holding it across async points.
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

    // Step 6: WebSocket upgrade over the now-established TLS stream.
    // We wrap the `native_tls` stream in `MaybeTlsStream::NativeTls` so the type matches
    // what `Peer::from_websocket` expects downstream.
    let ws = accept_async(MaybeTlsStream::NativeTls(tls))
        .await
        .map_err(ws_err)?;

    // Step 7: Chia handshake negotiation, address-manager registration, peer insertion.
    negotiate_inbound_over_ws(state, remote_addr, ws, peer_id).await
}

// ---------------------------------------------------------------------------
// Shared WebSocket + Chia handshake helpers
//
// These utility functions are used by `negotiate_inbound_over_ws` and
// `relay_new_peer_to_live_peers`. They are feature-gate-independent because
// the WebSocket + Handshake layer sits above TLS.
// ---------------------------------------------------------------------------

/// Convert a [`tokio_tungstenite`] WebSocket error into [`ClientError::Io`].
///
/// The string conversion loses the original error type, but `ClientError` does not have a
/// dedicated WebSocket variant, and we only need the message for diagnostic logging.
fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> ClientError {
    ClientError::Io(std::io::Error::other(e.to_string()))
}

/// Resolve the **advertised listen port** for our outbound [`Handshake::server_port`] field.
///
/// Prefers the OS-assigned bound address (populated after `TcpListener::bind` in [`accept_loop`])
/// over the configured address. This matters when `listen_addr` uses port `0` (OS picks an
/// ephemeral port) — tests rely on this to avoid port conflicts.
fn listen_port_for_handshake(state: &ServiceState) -> u16 {
    state
        .listen_bound_addr
        .lock()
        .ok()
        .and_then(|g| *g)
        .map(|a| a.port())
        .unwrap_or_else(|| state.config.listen_addr.port())
}

/// Build the [`PeerInfo`] representing **our own** listener endpoint.
///
/// Used as the `source` parameter when adding the inbound peer to the
/// [`AddressManager`](crate::discovery::address_manager::AddressManager) new-table
/// (Chia `address_manager.py:add_to_new_table` convention — the source is the node
/// that told us about the peer, which for inbound connections is ourselves).
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

/// Current wall-clock time as seconds since the Unix epoch.
///
/// Used for [`TimestampedPeerInfo`] timestamps when registering inbound peers in the
/// address manager. Falls back to `0` if the system clock is before the epoch (should
/// never happen in practice).
fn unix_secs_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Relay the inbound peer’s [`TimestampedPeerInfo`] to every **existing** live connection (CON-002 Peer Info Relay).
///
/// SPEC §1.6 #2 — "Inbound peer relay: When an inbound connection arrives, add peer to
/// address manager and relay to other peers" (`node_discovery.py:112-127`).
/// SPEC §1.1 — "Peer sharing via gossip": connected peers exchange peer lists periodically
/// via `chia-protocol`’s `RequestPeers`/`RespondPeers`.
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
/// **Why defer `Peer::from_websocket` until after one `RequestPeers` on the raw socket?** The first
/// outbound packet from [`GossipHandle::connect_to`](crate::service::gossip_handle::GossipHandle::connect_to)
/// may arrive before our `Peer` reader task exists, so we answer that **initial** probe on the raw
/// WebSocket. Later [`RequestPeers`](chia_protocol::RequestPeers) keepalives use the vendored
/// [`chia_sdk_client`] patch (`vendor/chia-sdk-client`): inbound `RequestPeers` is forwarded to the
/// application and answered with [`Peer::send_protocol_message`](dig_protocol::Peer::send_protocol_message).
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

/// Perform the Chia application-level handshake over an already-upgraded WebSocket,
/// register the peer in the address manager, and insert a [`LiveSlot`] into the peer map.
///
/// This is the **server-side** counterpart to the outbound handshake in
/// [`crate::connection::outbound::connect_outbound_peer`]. The sequence is:
///
/// 1. **Receive remote Handshake** — with [`INBOUND_HANDSHAKE_TIMEOUT`].
/// 2. **Validate** via [`crate::connection::handshake::validate_remote_handshake`] (CON-003).
/// 3. **Send our Handshake reply** — advertises [`ADVERTISED_PROTOCOL_VERSION`] and `FullNode` type.
/// 4. **Receive and answer `RequestPeers`** — outbound peers issue this immediately (CON-001).
/// 5. **Address manager insert** — add the newcomer to the new-table (DSC-001 bucketing).
/// 6. **Relay** — push the newcomer's `TimestampedPeerInfo` to all existing live peers.
/// 7. **Upgrade to `Peer`** — hand off to [`Peer::from_websocket`] for the steady-state reader.
/// 8. **Bridge inbound messages** — spawn a task that forwards wire messages into the
///    [`ServiceState::inbound_tx`] broadcast channel (API-002 event bus).
/// 9. **Insert `LiveSlot`** — the peer is now fully registered and visible to `peer_count`, etc.
/// 10. **Spawn keepalive** — [`crate::connection::keepalive::spawn_keepalive_task`] (CON-004).
///
/// # Arguments
///
/// - `state` — shared service state.
/// - `remote_addr` — the peer's TCP socket address.
/// - `ws` — the WebSocket stream (already TLS-upgraded).
/// - `peer_id` — the [`PeerId`] derived from the remote's TLS certificate SPKI.
///
/// # Errors
///
/// Returns [`ClientError`] for handshake timeouts, validation failures, or WebSocket errors.
/// The peer map is not modified if this function returns `Err`.
async fn negotiate_inbound_over_ws(
    state: Arc<ServiceState>,
    remote_addr: SocketAddr,
    mut ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    peer_id: PeerId,
) -> Result<(), ClientError> {
    let opts: PeerOptions = state.config.peer_options;

    // --- Phase 1: Receive the remote's Handshake (with timeout) ---
    let first = tokio::time::timeout(INBOUND_HANDSHAKE_TIMEOUT, read_next_wire_message(&mut ws))
        .await
        .map_err(|_| {
            ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "inbound handshake timeout",
            ))
        })??;

    // The first application message MUST be a Handshake; anything else is a protocol violation.
    if first.msg_type != ProtocolMessageTypes::Handshake {
        return Err(ClientError::InvalidResponse(
            vec![ProtocolMessageTypes::Handshake],
            first.msg_type,
        ));
    }
    let their_handshake = Handshake::from_bytes(&first.data)?;

    // --- Phase 2: CON-003 validation (network id, protocol version, software version) ---
    let net = network_id_handshake_string(state.config.network_id);
    let remote_software_version_sanitized =
        crate::connection::handshake::validate_remote_handshake(&their_handshake, &net)
            .map_err(ClientError::from)?;
    let remote_protocol_version = their_handshake.protocol_version.clone();

    // --- Phase 3: Send our Handshake reply ---
    // We advertise as FullNode with standard Chia capabilities (BASE=1, BLOCK_HEADERS=1, RATE_LIMITS=1).
    // The `server_port` tells the remote peer what port to dial us back on.
    let our_handshake = Handshake {
        network_id: net.clone(),
        protocol_version: ADVERTISED_PROTOCOL_VERSION.to_string(),
        software_version: format!("dig-gossip/{}", env!("CARGO_PKG_VERSION")),
        server_port: listen_port_for_handshake(&state),
        node_type: NodeType::FullNode,
        capabilities: vec![
            (1, "1".to_string()), // BASE protocol
            (2, "1".to_string()), // BLOCK_HEADERS
            (3, "1".to_string()), // RATE_LIMITS_V2
        ],
    };
    let reply = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None, // Handshakes have no correlation id in the Chia wire protocol.
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

    // CON-003: remote_software_version_sanitized was computed *before* our reply was sent.
    // This means we validate-then-respond, never the reverse — a malformed remote version
    // causes rejection before we leak our own Handshake.

    // --- Phase 4: Handle the expected `RequestPeers` from the outbound peer (CON-001 pattern) ---
    // The outbound `connect_to` issues `RequestPeers` immediately after the handshake exchange
    // (see `GossipHandle::connect_to`). We answer on the *raw* WebSocket before handing to
    // `Peer::from_websocket` — see `read_next_wire_message` doc for the rationale.
    let second = tokio::time::timeout(INBOUND_HANDSHAKE_TIMEOUT, read_next_wire_message(&mut ws))
        .await
        .map_err(|_| {
            ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "inbound RequestPeers timeout",
            ))
        })??;
    if second.msg_type == ProtocolMessageTypes::RequestPeers {
        // Reply with an empty peer list for now. Future DSC-* requirements will populate this
        // from the address manager's tried/new tables.
        let resp = RespondPeers::new(vec![]);
        let out = Message {
            msg_type: ProtocolMessageTypes::RespondPeers,
            id: second.id, // Preserve correlation id so the outbound Peer reader can match it.
            data: resp.to_bytes().map_err(ClientError::Streamable)?.into(),
        };
        ws.send(WsMsg::Binary(
            out.to_bytes().map_err(ClientError::Streamable)?,
        ))
        .await
        .map_err(|e| ClientError::Io(std::io::Error::other(e.to_string())))?;
    }

    // --- Phase 5: Register in the address manager (DSC-001 new-table bucketing) ---
    // SPEC §5.2 step 8 — "Add to address manager 'new' table (node_discovery.py:120-125)."
    // SPEC §6.3 — AddressManager (Rust port of address_manager.py, tried/new tables).
    let ts = unix_secs_u64();
    let new_row = TimestampedPeerInfo::new(
        remote_addr.ip().to_string(),
        their_handshake.server_port,
        ts,
    );
    let src = our_listen_peer_info(&state);
    // `penalty = 0`: inbound peers start fresh; future DSC-011 may apply group penalties.
    state
        .address_manager
        .add_to_new_table(std::slice::from_ref(&new_row), &src, 0);

    // --- Phase 6: Relay the newcomer's address to all existing live peers ---
    // SPEC §5.2 step 9 — "Relay peer info (node_discovery.py:126-127)."
    relay_new_peer_to_live_peers(&state, new_row).await?;

    // --- Phase 7: Upgrade to `Peer` (chia_sdk_client managed reader/writer) ---
    // After this point the WebSocket is consumed; all further communication goes through
    // the `Peer` handle (send) and the `inbound_rx` channel (receive).
    let (peer, mut inbound_rx) = Peer::from_websocket(ws, opts)?;

    // --- Phase 8: Per-connection inbound rate limiter (CON-005) + peer map insert ---
    // SPEC §5.4 — "Inbound: create a separate RateLimiter for each connection"
    // using `V2_RATE_LIMITS` from `chia-sdk-client`.
    // [`LiveSlot`] must exist **before** the forwarder runs so rate-limit violations can update
    // [`PeerReputation`] via [`apply_inbound_rate_limit_violation`].
    let inbound_limiter = Arc::new(Mutex::new(
        crate::connection::inbound_limits::new_inbound_rate_limiter(opts.rate_limit_factor),
    ));
    let meta = StubPeer {
        remote: remote_addr,
        node_type: their_handshake.node_type,
        is_outbound: false, // This is the *inbound* path; outbound has its own insertion logic.
    };
    let peer_for_keepalive = peer.clone();
    let lim = Arc::clone(&inbound_limiter);
    let mut peers = state
        .peers
        .lock()
        .map_err(|_| ClientError::Io(std::io::Error::from(std::io::ErrorKind::Other)))?;
    let opened_at = metric_unix_timestamp_secs();
    peers.insert(
        peer_id,
        PeerSlot::Live(LiveSlot {
            meta,
            peer,
            remote_protocol_version,
            remote_software_version_sanitized,
            reputation: std::sync::Arc::new(std::sync::Mutex::new(
                crate::types::reputation::PeerReputation::default(),
            )),
            inbound_rate_limiter: Arc::clone(&inbound_limiter),
            traffic: std::sync::Arc::new(std::sync::Mutex::new(PeerConnectionWireMetrics::new(
                opened_at,
            ))),
        }),
    );
    drop(peers);

    // --- Phase 9: Bridge inbound wire messages into the service broadcast channel ---
    // CON-005: [`RateLimiter::handle_message`] must approve each frame before CON-004 keepalive
    // auto-replies and before the `(PeerId, Message)` publish.
    if let Ok(guard) = state.inbound_tx.lock() {
        if let Some(tx_b) = guard.as_ref() {
            let tx: broadcast::Sender<(PeerId, Message)> = tx_b.clone();
            let pid_task = peer_id;
            let peer_rpc = peer_for_keepalive.clone();
            let state_fwd = state.clone();
            let lim_fwd = lim;
            tokio::spawn(async move {
                while let Some(msg) = inbound_rx.recv().await {
                    let allowed = lim_fwd
                        .lock()
                        .map(|mut g| g.handle_message(&msg))
                        .unwrap_or(true);
                    if !allowed {
                        apply_inbound_rate_limit_violation(&state_fwd, pid_task);
                        continue;
                    }
                    if let Ok(wl_in) = message_wire_len(&msg) {
                        record_live_peer_inbound_bytes(&state_fwd, pid_task, wl_in);
                    }
                    if msg.msg_type == ProtocolMessageTypes::RequestPeers {
                        if let Ok(body) = RespondPeers::new(vec![]).to_bytes() {
                            let reply = Message {
                                msg_type: ProtocolMessageTypes::RespondPeers,
                                id: msg.id,
                                data: body.into(),
                            };
                            let wl_out = message_wire_len(&reply).ok();
                            let _ = peer_rpc.send_protocol_message(reply).await;
                            if let Some(w) = wl_out {
                                record_live_peer_outbound_bytes(&state_fwd, pid_task, w);
                            }
                        }
                    }
                    // Ignore send errors: they mean all broadcast receivers have been dropped
                    // (service shutting down), which is a normal exit condition.
                    let _ = tx.send((pid_task, msg));
                }
            });
        }
    }

    // --- Phase 10: Start the keepalive loop for this connection (CON-004) ---
    crate::connection::keepalive::spawn_keepalive_task(state.clone(), peer_id, peer_for_keepalive);

    // Increment the lifetime connection counter (API-008 stats).
    state
        .total_connections
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Main accept loop: one OS listener, many spawned per-connection tasks (CON-002 acceptance matrix).
///
/// SPEC §5.2 — inbound connection flow starts at `TcpListener::accept()`.
/// SPEC §2.10 — `GossipConfig::max_connections` caps total peer slots; new TCP connections
/// are dropped if this limit is reached.
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
