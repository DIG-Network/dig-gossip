//! The `dig-nat`-backed peer transport: bridge the node's TLS identity, construct a `dig-nat`
//! [`PeerTarget`], establish a connection over the NAT-traversal ladder, and
//! expose the multiplexed streams the gossip layer uses.
//!
//! This replaces dig-gossip's bespoke `tokio-tungstenite` dialer for peer links with the unified
//! [`dig_nat::connect`] path. The mTLS handshake and `peer_id = SHA-256(SPKI DER)` verification are
//! performed BY `dig-nat` (its [`PeerIdPinningVerifier`](dig_nat::mtls::PeerIdPinningVerifier)), so
//! this module aligns with — rather than duplicates — the identity + verification, and hands back a
//! [`NatPeerConnection`] whose remote `peer_id` is already confirmed to equal the one asked for.

use std::net::SocketAddr;
use std::sync::Arc;

use dig_nat::{NatConfig, NatError, NodeCert, PeerConnection as NatConnection, PeerTarget};

use crate::types::peer::PeerId;

/// Construct a `dig-nat` [`PeerTarget`] from a gossip [`PeerId`] + optional dialable address +
/// network id.
///
/// With an address the target drives the direct/mapping/hole-punch methods; without one the peer is
/// reachable only via the relay-coordinated methods ([`PeerTarget::relay_only`]). The `peer_id` is
/// the 32 raw bytes — identical value in both crates (only the wrapper type differs).
pub fn peer_target_for(
    peer_id: PeerId,
    direct_addr: Option<SocketAddr>,
    network_id: impl Into<String>,
) -> PeerTarget {
    let nat_id = dig_nat::PeerId::from_bytes(*peer_id_bytes(&peer_id));
    match direct_addr {
        Some(addr) => PeerTarget::with_addr(nat_id, addr, network_id),
        None => PeerTarget::relay_only(nat_id, network_id),
    }
}

/// Borrow the 32 raw bytes of a gossip [`PeerId`] (`Bytes32`) as a fixed array.
fn peer_id_bytes(peer_id: &PeerId) -> &[u8; 32] {
    // `Bytes32` derefs/`AsRef`s to `[u8; 32]`; go through the slice to stay independent of the exact
    // inherent API surface of the chia-protocol version in use.
    peer_id
        .as_ref()
        .try_into()
        .expect("PeerId (Bytes32) is always 32 bytes")
}

/// An established, mutually-authenticated, multiplexed peer connection reached via `dig-nat`.
///
/// Wraps the `dig-nat` [`PeerConnection`](dig_nat::PeerConnection) — the verified remote `peer_id`,
/// which traversal tier established it (observability), the remote address, and the yamux session.
/// The gossip layer opens one logical stream per gossip channel over this connection; the gossip
/// ALGORITHMS run unchanged on top (this type only owns the transport).
pub struct NatPeerConnection {
    inner: NatConnection,
}

impl NatPeerConnection {
    /// Wrap an established `dig-nat` connection.
    pub fn new(inner: NatConnection) -> Self {
        NatPeerConnection { inner }
    }

    /// The verified remote identity as a gossip [`PeerId`] (the value the mTLS handshake confirmed
    /// equals the one asked for). Bridges the `dig-nat` `PeerId` newtype back to `Bytes32`.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from(*self.inner.peer_id.as_bytes())
    }

    /// Which traversal tier established this connection (Direct … Relayed) — observability only.
    pub fn method(&self) -> dig_nat::TraversalKind {
        self.inner.method
    }

    /// The remote endpoint the mTLS session runs over (the peer, or the relay for a relayed link).
    pub fn remote_addr(&self) -> SocketAddr {
        self.inner.remote_addr
    }

    /// Open a new logical stream (a gossip channel) over the multiplexed connection. Cheap — open one
    /// per concurrent channel/transfer; no head-of-line blocking between them.
    pub async fn open_channel(&mut self) -> std::io::Result<dig_nat::PeerStream> {
        self.inner.open_stream().await
    }

    /// Open a `dig.fetchRange` byte-range stream (multi-source download primitive — L7 spec §9).
    pub async fn open_range_stream(
        &mut self,
        req: &dig_nat::RangeRequest,
    ) -> std::io::Result<dig_nat::PeerStream> {
        self.inner.open_range_stream(req).await
    }

    /// Availability pre-check (`dig.getAvailability`, L7 spec §9) — ask the peer which items it holds
    /// before fetching ranges.
    pub async fn query_availability(
        &mut self,
        items: Vec<dig_nat::AvailabilityItem>,
    ) -> std::io::Result<dig_nat::AvailabilityResponse> {
        self.inner.query_availability(items).await
    }

    /// The underlying `dig-nat` connection, for callers that need the raw session (e.g. `dig-node`).
    pub fn into_inner(self) -> NatConnection {
        self.inner
    }
}

impl std::fmt::Debug for NatPeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatPeerConnection")
            .field("peer_id", &self.peer_id())
            .field("method", &self.inner.method)
            .field("remote_addr", &self.inner.remote_addr)
            .finish()
    }
}

/// Establish a peer connection through the unified `dig-nat` NAT-traversal ladder.
///
/// `node` is this node's CA-signed mTLS identity — a [`dig_tls::NodeCert`](dig_nat::NodeCert) chained
/// to the shipped DigNetwork CA and carrying the #1204 peer_id ↔ BLS-G1 binding — presented as the
/// client certificate (the self-signed→CA-signed cutover; an old self-signed cert would be rejected
/// by dig-nat's DigNetwork-CA chain check). `target` describes the peer ([`peer_target_for`]);
/// `config` selects enabled methods + timeouts + relay/STUN. On success the returned
/// [`NatPeerConnection`] carries the verified remote `peer_id` (== `target.peer_id`), the tier that
/// established it, and the multiplexed session. Never panics or hangs: every method is bounded by the
/// per-method timeout (a `dig-nat` guarantee).
pub async fn nat_connect(
    target: &PeerTarget,
    node: &Arc<NodeCert>,
    config: &NatConfig,
) -> Result<NatPeerConnection, NatError> {
    let conn = dig_nat::connect(target, node, config).await?;
    Ok(NatPeerConnection::new(conn))
}
