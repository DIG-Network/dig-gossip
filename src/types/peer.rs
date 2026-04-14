//! Peer identity, metadata, and the gossip-layer connection wrapper.
//!
//! **Layout:** STR-002; **re-exports:** STR-003 /
//! [`specs/STR-003.md`](../../../docs/requirements/domains/crate_structure/specs/STR-003.md).
//! **Full metadata:** API-005 /
//! [`docs/requirements/domains/crate_api/specs/API-005.md`](../../../docs/requirements/domains/crate_api/specs/API-005.md)
//! and [`SPEC.md`](../../../docs/resources/SPEC.md) Section 2.4.
//!
//! `PeerConnection` intentionally **does not** implement [`Clone`]: it owns an
//! [`tokio::sync::mpsc::Receiver`] for inbound wire messages (SPEC 2.4), which is not clonable.
//! Upstream [`chia_sdk_client::Peer`] is cloneable (`Arc` inside), but duplicating a connection’s
//! receiver would violate single-consumer semantics.

use std::fmt;
use std::net::SocketAddr;

use chia_protocol::{Bytes32, Message, NodeType};
use chia_sdk_client::Peer;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::reputation::PeerReputation;

/// 32-byte peer identifier (BLS-derived in Chia; same wire type for DIG).
pub type PeerId = Bytes32;

/// Derive the gossip-layer [`PeerId`] from a TLS **SubjectPublicKeyInfo** block in PKIX DER form.
///
/// **Normative:** API-005 acceptance — “`peer_id` is derived from SHA256 of the TLS public key.”
/// We define that as **SHA256(`raw` SPKI DER)** where `raw` is the ASN.1 `SubjectPublicKeyInfo` sequence
/// (algorithm id + subjectPublicKey bit string), matching the `SubjectPublicKeyInfo::raw` slice in
/// the `x509-parser` crate when parsing X.509 certs. CON-001 will lift this blob from the negotiated peer cert.
///
/// **Not** the bare RSA/EC bit string alone — callers must pass the full SPKI DER slice.
pub fn peer_id_from_tls_spki_der(spki_der: &[u8]) -> PeerId {
    let digest = Sha256::digest(spki_der);
    let bytes: [u8; 32] = digest.into();
    PeerId::from(bytes)
}

/// Static / semi-static peer metadata used by discovery and address bucketing.
///
/// **Future fields:** IP, ports, services flags, timestamp — see discovery specs.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Stable peer identity on the wire.
    pub peer_id: PeerId,
}

/// Active connection with gossip bookkeeping.
///
/// Wraps [`Peer`] (TLS WebSocket I/O) with DIG-only metadata. Field layout matches
/// [`SPEC.md`](../../../docs/resources/SPEC.md) §2.4; behavior (handshake, metrics, …) is filled by
/// connection-domain requirements (CON-*, API-005).
pub struct PeerConnection {
    /// Underlying Chia light-wallet-protocol peer handle.
    pub peer: Peer,
    /// Unique peer identifier (TLS cert hash / Chia rules).
    pub peer_id: PeerId,
    /// Remote socket address.
    pub address: SocketAddr,
    /// `true` if we initiated the connection (outbound).
    pub is_outbound: bool,
    /// Declared node role from the [`Handshake`](chia_protocol::Handshake).
    pub node_type: NodeType,
    /// Peer protocol version string.
    pub protocol_version: String,
    /// Peer software version string (sanitized in CON-008).
    pub software_version: String,
    /// Peer-advertised server port from handshake.
    pub peer_server_port: u16,
    /// Capability tuples `(code, name)` from handshake.
    pub capabilities: Vec<(u16, String)>,
    /// Unix seconds when this connection object was created.
    pub creation_time: u64,
    /// Bytes read (CON-006 updates on receive).
    pub bytes_read: u64,
    /// Bytes written (CON-006 updates on send).
    pub bytes_written: u64,
    /// Unix seconds of last inbound message.
    pub last_message_time: u64,
    /// Reputation snapshot (API-006).
    pub reputation: PeerReputation,
    /// Inbound wire messages for this connection (`connect_peer` / `Peer::from_websocket`).
    pub inbound_rx: mpsc::Receiver<Message>,
}

impl fmt::Debug for PeerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerConnection")
            .field("peer", &self.peer)
            .field("peer_id", &self.peer_id)
            .field("address", &self.address)
            .field("is_outbound", &self.is_outbound)
            .field("node_type", &self.node_type)
            .field("protocol_version", &self.protocol_version)
            .field("software_version", &self.software_version)
            .field("peer_server_port", &self.peer_server_port)
            .field("capabilities", &self.capabilities)
            .field("creation_time", &self.creation_time)
            .field("bytes_read", &self.bytes_read)
            .field("bytes_written", &self.bytes_written)
            .field("last_message_time", &self.last_message_time)
            .field("reputation", &self.reputation)
            .field("inbound_rx", &"<mpsc::Receiver<Message>>")
            .finish()
    }
}
