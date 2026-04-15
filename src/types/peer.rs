//! Peer identity, metadata, and the gossip-layer connection wrapper.
//!
//! **Layout:** STR-002; **re-exports:** STR-003 /
//! [`specs/STR-003.md`](../../../docs/requirements/domains/crate_structure/specs/STR-003.md).
//!
//! - **API-007 — [`PeerId`] / [`PeerInfo`]:**
//!   [`docs/requirements/domains/crate_api/specs/API-007.md`](../../../docs/requirements/domains/crate_api/specs/API-007.md),
//!   [`SPEC.md`](../../../docs/resources/SPEC.md) §2.2, §2.7 (Chia `peer_info.py` semantics).
//! - **API-005 — [`PeerConnection`]:**
//!   [`docs/requirements/domains/crate_api/specs/API-005.md`](../../../docs/requirements/domains/crate_api/specs/API-005.md)
//!   and [`SPEC.md`](../../../docs/resources/SPEC.md) Section 2.4.
//! - **API-011 — [`ExtendedPeerInfo`]:**
//!   [`docs/requirements/domains/crate_api/specs/API-011.md`](../../../docs/requirements/domains/crate_api/specs/API-011.md),
//!   [`SPEC.md`](../../../docs/resources/SPEC.md) §2.6 — address-manager row metadata (Chia `address_manager.py:43`).
//!
//! `PeerConnection` intentionally **does not** implement [`Clone`]: it owns an
//! [`tokio::sync::mpsc::Receiver`] for inbound wire messages (SPEC 2.4), which is not clonable.
//! Upstream [`chia_sdk_client::Peer`] is cloneable (`Arc` inside), but duplicating a connection’s
//! receiver would violate single-consumer semantics.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use chia_protocol::{Bytes32, Message, NodeType};
use chia_sdk_client::Peer;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::reputation::PeerReputation;

/// A unique identifier for a peer, derived from SHA256(TLS public key material).
///
/// **Normative:** API-007 — type alias for [`Bytes32`] from `chia-protocol` so wire types and
/// hashing stay aligned with Chia crates (see [`SPEC.md`](../../../docs/resources/SPEC.md) §2.2).
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

/// Resolved peer socket identity for the **address manager** (tried/new buckets, group diversity).
///
/// This is **not** the TLS-derived [`PeerId`]; it is the `host` + `port` we would dial or learned
/// from DNS / introducer. [`get_group`](Self::get_group) and [`get_key`](Self::get_key) mirror Chia
/// `peer_info.py:43-57` so DSC-001 / DSC-011 can port Python bucketing faithfully.
///
/// **Parsing:** [`Self::host`] is usually a numeric IP string. If it is not a literal [`IpAddr`],
/// methods fall back to **deterministic SHA-256** of the host string (and for [`Self::get_key`],
/// append the port in big-endian), per API-007 implementation notes — avoids `std` hasher
/// instability across Rust versions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    /// Hostname or IP literal (e.g. `"192.168.1.5"`, `"2001:db8::1"`, `"seed.example.com"`).
    pub host: String,
    /// P2P port (may be `0` in edge cases; still encoded in [`Self::get_key`]).
    pub port: u16,
}

impl PeerInfo {
    /// Network “group” for eclipse resistance: IPv4 `/16` (first two octets), IPv6 first 32 bits.
    ///
    /// **IPv4-mapped IPv6** (`::ffff:a.b.c.d`) is normalized to IPv4 so grouping matches Chia.
    /// **Non-IP hosts:** returns the first **4** bytes of `SHA256(host)` so length is stable and
    /// suitable alongside IPv6 group width (API-007 test plan).
    ///
    /// **See:** [`SPEC.md`](../../../docs/resources/SPEC.md) §2.7, Chia `peer_info.py:51-56`.
    pub fn get_group(&self) -> Vec<u8> {
        match self.host.parse::<IpAddr>() {
            Ok(ip) => group_bytes_for_ip(normalize_ip(ip)),
            Err(_) => hostname_group_bytes(&self.host),
        }
    }

    /// Stable bucket key: IP octets then port **big-endian** (Chia `peer_info.py:43-49`).
    ///
    /// - **IPv4:** 4 + 2 bytes  
    /// - **IPv6:** 16 + 2 bytes  
    /// - **IPv4-mapped IPv6:** uses the embedded IPv4 (4 + 2 bytes)  
    /// - **Hostname (unparseable as [`IpAddr`]):** `SHA256(host) || port_be` (32 + 2 bytes)
    pub fn get_key(&self) -> Vec<u8> {
        match self.host.parse::<IpAddr>() {
            Ok(ip) => key_bytes_for_ip(normalize_ip(ip), self.port),
            Err(_) => hostname_key_bytes(&self.host, self.port),
        }
    }
}

/// Collapse IPv4-mapped IPv6 to [`IpAddr::V4`] so `/16` grouping matches Chia.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn group_bytes_for_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets()[..2].to_vec(),
        IpAddr::V6(v6) => v6.octets()[..4].to_vec(),
    }
}

fn key_bytes_for_ip(ip: IpAddr, port: u16) -> Vec<u8> {
    let mut v = match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    v.extend_from_slice(&port.to_be_bytes());
    v
}

fn hostname_group_bytes(host: &str) -> Vec<u8> {
    Sha256::digest(host.as_bytes())[..4].to_vec()
}

fn hostname_key_bytes(host: &str, port: u16) -> Vec<u8> {
    let mut out = Sha256::digest(host.as_bytes()).to_vec();
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Address-manager row: tried vs new table metadata for one [`PeerInfo`].
///
/// **Rust port** of Chia `ExtendedPeerInfo` (`address_manager.py:43+`). DSC-001 will embed these in
/// tried/new buckets; fields mirror Python semantics so eviction, ref-counting, and random peer pick
/// (`random_pos`) can be ported line-by-line.
///
/// Uses this crate’s [`PeerInfo`] (API-007), **not** [`chia_protocol::TimestampedPeerInfo`], so
/// [`get_group`](PeerInfo::get_group) / [`get_key`](PeerInfo::get_key) stay available for bucketing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPeerInfo {
    /// Address we would dial or learned from the network.
    pub peer_info: PeerInfo,
    /// Last time this row was updated (Unix seconds); staleness / horizon logic (DSC-001).
    pub timestamp: u64,
    /// Peer that gossiped this address — drives **source-group** buckets in the new table.
    pub src: PeerInfo,
    /// Index in the random-order vector for O(1) uniform selection; [`None`] until inserted.
    pub random_pos: Option<usize>,
    /// `true` once we have placed the peer in the **tried** table (successful connect historically).
    pub is_tried: bool,
    /// New-table reference count from bucket entries pointing at this record; `0` in tried rows.
    pub ref_count: u32,
    /// Last successful TCP/TLS completion (Unix seconds); `0` means never connected.
    pub last_success: u64,
    /// Last connect attempt (Unix seconds); pairs with [`Self::num_attempts`] for backoff.
    pub last_try: u64,
    /// Monotonic attempt counter; compared to [`crate::constants::MAX_RETRIES`] when evicting.
    pub num_attempts: u32,
    /// Rate-limits how often attempts increment toward eviction (Chia `last_count_attempt`).
    pub last_count_attempt: u64,
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
    /// Peer software version string (Cc/Cf stripped per CON-003 / CON-008 — Chia `ws_connection.py`).
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
