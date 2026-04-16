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
//! - **CON-006 — connection metrics:** [`docs/requirements/domains/connection/specs/CON-006.md`](../../../docs/requirements/domains/connection/specs/CON-006.md) —
//!   `bytes_*`, `messages_*`, `last_message_time`; live slots mirror via [`PeerConnectionWireMetrics`].
//! - **API-011 — [`ExtendedPeerInfo`]:**
//!   [`docs/requirements/domains/crate_api/specs/API-011.md`](../../../docs/requirements/domains/crate_api/specs/API-011.md),
//!   [`SPEC.md`](../../../docs/resources/SPEC.md) §2.6 — address-manager row metadata (Chia `address_manager.py:43`).
//!
//! `PeerConnection` intentionally **does not** implement [`Clone`]: it owns an
//! [`tokio::sync::mpsc::Receiver`] for inbound wire messages (SPEC 2.4), which is not clonable.
//! Upstream [`dig_protocol::Peer`] is cloneable (`Arc` inside), but duplicating a connection’s
//! receiver would violate single-consumer semantics.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::constants::{
    BUCKET_SIZE, HORIZON_DAYS, MAX_FAILURES, MAX_RETRIES, MIN_FAIL_DAYS,
    NEW_BUCKETS_PER_SOURCE_GROUP, NEW_BUCKET_COUNT, TRIED_BUCKETS_PER_GROUP, TRIED_BUCKET_COUNT,
};
use dig_protocol::Peer;
use dig_protocol::Streamable;
use dig_protocol::{Bytes32, Message, NodeType};
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Chia `chia.util.hash.std_hash` — SHA-256; first 8 bytes interpreted as big-endian `u64`
/// (`address_manager.py` bucket math).
fn chia_std_hash_u64_prefix(data: &[u8]) -> u64 {
    let d = Sha256::digest(data);
    u64::from_be_bytes(d[..8].try_into().expect("sha256 len"))
}

impl ExtendedPeerInfo {
    /// Whether this row should be evicted as “terrible” (Chia `ExtendedPeerInfo.is_terrible`,
    /// `address_manager.py:176+`).
    ///
    /// **DSC-001:** [`crate::discovery::address_manager::AddressManager`] uses this for new-table
    /// replacement policy when a bucket slot is full.
    pub fn is_terrible(&self, now: u64) -> bool {
        if self.last_try > 0 && self.last_try >= now.saturating_sub(60) {
            return false;
        }
        if self.timestamp > now.saturating_add(10 * 60) {
            return true;
        }
        let horizon_secs = u64::from(HORIZON_DAYS) * 24 * 60 * 60;
        if self.timestamp == 0 || now.saturating_sub(self.timestamp) > horizon_secs {
            return true;
        }
        if self.last_success == 0 && self.num_attempts >= MAX_RETRIES {
            return true;
        }
        let min_fail_secs = u64::from(MIN_FAIL_DAYS) * 24 * 60 * 60;
        if now.saturating_sub(self.last_success) > min_fail_secs
            && self.num_attempts >= MAX_FAILURES
        {
            return true;
        }
        false
    }

    /// Weighting for [`crate::discovery::address_manager::AddressManager::select_peer`] retries
    /// (Chia `get_selection_chance`, `address_manager.py:201+`).
    pub fn get_selection_chance(&self, now: u64) -> f64 {
        let mut chance = 1.0_f64;
        let since_last_try = now.saturating_sub(self.last_try);
        if since_last_try < 60 * 10 {
            chance *= 0.01;
        }
        chance * 0.66_f64.powi(self.num_attempts.min(8) as i32)
    }

    /// Tried-table bucket for this row (`ExtendedPeerInfo.get_tried_bucket` in Chia).
    pub(crate) fn tried_bucket_index(&self, key: &[u8; 32]) -> usize {
        let peer = &self.peer_info;
        let mut buf = Vec::with_capacity(32 + peer.get_key().len());
        buf.extend_from_slice(key);
        buf.extend_from_slice(&peer.get_key());
        let hash1 = (chia_std_hash_u64_prefix(&buf) as usize) % TRIED_BUCKETS_PER_GROUP;
        let mut buf2 = Vec::with_capacity(32 + peer.get_group().len() + 1);
        buf2.extend_from_slice(key);
        buf2.extend_from_slice(&peer.get_group());
        buf2.push(hash1 as u8);
        (chia_std_hash_u64_prefix(&buf2) as usize) % TRIED_BUCKET_COUNT
    }

    /// New-table bucket for `source` attribution (`get_new_bucket`, Chia `address_manager.py:146+`).
    pub(crate) fn new_bucket_index(&self, key: &[u8; 32], src_peer: &PeerInfo) -> usize {
        let mut buf =
            Vec::with_capacity(32 + self.peer_info.get_group().len() + src_peer.get_group().len());
        buf.extend_from_slice(key);
        buf.extend_from_slice(&self.peer_info.get_group());
        buf.extend_from_slice(&src_peer.get_group());
        let hash1 = (chia_std_hash_u64_prefix(&buf) as usize) % NEW_BUCKETS_PER_SOURCE_GROUP;
        let mut buf2 = Vec::with_capacity(32 + src_peer.get_group().len() + 1);
        buf2.extend_from_slice(key);
        buf2.extend_from_slice(&src_peer.get_group());
        buf2.push(hash1 as u8);
        (chia_std_hash_u64_prefix(&buf2) as usize) % NEW_BUCKET_COUNT
    }

    /// Slot within a bucket (`get_bucket_position`, Chia `address_manager.py:161+`).
    pub(crate) fn bucket_position(&self, key: &[u8; 32], is_new: bool, n_bucket: usize) -> usize {
        let ch: u8 = if is_new { b'N' } else { b'K' };
        let nb = n_bucket as u32;
        let mut buf = Vec::with_capacity(32 + 1 + 3 + self.peer_info.get_key().len());
        buf.extend_from_slice(key);
        buf.push(ch);
        buf.push(((nb >> 16) & 0xff) as u8);
        buf.push(((nb >> 8) & 0xff) as u8);
        buf.push((nb & 0xff) as u8);
        buf.extend_from_slice(&self.peer_info.get_key());
        (chia_std_hash_u64_prefix(&buf) as usize) % BUCKET_SIZE
    }
}

/// Wall-clock **Unix seconds** for [`PeerConnection`] / CON-006 metric timestamps.
///
/// Uses the same “saturating to 0” pattern as keepalive penalties — if the host clock is
/// before `UNIX_EPOCH`, callers still get a deterministic value.
pub fn metric_unix_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Serialized on-wire length of a [`Message`] (header + body) — **CON-006** requires byte counters
/// to reflect wire size, not in-memory struct size.
///
/// **See:** [`CON-006.md`](../../../docs/requirements/domains/connection/specs/CON-006.md) —
/// “`bytes_read`/`bytes_written` should count the serialized wire size”.
#[allow(clippy::result_large_err)] // mirrors `encode_message` / Chia `Streamable` error surface
pub fn message_wire_len(msg: &Message) -> Result<u64, dig_protocol::ClientError> {
    msg.to_bytes()
        .map(|b| b.len() as u64)
        .map_err(dig_protocol::ClientError::Streamable)
}

/// Per-connection byte/message counters shared by [`LiveSlot`](crate::service::state::LiveSlot)
/// (runtime source of truth) and copyable into [`PeerConnection`] snapshots (API-005 / CON-006).
///
/// Stored under `Arc<Mutex<…>>` on each live slot so accept-loop forwarders and
/// [`GossipHandle`](crate::service::gossip_handle::GossipHandle) send paths can update metrics
/// without blocking the whole peer map (CON-006 implementation notes — concurrent tasks).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerConnectionWireMetrics {
    /// Immutable connection-open time (Unix seconds).
    pub creation_time: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub last_message_time: u64,
}

impl PeerConnectionWireMetrics {
    /// Initialize counters to zero with timestamps set to `now` (typically [`metric_unix_timestamp_secs`]).
    pub fn new(now: u64) -> Self {
        Self {
            creation_time: now,
            bytes_read: 0,
            bytes_written: 0,
            messages_sent: 0,
            messages_received: 0,
            last_message_time: now,
        }
    }

    /// CON-006 — outbound metering: `bytes_written += wire_len`, `messages_sent += 1`.
    ///
    /// Does **not** touch [`Self::last_message_time`] (receive-only field per CON-006 spec).
    pub fn record_message_sent(&mut self, wire_len: u64) {
        self.bytes_written = self.bytes_written.saturating_add(wire_len);
        self.messages_sent = self.messages_sent.saturating_add(1);
    }

    /// CON-006 — inbound metering: bytes + message count + `last_message_time = now`.
    pub fn record_message_received(&mut self, wire_len: u64, now: u64) {
        self.bytes_read = self.bytes_read.saturating_add(wire_len);
        self.messages_received = self.messages_received.saturating_add(1);
        self.last_message_time = now;
    }
}

/// Sum CON-006 fields across snapshots — must match how [`crate::types::stats::GossipStats`]
/// aggregates `messages_sent` / `messages_received` / `bytes_sent` / `bytes_received` (SPEC §3.4).
pub fn aggregate_peer_connection_io(peers: &[PeerConnection]) -> (u64, u64, u64, u64) {
    let mut messages_sent = 0u64;
    let mut messages_received = 0u64;
    let mut bytes_written = 0u64;
    let mut bytes_read = 0u64;
    for p in peers {
        messages_sent = messages_sent.saturating_add(p.messages_sent);
        messages_received = messages_received.saturating_add(p.messages_received);
        bytes_written = bytes_written.saturating_add(p.bytes_written);
        bytes_read = bytes_read.saturating_add(p.bytes_read);
    }
    (messages_sent, messages_received, bytes_written, bytes_read)
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
    /// Application-level messages sent on this connection (CON-006).
    pub messages_sent: u64,
    /// Application-level messages received on this connection (CON-006).
    pub messages_received: u64,
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
            .field("messages_sent", &self.messages_sent)
            .field("messages_received", &self.messages_received)
            .field("last_message_time", &self.last_message_time)
            .field("reputation", &self.reputation)
            .field("inbound_rx", &"<mpsc::Receiver<Message>>")
            .finish()
    }
}

impl PeerConnection {
    /// CON-006 — apply outbound accounting (see [`PeerConnectionWireMetrics::record_message_sent`]).
    pub fn record_message_sent(&mut self, wire_len: u64) {
        self.bytes_written = self.bytes_written.saturating_add(wire_len);
        self.messages_sent = self.messages_sent.saturating_add(1);
    }

    /// CON-006 — apply inbound accounting (see [`PeerConnectionWireMetrics::record_message_received`]).
    pub fn record_message_received(&mut self, wire_len: u64, now: u64) {
        self.bytes_read = self.bytes_read.saturating_add(wire_len);
        self.messages_received = self.messages_received.saturating_add(1);
        self.last_message_time = now;
    }
}
