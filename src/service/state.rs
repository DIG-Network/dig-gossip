//! Shared mutable runtime state for the gossip subsystem.
//!
//! [`ServiceState`] is the single `Arc`-shared structure that both
//! [`GossipService`](super::gossip_service::GossipService) (lifecycle owner) and
//! [`GossipHandle`](super::gossip_handle::GossipHandle) (messaging surface) hold a
//! reference to. Every mutable field is independently synchronized so that concurrent
//! tasks -- the accept loop (CON-002), keepalive tasks (CON-004), the discovery loop,
//! and user-facing handle calls -- can operate with minimal contention.
//!
//! ## SPEC citations
//!
//! - SPEC §9.1 — Crate Boundary: `dig-gossip` is a library crate wrapping
//!   `chia-sdk-client` and `chia-protocol`. Input: `Message` via `broadcast()`/`send_to()`.
//!   Output: `(PeerId, Message)` via inbound channel. `ServiceState` is the runtime
//!   interior that makes this possible.
//! - SPEC §2.4 — `PeerConnection` fields: `ServiceState::peers` stores per-connection
//!   metadata (direction, node type, remote address, reputation, rate limiter) that
//!   populates `PeerConnection` snapshots returned by `get_connections()`.
//! - SPEC §3.3 — `GossipHandle`: the handle's methods (`broadcast`, `send_to`, `request`,
//!   `peer_count`, `get_connections`, `stats`) all read/write through `ServiceState`
//!   fields under independent locks.
//!
//! # Requirements satisfied
//!
//! | Req | Role |
//! |-----|------|
//! | **API-001** | Lifecycle flags (`lifecycle` atomic) and TLS material storage |
//! | **API-002** | Handle RPC wiring: peer map, broadcast channel, address manager ([`API-002.md`]) |
//! | **API-008** | Cumulative stats counters (`messages_sent`, `bytes_sent`, ...) as [`AtomicU64`] ([`API-008.md`]) |
//! | **CON-002** | Inbound listener fields: `listener_stop`, `listener_task`, `listen_bound_addr`, `inbound_tx` ([`CON-002.md`]) |
//! | **CNC-003** | Synchronization primitives: `std::sync::Mutex` for maps, `AtomicU8`/`AtomicU64` for counters ([`CNC-003.md`]) |
//!
//! # Thread-safety design (CNC-003)
//!
//! | Primitive | Fields | Rationale |
//! |-----------|--------|-----------|
//! | `std::sync::Mutex` | `peers`, `banned`, `penalties`, `seen_messages`, `inbound_tx`, `listen_bound_addr`, `listener_stop`, `listener_task` | Short critical sections (insert/remove/lookup); no `await` while lock is held. `std::sync::Mutex` is cheaper than `tokio::sync::Mutex` for non-async guards. |
//! | `tokio::sync::Mutex` | `chia_ip_bans` | Holds upstream [`ClientState`] for **CON-007** `ban`/`unban` on remote IPs; mutated only across `.await` from async gossip paths. |
//! | `AtomicU64` | `messages_sent`, `messages_received`, `bytes_sent`, `bytes_received`, `total_connections` | Lock-free, single-word counters incremented from many tasks concurrently; reads via `Relaxed` are acceptable for stats. |
//! | `AtomicU8` | `lifecycle` | Three-state flag guarding the constructed -> running -> stopped transitions. |
//! | `broadcast::Sender` (inside Mutex) | `inbound_tx` | Created once in `start()`, dropped in `stop()`. The sender itself is lock-free; the `Mutex` guards the `Option` wrapper for late initialization. |
//!
//! # Stub peers (pre-CON-001)
//!
//! Real [`crate::types::peer::PeerConnection`] values require a live [`dig_protocol::Peer`].
//! Until CON-001 (outbound WSS connect) was implemented, we tracked synthetic peers in
//! [`ServiceState::peers`] via [`PeerSlot::Stub`] so `peer_count`, `broadcast`, and
//! `connect_to` semantics could be tested without TLS sockets. Stubs remain for
//! unit-test use.
//!
//! # Chia equivalent
//!
//! The closest Chia analog is the `ChiaServer` instance in
//! [`chia/server/server.py`](https://github.com/Chia-Network/chia-blockchain/blob/main/chia/server/server.py),
//! which owns the connection dict, rate limiters, and address manager. DIG factors the
//! state into a separate struct so it can be shared across service and handle without
//! exposing lifecycle methods on the handle.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use dig_protocol::{Message, NodeType};
use dig_protocol::{ClientState, Peer, RateLimiter};
use dig_protocol::ChiaCertificate;
use lru::LruCache;
use tokio::sync::broadcast;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use dig_protocol::Bytes32;

use crate::discovery::address_manager::AddressManager;
use crate::error::GossipError;
use crate::types::config::GossipConfig;
use crate::types::peer::{PeerConnectionWireMetrics, PeerId};
use crate::types::reputation::{PeerReputation, PenaltyReason};
use crate::util::as_lookup::AsDiversityFilter;
use crate::util::ip_address::SubnetGroupFilter;

/// Lifecycle state: service has been constructed but `start()` has not been called.
/// Config is validated and TLS is loaded, but no tasks are running and no ports are bound.
pub(crate) const LC_CONSTRUCTED: u8 = 0;
/// Lifecycle state: `start()` succeeded. The accept loop is running and handles are usable.
pub(crate) const LC_RUNNING: u8 = 1;
/// Lifecycle state: `stop()` has been called. All tasks are terminated and resources freed.
/// Transitioning back to `LC_RUNNING` is permanently forbidden (API-001 acceptance criterion).
pub(crate) const LC_STOPPED: u8 = 2;

/// Minimal metadata shared by both stub rows and live TLS peers.
///
/// Kept separate from [`LiveSlot`] so that unit tests can create lightweight entries
/// without a real [`Peer`] handle. Every peer -- stub or live -- has a direction, a
/// declared [`NodeType`] (from the Chia `Handshake`), and a remote socket address.
///
/// # Fields
///
/// * `remote` -- the remote endpoint's `SocketAddr` (IP:port). For inbound peers this
///   is the address reported by `TcpListener::accept()`.
/// * `node_type` -- what the remote declared itself as in the Chia `Handshake`
///   (e.g. `NodeType::FullNode`). Used for connection filtering (API-002 `get_connections`).
/// * `is_outbound` -- `true` if *we* initiated the connection. Outbound connections count
///   toward `target_outbound_count`; inbound ones do not.
#[derive(Debug, Clone)]
pub(crate) struct StubPeer {
    /// Remote socket address as seen by this node.
    pub remote: SocketAddr,
    /// Role declared by the remote during the Chia `Handshake` exchange.
    pub node_type: NodeType,
    /// Direction: `true` = we dialed them (outbound), `false` = they connected to us (inbound).
    pub is_outbound: bool,
}

/// A *live* TLS peer with a real [`Peer`] handle (CON-001 outbound `wss://` or CON-002 inbound).
///
/// Created after a successful Chia handshake and policy validation (CON-003). The slot
/// retains handshake metadata so that snapshot types like
/// [`crate::types::peer::PeerConnection`] can expose it without re-querying the wire.
///
/// # Ownership
///
/// The [`Peer`] inside is an `Arc`-backed handle from `chia-sdk-client`; dropping this
/// slot does *not* close the underlying WebSocket -- the caller must call
/// [`Peer::close()`](Peer::close) explicitly (done in
/// [`GossipService::stop`](super::gossip_service::GossipService::stop)).
///
/// # Requirement traceability
///
/// * **CON-001** -- outbound WSS connect populates this slot.
/// * **CON-003** -- handshake validation decides which fields are retained.
/// * **CON-004** -- [`PeerReputation`] is updated by
///   [`crate::connection::keepalive::spawn_keepalive_task`] with RTT samples.
/// * **CON-005** -- [`RateLimiter`] (`incoming = true`, 60 s window) enforced on the inbound
///   `mpsc` bridge before broadcast; violations call [`apply_inbound_rate_limit_violation`].
/// * **CON-006** -- [`PeerConnectionWireMetrics`] updated on each metered send/receive (wire bytes).
#[derive(Debug)]
pub(crate) struct LiveSlot {
    /// Common metadata (direction, node type, remote address) shared with [`StubPeer`].
    pub meta: StubPeer,
    /// The `chia-sdk-client` WebSocket handle for sending/receiving wire messages.
    pub peer: Peer,
    /// Remote’s declared protocol version string from the Chia `Handshake`, retained
    /// after [`crate::connection::handshake::validate_remote_handshake`] succeeds (CON-003).
    pub remote_protocol_version: String,
    /// Remote’s [`Handshake::software_version`](chia_protocol::Handshake) after CON-008
    /// Unicode **Cc**/**Cf** sanitization ([`crate::connection::handshake::sanitize_software_version`]).
    /// Stored sanitized so [`crate::types::peer::PeerConnection::software_version`]
    /// reflects exactly what we accepted.
    pub remote_software_version_sanitized: String,
    /// Per-connection reputation state: RTT sliding window, penalty accumulator, and
    /// latency score.
    ///
    /// Wrapped in `Arc<Mutex<…>>` (not a bare `Mutex` inside the map slot) so callers can
    /// [`Arc::clone`] the handle, **release** [`ServiceState::peers`], then lock reputation
    /// without rustc’s nested-guard lifetime error (E0597). Same mutex still serializes
    /// keepalive RTT updates vs penalties (CON-004 / API-006).
    pub reputation: Arc<Mutex<PeerReputation>>,
    /// Per-connection inbound [`RateLimiter`] (CON-005) — `V2_RATE_LIMITS` + DIG `dig_wire`.
    ///
    /// The accept/forwarder tasks currently hold their own `Arc` clone of the same limiter;
    /// this field remains the **slot of record** for diagnostics and future introspection APIs.
    #[allow(dead_code)]
    pub inbound_rate_limiter: Arc<Mutex<RateLimiter>>,
    /// CON-006 — per-live-connection counters mirrored into [`crate::types::peer::PeerConnection`]
    /// when snapshot APIs land; summed into [`crate::types::stats::GossipStats`] in [`crate::service::gossip_handle::GossipHandle::stats`].
    pub traffic: Arc<Mutex<PeerConnectionWireMetrics>>,
}

/// **CON-007** — DIG timed-ban row stored alongside [`PeerId`] in [`ServiceState::banned`].
///
/// We keep the **remote IP** so that when [`DigBanEntry::until`] expires we can call
/// [`ClientState::unban`] even though the peer slot is long gone (disconnect-on-ban).
#[derive(Debug, Clone, Copy)]
pub(crate) struct DigBanEntry {
    /// Unix seconds (inclusive): ban lifts when `now >= until` (matches [`PeerReputation::refresh_ban_status`]).
    pub until: u64,
    /// Source address used for [`ClientState::ban`] / [`ClientState::unban`].
    ///
    /// [`Ipv4Addr::UNSPECIFIED`] means “unknown IP” (e.g. manual `penalize_peer` on a ghost id);
    /// those rows still block by [`PeerId`] but do **not** touch Chia's IP ban table.
    pub ip: IpAddr,
}

/// A slot in the peer map: either a lightweight **test-only stub** or a **real** TLS peer.
///
/// The two-variant design lets the API surface (`peer_count`, `broadcast`, `get_connections`)
/// operate identically regardless of whether the peer was created synthetically in a
/// unit test or via a real CON-001/CON-002 TLS handshake.
///
/// # Invariant
///
/// A `Live` slot always has a valid [`Peer`] handle. A `Stub` slot never has one.
/// Pattern-matching on the variant is the only way to access the handle, preventing
/// accidental sends to stubs.
#[derive(Debug)]
pub(crate) enum PeerSlot {
    /// Synthetic peer for unit testing (no network resource).
    Stub(StubPeer),
    /// Real TLS peer with a `chia-sdk-client` [`Peer`] handle.
    Live(LiveSlot),
}

impl PeerSlot {
    /// The remote endpoint's socket address, regardless of stub vs live.
    /// Used by self-dial guards and address-manager updates.
    pub(crate) fn remote(&self) -> SocketAddr {
        match self {
            PeerSlot::Stub(p) => p.remote,
            PeerSlot::Live(l) => l.meta.remote,
        }
    }

    /// Whether *we* initiated the connection (outbound). Outbound peers count toward
    /// [`GossipConfig::target_outbound_count`](crate::types::config::GossipConfig::target_outbound_count).
    pub(crate) fn is_outbound(&self) -> bool {
        match self {
            PeerSlot::Stub(p) => p.is_outbound,
            PeerSlot::Live(l) => l.meta.is_outbound,
        }
    }

    /// The node type declared by the remote during the Chia `Handshake`.
    /// Used by [`GossipHandle::get_connections`](super::gossip_handle::GossipHandle) to
    /// filter by role.
    pub(crate) fn node_type(&self) -> NodeType {
        match self {
            PeerSlot::Stub(p) => p.node_type,
            PeerSlot::Live(l) => l.meta.node_type,
        }
    }
}

/// The `Arc`-shared interior of [`GossipService`](super::gossip_service::GossipService)
/// and [`GossipHandle`](super::gossip_handle::GossipHandle).
///
/// Contains every piece of mutable runtime state for the gossip subsystem: peer map,
/// address manager, TLS material, broadcast channel, lifecycle flag, and cumulative
/// stats counters. Each field is independently locked or atomic so concurrent tasks can
/// operate without coarse-grained serialization (CNC-003).
///
/// # Who reads / writes each field
///
/// | Field | Writers | Readers |
/// |-------|---------|---------|
/// | `peers` | `connect_to`, accept loop, `disconnect`, `stop` | `broadcast`, `peer_count`, `get_connections`, `send_to`, `request` |
/// | `banned` | `ban_peer`, `stop`, `prune_expired_dig_bans` | `connect_to`, accept loop, messaging |
/// | `chia_ip_bans` | `execute_dig_timed_ban`, `prune_expired_dig_bans`, `stop` | (internal — mirrors `banned` into Chia) |
/// | `penalties` | `penalize_peer`, `keepalive`, `stop`, `prune_expired_dig_bans` | threshold checks, diagnostics |
/// | `lifecycle` | `start`, `stop` | every handle method (guard) |
/// | `inbound_tx` | `start`, `stop` | accept loop, `test_inject_message` |
/// | `messages_sent` | `broadcast`, `send_to` | `stats` |
/// | `listen_bound_addr` | `start`, `stop` | `dial_targets_local_listen`, handshake builder |
/// | `listener_stop` / `listener_task` | `start`, `stop` | (internal only) |
///
/// # Requirement traceability
///
/// * **CNC-003** -- choice of `Mutex` vs `AtomicU64` vs `broadcast`.
/// * **API-008** -- stats counters.
/// * **CON-002** -- listener fields.
pub struct ServiceState {
    /// Immutable after construction. Holds all user-supplied knobs (listen address,
    /// connection limits, cert paths, timeouts, etc.). See [`GossipConfig`].
    /// SPEC §2.10 — `GossipConfig` fields.
    pub config: GossipConfig,

    /// TLS certificate + private key loaded (or generated) during construction.
    /// Used by the outbound connector (`connect_peer()`) and the inbound TLS acceptor
    /// (CON-002). Immutable after construction.
    #[allow(dead_code)]
    pub tls: ChiaCertificate,

    /// Bitcoin/Chia-style address manager (tried/new bucket tables).
    /// Manages known peer addresses for the discovery loop. Updated on successful
    /// connect (`mark_good`), on peer exchange (`add_to_new_table`), and on connect
    /// failure (`attempt`). See [`crate::discovery::address_manager::AddressManager`].
    /// SPEC §6.3 — Address Manager (Rust port of `address_manager.py`).
    pub address_manager: AddressManager,

    /// LRU set for message deduplication (SPEC §8.1 step 2). Keyed by
    /// `SHA256(msg_type || data)`. Capacity is set from
    /// [`GossipConfig::max_seen_messages`](crate::types::config::GossipConfig::max_seen_messages).
    /// Writers: broadcast path, inbound message handler.
    /// Readers: broadcast path (contains check).
    #[allow(dead_code)]
    pub seen_messages: Mutex<LruCache<Bytes32, ()>>,

    /// Plumtree gossip state — eager/lazy peer classification, lazy queue.
    /// INT-001: `broadcast()` routes through this instead of flat fan-out.
    /// SPEC §8.1 — Plumtree structured gossip.
    pub plumtree: Mutex<crate::gossip::plumtree::PlumtreeState>,

    /// Message cache for Plumtree GRAFT responses.
    /// INT-001: recently broadcast messages cached for lazy peers that GRAFT.
    /// SPEC §8.1 — "Message cache: LRU capacity 1000, TTL 60s."
    pub message_cache: Mutex<crate::gossip::message_cache::MessageCache>,

    /// **INT-006** — /16 subnet diversity filter for outbound connections.
    /// Blocks candidates whose /16 group already has an outbound connection.
    /// SPEC §6.4 item 3: "one outbound per IPv4 /16 subnet."
    pub subnet_filter: Mutex<SubnetGroupFilter>,

    /// **INT-007** — AS-level diversity filter for outbound connections.
    /// Blocks candidates whose AS is already represented in outbound set.
    /// SPEC §6.4 item 3: "AS-level diversity — one outbound per AS."
    pub as_filter: Mutex<AsDiversityFilter>,

    /// Map of currently connected peers (stubs for tests, live for real connections).
    /// Keyed by [`PeerId`] (SHA256 of remote TLS public key for live peers, or
    /// deterministic hash of `SocketAddr` for stubs).
    /// Writers: `connect_to`, accept loop, `disconnect`, `stop`.
    /// Readers: `broadcast`, `peer_count`, `get_connections`, `send_to`, `request`.
    pub(crate) peers: Mutex<HashMap<PeerId, PeerSlot>>,

    /// **CON-007** — timed bans keyed by [`PeerId`]: each entry records `until` + IP for
    /// Chia [`ClientState`] synchronization. Expired rows are pruned on connection attempts
    /// and on explicit [`Self::prune_expired_dig_bans`] calls. Cleared on `stop()`.
    pub(crate) banned: Mutex<HashMap<PeerId, DigBanEntry>>,

    /// Chia upstream IP ban table — **must** stay consistent with `banned` for live sockets
    /// that flow through `chia-sdk-client` connect paths (CON-007 acceptance).
    ///
    /// Wrapped in [`tokio::sync::Mutex`] because eviction (`unban`) runs from async tasks;
    /// the inner [`ClientState`] methods are synchronous.
    pub(crate) chia_ip_bans: Arc<tokio::sync::Mutex<ClientState>>,

    /// Accumulated penalty scores per peer. When a peer's score crosses
    /// [`PENALTY_BAN_THRESHOLD`](crate::constants::PENALTY_BAN_THRESHOLD) it is moved
    /// to `banned`. Cleared on `stop()`.
    pub penalties: Mutex<HashMap<PeerId, u32>>,

    /// Three-state lifecycle flag: `LC_CONSTRUCTED` -> `LC_RUNNING` -> `LC_STOPPED`.
    /// Every [`GossipHandle`](super::gossip_handle::GossipHandle) method checks this
    /// at entry and returns [`GossipError::ServiceNotStarted`] if not `LC_RUNNING`.
    /// Transitions are atomic CAS (in `start`) or unconditional swap (in `stop`).
    pub lifecycle: AtomicU8,

    /// Inbound wire message fan-out channel.
    ///
    /// SPEC §3.3 describes this as `mpsc::Receiver`, but a [`broadcast`] channel is
    /// the Rust-idiomatic way to allow multiple [`GossipHandle`] clones to each
    /// subscribe independently. Created in `start()`, dropped (set to `None`) in
    /// `stop()`.
    ///
    /// Writers: accept loop (CON-002), `test_inject_message` (API-002).
    /// Readers: each handle's `inbound_receiver()` subscriber.
    pub inbound_tx: Mutex<Option<broadcast::Sender<(PeerId, Message)>>>,

    /// Cumulative count of messages sent (API-008). `broadcast` adds one per recipient
    /// that accepted the message; `send_to` adds 1. Never decremented.
    /// SPEC §3.4 — `GossipStats::messages_sent`.
    pub messages_sent: AtomicU64,

    /// Cumulative count of inbound messages observed (API-008). The accept loop
    /// (CON-002) increments this; stub tests increment via `test_inject_message`.
    /// SPEC §3.4 — `GossipStats::messages_received`.
    pub messages_received: AtomicU64,

    /// Cumulative outbound bytes. Remains `0` until the CON-* transport layer meters
    /// TLS payload sizes. Placeholder for API-008 completeness.
    pub bytes_sent: AtomicU64,
    /// Cumulative inbound bytes. Same caveat as `bytes_sent`.
    pub bytes_received: AtomicU64,

    /// Cumulative successful `connect` completions (stubs + live). Monotonically
    /// increasing -- never decremented on disconnect. Used by `GossipStats::total_connections`.
    pub total_connections: AtomicU64,

    /// Cumulative peers received via `RespondPeers` across all peer exchange rounds.
    /// DSC-007: capped at [`MAX_TOTAL_PEERS_RECEIVED`](crate::constants::MAX_TOTAL_PEERS_RECEIVED) (3000).
    /// When this counter reaches the cap, further `RespondPeers` peer lists are silently discarded.
    /// SPEC §1.6#11, Chia `node_discovery.py:35`.
    pub total_peers_received: AtomicU64,

    /// OS-assigned listen socket address after
    /// [`TcpListener::bind`](tokio::net::TcpListener::bind).
    ///
    /// **Why this exists:** [`GossipConfig::listen_addr`](crate::types::config::GossipConfig::listen_addr)
    /// may use port `0` (tests); the resolved ephemeral port is needed for:
    /// 1. [`Handshake::server_port`](chia_protocol::Handshake) sent to remotes,
    /// 2. Self-dial guard in [`dial_targets_local_listen`](ServiceState::dial_targets_local_listen).
    ///
    /// Set in `start()`, cleared in `stop()`.
    pub listen_bound_addr: Mutex<Option<SocketAddr>>,

    /// [`Notify`] handle used to signal the CON-002 accept loop to exit gracefully
    /// when [`GossipService::stop`](super::gossip_service::GossipService::stop) is called.
    pub(crate) listener_stop: Mutex<Option<std::sync::Arc<Notify>>>,

    /// [`JoinHandle`] for the spawned accept-loop task. Stored so `stop()` can
    /// `abort()` + `await` it for clean shutdown.
    pub(crate) listener_task: Mutex<Option<JoinHandle<()>>>,
}

/// Derive a deterministic [`PeerId`] from a [`SocketAddr`].
///
/// **Stub / test use only.** Live peers derive their `PeerId` from
/// `SHA256(remote_TLS_certificate_public_key)` (SPEC §5.3). This function exists so that
/// unit tests that create stub peers without TLS can still produce unique, reproducible
/// IDs keyed to the socket address.
///
/// # Layout of the 32-byte output
///
/// | Bytes | Content |
/// |-------|---------|
/// | 0..8 | `DefaultHasher` hash of the full `SocketAddr` |
/// | 8..16 | Port number (zero-extended to 8 bytes) |
/// | 16..20 (v4) or 16..32 (v6) | Raw IP octets |
///
/// This layout is *not* cryptographically meaningful; it is designed to be
/// collision-resistant enough for test purposes.
pub fn peer_id_for_addr(addr: SocketAddr) -> PeerId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    addr.hash(&mut h);
    let x = h.finish();
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&x.to_le_bytes());
    b[8..16].copy_from_slice(&(u128::from(addr.port()) as u64).to_le_bytes());
    match addr.ip() {
        std::net::IpAddr::V4(v4) => b[16..20].copy_from_slice(&v4.octets()),
        std::net::IpAddr::V6(v6) => {
            let o = v6.octets();
            b[16..32].copy_from_slice(&o[..16]);
        }
    }
    PeerId::from(b)
}

impl ServiceState {
    /// Construct a fresh `ServiceState` in the `LC_CONSTRUCTED` lifecycle phase.
    ///
    /// All mutable containers start empty; counters start at zero. The LRU capacity for
    /// `seen_messages` is clamped to at least 1 because [`LruCache::new`] panics on zero.
    ///
    /// **DSC-002:** [`AddressManager::create`](crate::discovery::address_manager::AddressManager::create)
    /// loads a persisted peers file from [`GossipConfig::peers_file_path`] when present.
    pub fn new(config: GossipConfig, tls: ChiaCertificate) -> Result<Self, GossipError> {
        // Clamp to 1 to satisfy `NonZeroUsize`; a capacity of 0 would be nonsensical
        // for dedup anyway.
        let cap = NonZeroUsize::new(config.max_seen_messages.max(1)).expect("max 1+");
        let address_manager = AddressManager::create(&config.peers_file_path)?;
        Ok(Self {
            config,
            tls,
            address_manager,
            seen_messages: Mutex::new(LruCache::new(cap)),
            plumtree: Mutex::new(crate::gossip::plumtree::PlumtreeState::new()),
            message_cache: Mutex::new(crate::gossip::message_cache::MessageCache::new()),
            subnet_filter: Mutex::new(SubnetGroupFilter::new()),
            as_filter: Mutex::new(AsDiversityFilter::no_bgp_data()),
            peers: Mutex::new(HashMap::new()),
            banned: Mutex::new(HashMap::new()),
            chia_ip_bans: Arc::new(tokio::sync::Mutex::new(ClientState::default())),
            penalties: Mutex::new(HashMap::new()),
            lifecycle: AtomicU8::new(LC_CONSTRUCTED),
            inbound_tx: Mutex::new(None),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            total_peers_received: AtomicU64::new(0),
            listen_bound_addr: Mutex::new(None),
            listener_stop: Mutex::new(None),
            listener_task: Mutex::new(None),
        })
    }

    /// Returns `true` if the service is in the *running* lifecycle state.
    ///
    /// Used as the entry guard in every [`GossipHandle`](super::gossip_handle::GossipHandle)
    /// method -- if this returns `false`, the method immediately returns
    /// [`GossipError::ServiceNotStarted`].
    pub(crate) fn is_running(&self) -> bool {
        self.lifecycle.load(Ordering::SeqCst) == LC_RUNNING
    }

    // -------------------------------------------------------------------------
    // CON-007 — timed `PeerId` bans mirrored into `dig_protocol::ClientState`
    // -------------------------------------------------------------------------

    /// Drop [`DigBanEntry`] rows whose `until` timestamp has passed, call [`ClientState::unban`]
    /// for each non-placeholder IP, and remove the matching [`penalties`] row so a cooled-off
    /// peer truly gets a clean slate (CON-007 acceptance + [`PeerReputation::refresh_ban_status`]).
    pub(crate) async fn prune_expired_dig_bans(&self, now_unix_secs: u64) {
        let mut expired: Vec<(PeerId, IpAddr)> = Vec::new();
        {
            let Ok(mut guard) = self.banned.lock() else {
                return;
            };
            guard.retain(|pid, entry| {
                if now_unix_secs >= entry.until {
                    expired.push((*pid, entry.ip));
                    false
                } else {
                    true
                }
            });
        }
        for (pid, ip) in expired {
            if !ip.is_unspecified() {
                let mut cs = self.chia_ip_bans.lock().await;
                cs.unban(ip);
            }
            if let Ok(mut p) = self.penalties.lock() {
                p.remove(&pid);
            }
        }
    }

    /// Record a timed ban and synchronously call [`ClientState::ban`] when we know a real IP.
    ///
    /// **Call ordering:** callers usually [`Self::prune_expired_dig_bans`] first so clocks
    /// cannot resurrect stale rows incorrectly.
    pub(crate) async fn execute_dig_timed_ban(
        &self,
        peer_id: PeerId,
        remote_ip: IpAddr,
        now_unix_secs: u64,
    ) {
        let until = now_unix_secs.saturating_add(crate::constants::BAN_DURATION_SECS);
        {
            let Ok(mut g) = self.banned.lock() else {
                return;
            };
            g.insert(
                peer_id,
                DigBanEntry {
                    until,
                    ip: remote_ip,
                },
            );
        }
        if !remote_ip.is_unspecified() {
            let mut cs = self.chia_ip_bans.lock().await;
            cs.ban(remote_ip);
        }
    }

    /// Remove the peer slot (if any), close live TLS, then [`Self::execute_dig_timed_ban`].
    ///
    /// Shared by explicit [`super::gossip_handle::GossipHandle::ban_peer`], automatic
    /// threshold bans, and CON-005 rate-limit bursts that cross the reputation threshold.
    pub(crate) async fn enforce_timed_ban_and_disconnect(
        &self,
        peer_id: PeerId,
        now_unix_secs: u64,
    ) {
        self.prune_expired_dig_bans(now_unix_secs).await;
        let removed = {
            let Ok(mut peers) = self.peers.lock() else {
                return;
            };
            peers.remove(&peer_id)
        };
        let ip = removed
            .as_ref()
            .map(|s| s.remote().ip())
            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
        if let Some(PeerSlot::Live(l)) = removed {
            let _ = l.peer.close().await;
        }
        self.execute_dig_timed_ban(peer_id, ip, now_unix_secs).await;
    }

    /// `true` if `peer_id` is currently banned **after** pruning expired rows at `now_unix_secs`.
    pub(crate) async fn is_peer_id_banned_at(&self, peer_id: PeerId, now_unix_secs: u64) -> bool {
        self.prune_expired_dig_bans(now_unix_secs).await;
        self.banned
            .lock()
            .ok()
            .is_some_and(|g| g.contains_key(&peer_id))
    }

    /// Self-dial guard: returns `true` when `addr` matches either the *configured*
    /// listen address or the *bound* address (which differs when port `0` is used).
    ///
    /// Prevents the discovery loop or `connect_to` from opening a connection back to
    /// ourselves, which would waste a connection slot and confuse the peer map.
    ///
    /// **Requirement:** CON-002 (inbound listener) -- the bound address is only known
    /// after `start()` resolves it.
    pub(crate) fn dial_targets_local_listen(&self, addr: SocketAddr) -> bool {
        if addr == self.config.listen_addr {
            return true;
        }
        self.listen_bound_addr
            .lock()
            .ok()
            .and_then(|g| *g)
            .is_some_and(|b| b == addr)
    }
}

/// CON-005: apply [`PenaltyReason::RateLimitExceeded`] when an inbound wire frame fails
/// [`RateLimiter::handle_message`].
///
/// **CON-007:** if [`PeerReputation::apply_penalty`] reports a *fresh* ban threshold crossing,
/// we spawn [`ServiceState::enforce_timed_ban_and_disconnect`] — this function is synchronous
/// (called under the inbound forwarder's hot path) and therefore cannot `.await` directly.
pub fn apply_inbound_rate_limit_violation(state: &Arc<ServiceState>, peer_id: PeerId) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let rep_mtx = {
        let Ok(peers) = state.peers.lock() else {
            return;
        };
        let Some(PeerSlot::Live(live)) = peers.get(&peer_id) else {
            return;
        };
        Arc::clone(&live.reputation)
    };
    let triggered = match rep_mtx.lock() {
        Ok(mut rep) => rep.apply_penalty(PenaltyReason::RateLimitExceeded, now),
        Err(e) => e
            .into_inner()
            .apply_penalty(PenaltyReason::RateLimitExceeded, now),
    };
    if triggered {
        let st = Arc::clone(state);
        tokio::spawn(async move {
            let n = crate::types::peer::metric_unix_timestamp_secs();
            st.enforce_timed_ban_and_disconnect(peer_id, n).await;
        });
    }
}

/// CON-006 — increment outbound wire counters for a live peer (after a successful `Peer::send_*`).
pub(crate) fn record_live_peer_outbound_bytes(
    state: &ServiceState,
    peer_id: PeerId,
    wire_len: u64,
) {
    let traffic = {
        let Ok(peers) = state.peers.lock() else {
            return;
        };
        let Some(PeerSlot::Live(live)) = peers.get(&peer_id) else {
            return;
        };
        Arc::clone(&live.traffic)
    };
    if let Ok(mut g) = traffic.lock() {
        g.record_message_sent(wire_len);
    };
}

/// CON-006 — increment inbound wire counters for a live peer (after a decoded inbound [`Message`]).
pub(crate) fn record_live_peer_inbound_bytes(state: &ServiceState, peer_id: PeerId, wire_len: u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let traffic = {
        let Ok(peers) = state.peers.lock() else {
            return;
        };
        let Some(PeerSlot::Live(live)) = peers.get(&peer_id) else {
            return;
        };
        Arc::clone(&live.traffic)
    };
    if let Ok(mut g) = traffic.lock() {
        g.record_message_received(wire_len, now);
    };
}

/// Sum [`PeerConnectionWireMetrics`] across all [`PeerSlot::Live`] rows — feeds [`GossipStats`] I/O fields.
pub(crate) fn sum_live_peer_wire_metrics(state: &ServiceState) -> (u64, u64, u64, u64) {
    let Ok(peers) = state.peers.lock() else {
        return (0, 0, 0, 0);
    };
    let mut messages_sent = 0u64;
    let mut messages_received = 0u64;
    let mut bytes_written = 0u64;
    let mut bytes_read = 0u64;
    for slot in peers.values() {
        if let PeerSlot::Live(l) = slot {
            if let Ok(g) = l.traffic.lock() {
                messages_sent = messages_sent.saturating_add(g.messages_sent);
                messages_received = messages_received.saturating_add(g.messages_received);
                bytes_written = bytes_written.saturating_add(g.bytes_written);
                bytes_read = bytes_read.saturating_add(g.bytes_read);
            }
        }
    }
    (messages_sent, messages_received, bytes_written, bytes_read)
}

impl fmt::Debug for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceState")
            .field("config", &self.config)
            .field("lifecycle", &self.lifecycle.load(Ordering::SeqCst))
            .field(
                "stub_peer_count",
                &self.peers.lock().map(|g| g.len()).unwrap_or(0),
            )
            .field("address_manager", &self.address_manager)
            .finish_non_exhaustive()
    }
}
