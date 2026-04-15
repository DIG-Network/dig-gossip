//! Shared mutable runtime state for the gossip subsystem.
//!
//! [`ServiceState`] is the single `Arc`-shared structure that both
//! [`GossipService`](super::gossip_service::GossipService) (lifecycle owner) and
//! [`GossipHandle`](super::gossip_handle::GossipHandle) (messaging surface) hold a
//! reference to. Every mutable field is independently synchronized so that concurrent
//! tasks -- the accept loop (CON-002), keepalive tasks (CON-004), the discovery loop,
//! and user-facing handle calls -- can operate with minimal contention.
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
//! | `AtomicU64` | `messages_sent`, `messages_received`, `bytes_sent`, `bytes_received`, `total_connections` | Lock-free, single-word counters incremented from many tasks concurrently; reads via `Relaxed` are acceptable for stats. |
//! | `AtomicU8` | `lifecycle` | Three-state flag guarding the constructed -> running -> stopped transitions. |
//! | `broadcast::Sender` (inside Mutex) | `inbound_tx` | Created once in `start()`, dropped in `stop()`. The sender itself is lock-free; the `Mutex` guards the `Option` wrapper for late initialization. |
//!
//! # Stub peers (pre-CON-001)
//!
//! Real [`crate::types::peer::PeerConnection`] values require a live [`chia_sdk_client::Peer`].
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

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use chia_protocol::{Message, NodeType};
use chia_sdk_client::{Peer, RateLimiter};
use chia_ssl::ChiaCertificate;
use lru::LruCache;
use tokio::sync::broadcast;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use chia_protocol::Bytes32;

use crate::discovery::address_manager::AddressManager;
use crate::types::config::GossipConfig;
use crate::types::peer::PeerId;
use crate::types::reputation::{PeerReputation, PenaltyReason};

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
#[derive(Debug)]
pub(crate) struct LiveSlot {
    /// Common metadata (direction, node type, remote address) shared with [`StubPeer`].
    pub meta: StubPeer,
    /// The `chia-sdk-client` WebSocket handle for sending/receiving wire messages.
    pub peer: Peer,
    /// Remote’s declared protocol version string from the Chia `Handshake`, retained
    /// after [`crate::connection::handshake::validate_remote_handshake`] succeeds (CON-003).
    pub remote_protocol_version: String,
    /// Remote’s software version after stripping Chia-specific prefixes ("Cc"/"Cf").
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
/// | `banned` | `ban_peer`, `stop` | `connect_to`, accept loop |
/// | `penalties` | `penalize_peer`, `stop` | `ban_peer` (threshold check) |
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
    pub address_manager: AddressManager,

    /// LRU set for message deduplication (SPEC §8.1 step 2). Keyed by
    /// `SHA256(msg_type || data)`. Capacity is set from
    /// [`GossipConfig::max_seen_messages`](crate::types::config::GossipConfig::max_seen_messages).
    /// Writers: broadcast path, inbound message handler.
    /// Readers: broadcast path (contains check).
    #[allow(dead_code)]
    pub seen_messages: Mutex<LruCache<Bytes32, ()>>,

    /// Map of currently connected peers (stubs for tests, live for real connections).
    /// Keyed by [`PeerId`] (SHA256 of remote TLS public key for live peers, or
    /// deterministic hash of `SocketAddr` for stubs).
    /// Writers: `connect_to`, accept loop, `disconnect`, `stop`.
    /// Readers: `broadcast`, `peer_count`, `get_connections`, `send_to`, `request`.
    pub(crate) peers: Mutex<HashMap<PeerId, PeerSlot>>,

    /// Set of banned [`PeerId`]s. Checked during `connect_to` and inbound accept to
    /// reject known-bad peers. Cleared on `stop()`.
    pub banned: Mutex<HashSet<PeerId>>,

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
    pub messages_sent: AtomicU64,

    /// Cumulative count of inbound messages observed (API-008). The accept loop
    /// (CON-002) increments this; stub tests increment via `test_inject_message`.
    pub messages_received: AtomicU64,

    /// Cumulative outbound bytes. Remains `0` until the CON-* transport layer meters
    /// TLS payload sizes. Placeholder for API-008 completeness.
    pub bytes_sent: AtomicU64,
    /// Cumulative inbound bytes. Same caveat as `bytes_sent`.
    pub bytes_received: AtomicU64,

    /// Cumulative successful `connect` completions (stubs + live). Monotonically
    /// increasing -- never decremented on disconnect. Used by `GossipStats::total_connections`.
    pub total_connections: AtomicU64,

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
    pub fn new(config: GossipConfig, tls: ChiaCertificate) -> Self {
        // Clamp to 1 to satisfy `NonZeroUsize`; a capacity of 0 would be nonsensical
        // for dedup anyway.
        let cap = NonZeroUsize::new(config.max_seen_messages.max(1)).expect("max 1+");
        Self {
            config,
            tls,
            address_manager: AddressManager::default(),
            seen_messages: Mutex::new(LruCache::new(cap)),
            peers: Mutex::new(HashMap::new()),
            banned: Mutex::new(HashSet::new()),
            penalties: Mutex::new(HashMap::new()),
            lifecycle: AtomicU8::new(LC_CONSTRUCTED),
            inbound_tx: Mutex::new(None),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            listen_bound_addr: Mutex::new(None),
            listener_stop: Mutex::new(None),
            listener_task: Mutex::new(None),
        }
    }

    /// Returns `true` if the service is in the *running* lifecycle state.
    ///
    /// Used as the entry guard in every [`GossipHandle`](super::gossip_handle::GossipHandle)
    /// method -- if this returns `false`, the method immediately returns
    /// [`GossipError::ServiceNotStarted`].
    pub(crate) fn is_running(&self) -> bool {
        self.lifecycle.load(Ordering::SeqCst) == LC_RUNNING
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
    // Statement form (`if let` + `;`) ends the `lock()` temporary before `rep_mtx` drops — same
    // drop-order fix as `match … ;` (avoids E0597); `clippy::single_match` prefers `if let`.
    if let Ok(mut rep) = rep_mtx.lock() {
        rep.apply_penalty(PenaltyReason::RateLimitExceeded, now);
    };
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
