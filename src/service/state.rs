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
use std::sync::Mutex;

use chia_protocol::{Message, NodeType};
use chia_sdk_client::Peer;
use chia_ssl::ChiaCertificate;
use lru::LruCache;
use tokio::sync::broadcast;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use chia_protocol::Bytes32;

use crate::discovery::address_manager::AddressManager;
use crate::types::config::GossipConfig;
use crate::types::peer::PeerId;
use crate::types::reputation::PeerReputation;

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
    /// latency score. Protected by its own `Mutex` because keepalive tasks (CON-004)
    /// update it independently of the outer peer-map lock (API-006, SPEC §1.8 #6).
    pub reputation: Mutex<PeerReputation>,
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

/// Arc-shared guts: configuration, TLS material, stub peer map, inbound fan-out, counters.
pub(crate) struct ServiceState {
    pub config: GossipConfig,
    #[allow(dead_code)]
    pub tls: ChiaCertificate,
    pub address_manager: AddressManager,
    #[allow(dead_code)]
    pub seen_messages: Mutex<LruCache<Bytes32, ()>>,
    /// Connected peers — stubs ([`PeerSlot::Stub`]) or live TLS ([`PeerSlot::Live`]).
    pub peers: Mutex<HashMap<PeerId, PeerSlot>>,
    pub banned: Mutex<HashSet<PeerId>>,
    pub penalties: Mutex<HashMap<PeerId, u32>>,
    pub lifecycle: AtomicU8,
    /// Inbound wire fan-out: SPEC §3.3 names `mpsc::Receiver`, but a [`broadcast`] channel is the
    /// Rust-idiomatic way to keep [`GossipHandle: Clone`](super::gossip_handle::GossipHandle)
    /// while allowing multiple subscribers (see `GossipHandle::inbound_receiver` rustdoc).
    pub inbound_tx: Mutex<Option<broadcast::Sender<(PeerId, Message)>>>,
    /// Cumulative “messages sent” counter (API-008): broadcast adds per-recipient deliveries; `send_to` adds 1.
    pub messages_sent: AtomicU64,
    /// Cumulative inbound messages observed (stub: test inject path increments).
    pub messages_received: AtomicU64,
    /// Cumulative outbound / inbound bytes (stub: remain `0` until CON-* meters TLS payload sizes).
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    /// Cumulative successful stub/live `connect` completions (never decremented on disconnect).
    pub total_connections: AtomicU64,
    /// OS-assigned listen socket after [`TcpListener::bind`](tokio::net::TcpListener::bind) (`127.0.0.1:0` in tests).
    ///
    /// **Why:** [`GossipConfig::listen_addr`](crate::types::config::GossipConfig::listen_addr) may use port `0`;
    /// [`Handshake::server_port`](chia_protocol::Handshake::server_port) and self-dial checks need the resolved endpoint.
    pub listen_bound_addr: Mutex<Option<SocketAddr>>,
    /// Signals [`crate::connection::listener::accept_loop`] to exit on [`GossipService::stop`](super::gossip_service::GossipService::stop).
    pub(crate) listener_stop: Mutex<Option<std::sync::Arc<Notify>>>,
    pub(crate) listener_task: Mutex<Option<JoinHandle<()>>>,
}

/// Deterministic [`PeerId`] from a remote socket (stub peers / tests only — live peers use TLS SPKI).
pub(crate) fn peer_id_for_addr(addr: SocketAddr) -> PeerId {
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
    pub(crate) fn new(config: GossipConfig, tls: ChiaCertificate) -> Self {
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

    pub(crate) fn is_running(&self) -> bool {
        self.lifecycle.load(Ordering::SeqCst) == LC_RUNNING
    }

    /// `true` when `addr` is our configured or bound P2P listen address (CON-002 / self-dial guard).
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
