//! Shared runtime state for [`super::gossip_service::GossipService`] and [`super::gossip_handle::GossipHandle`].
//!
//! **Requirements:** API-001 (lifecycle + TLS), API-002 (handle RPC wiring) /
//! [`API-002.md`](../../../docs/requirements/domains/crate_api/specs/API-002.md), API-008 (stats atomics) /
//! [`API-008.md`](../../../docs/requirements/domains/crate_api/specs/API-008.md).
//!
//! ## Stub peers (pre–CON-001)
//!
//! Real [`crate::types::peer::PeerConnection`] values require a live [`chia_sdk_client::Peer`].
//! Until CON-001, we track synthetic peers in [`ServiceState::peers`] so `peer_count`, `broadcast`,
//! and `connect_to` semantics can be tested without TLS sockets.

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

use chia_protocol::Bytes32;

use crate::discovery::address_manager::AddressManager;
use crate::types::config::GossipConfig;
use crate::types::peer::PeerId;

/// `lifecycle` values — see [`ServiceState::lifecycle`].
pub(crate) const LC_CONSTRUCTED: u8 = 0;
pub(crate) const LC_RUNNING: u8 = 1;
pub(crate) const LC_STOPPED: u8 = 2;

/// Metadata shared by stub rows and live TLS peers (direction + declared role + remote socket).
#[derive(Debug, Clone)]
pub(crate) struct StubPeer {
    pub remote: SocketAddr,
    pub node_type: NodeType,
    pub is_outbound: bool,
}

/// Live [`Peer`] handle after CON-001 outbound `wss://` + handshake (chia-sdk-client `Arc` inside).
#[derive(Debug)]
pub(crate) struct LiveSlot {
    pub meta: StubPeer,
    pub peer: Peer,
}

/// Either a **test-only stub** row or a **real** TLS peer (CON-001+).
#[derive(Debug)]
pub(crate) enum PeerSlot {
    Stub(StubPeer),
    Live(LiveSlot),
}

impl PeerSlot {
    pub(crate) fn remote(&self) -> SocketAddr {
        match self {
            PeerSlot::Stub(p) => p.remote,
            PeerSlot::Live(l) => l.meta.remote,
        }
    }

    pub(crate) fn is_outbound(&self) -> bool {
        match self {
            PeerSlot::Stub(p) => p.is_outbound,
            PeerSlot::Live(l) => l.meta.is_outbound,
        }
    }

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
        }
    }

    pub(crate) fn is_running(&self) -> bool {
        self.lifecycle.load(Ordering::SeqCst) == LC_RUNNING
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
