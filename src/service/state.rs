//! Shared runtime state for [`super::gossip_service::GossipService`] and [`super::gossip_handle::GossipHandle`].
//!
//! **Requirements:** API-001 (lifecycle + TLS), API-002 (handle RPC wiring) /
//! [`API-002.md`](../../../docs/requirements/domains/crate_api/specs/API-002.md).
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

/// Metadata for a **stub** connection (CON-001 will replace with full handshake fields).
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct StubPeer {
    pub remote: SocketAddr,
    pub node_type: NodeType,
    pub is_outbound: bool,
}

/// Arc-shared guts: configuration, TLS material, stub peer map, inbound fan-out, counters.
pub(crate) struct ServiceState {
    pub config: GossipConfig,
    #[allow(dead_code)]
    pub tls: ChiaCertificate,
    pub address_manager: AddressManager,
    #[allow(dead_code)]
    pub seen_messages: Mutex<LruCache<Bytes32, ()>>,
    /// Stub connection registry — keyed by deterministic [`peer_id_for_addr`].
    pub peers: Mutex<HashMap<PeerId, StubPeer>>,
    pub banned: Mutex<HashSet<PeerId>>,
    pub penalties: Mutex<HashMap<PeerId, u32>>,
    pub lifecycle: AtomicU8,
    /// Inbound wire fan-out: SPEC §3.3 names `mpsc::Receiver`, but a [`broadcast`] channel is the
    /// Rust-idiomatic way to keep [`GossipHandle: Clone`](super::gossip_handle::GossipHandle)
    /// while allowing multiple subscribers (see `GossipHandle::inbound_receiver` rustdoc).
    pub inbound_tx: Mutex<Option<broadcast::Sender<(PeerId, Message)>>>,
    /// Sum of peer delivery counts from [`super::gossip_handle::GossipHandle::broadcast`] (stub).
    pub messages_broadcast: AtomicU64,
}

/// Deterministic [`PeerId`] from a remote socket (until CON-001 derives TLS identities).
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
            messages_broadcast: AtomicU64::new(0),
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
