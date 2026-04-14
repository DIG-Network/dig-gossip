//! Shared runtime state for [`super::gossip_service::GossipService`] and [`super::gossip_handle::GossipHandle`].
//!
//! **Requirement:** API-001 /
//! [`docs/requirements/domains/crate_api/specs/API-001.md`](../../../docs/requirements/domains/crate_api/specs/API-001.md)
//! — constructor prepares address-manager slot, seen-message LRU, and peer map **without**
//! spawning tasks. Full behavior lands in DSC-*, PLT-*, CON-*.
//!
//! **Lifecycle encoding:** a single [`AtomicU8`] keeps [`GossipService::start`](super::gossip_service::GossipService::start)
//! idempotent rules cheaply on the hot path that `GossipHandle` clones share.

use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use chia_protocol::Bytes32;
use chia_ssl::ChiaCertificate;
use lru::LruCache;

use crate::discovery::address_manager::AddressManager;
use crate::types::config::GossipConfig;
use crate::types::peer::PeerId;

/// `lifecycle` values — see [`ServiceState::lifecycle`].
pub(crate) const LC_CONSTRUCTED: u8 = 0;
pub(crate) const LC_RUNNING: u8 = 1;
pub(crate) const LC_STOPPED: u8 = 2;

/// Arc-shared guts: configuration, TLS material, and placeholder structures for later requirements.
#[allow(dead_code)]
pub(crate) struct ServiceState {
    /// Copy of the caller’s [`GossipConfig`] (needed for `start()` / discovery loops later).
    pub config: GossipConfig,
    /// Node identity material loaded or generated during [`GossipService::new`](super::gossip_service::GossipService::new).
    pub tls: ChiaCertificate,
    /// Address tables — DSC-001 will replace the stub.
    pub address_manager: AddressManager,
    /// Seen-message LRU — capacity from [`GossipConfig::max_seen_messages`] (PLT-008).
    pub seen_messages: Mutex<LruCache<Bytes32, ()>>,
    /// Future `PeerId` → active connection map; placeholder until CNC-003.
    pub peers_placeholder: Mutex<HashMap<PeerId, ()>>,
    /// See module docs — `CONSTRUCTED`, `RUNNING`, or `STOPPED`.
    pub lifecycle: AtomicU8,
}

impl ServiceState {
    /// Build storage structures after TLS succeeded in `GossipService::new`.
    pub(crate) fn new(config: GossipConfig, tls: ChiaCertificate) -> Self {
        let cap = NonZeroUsize::new(config.max_seen_messages.max(1)).expect("max 1+");
        Self {
            config,
            tls,
            address_manager: AddressManager::default(),
            seen_messages: Mutex::new(LruCache::new(cap)),
            peers_placeholder: Mutex::new(HashMap::new()),
            lifecycle: AtomicU8::new(LC_CONSTRUCTED),
        }
    }

    /// API-001 / API-002 gate: only a running service accepts work on the handle.
    pub(crate) fn is_running(&self) -> bool {
        self.lifecycle.load(Ordering::SeqCst) == LC_RUNNING
    }
}

impl fmt::Debug for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceState")
            .field("config", &self.config)
            .field("lifecycle", &self.lifecycle.load(Ordering::SeqCst))
            .field("address_manager", &self.address_manager)
            .finish_non_exhaustive()
    }
}
