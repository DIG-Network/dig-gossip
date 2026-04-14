//! Aggregate statistics exposed via [`crate::service::gossip_handle::GossipHandle`] (API-002 / API-008).
//!
//! **Spec growth:** [`API-008.md`](../../docs/requirements/domains/crate_api/specs/API-008.md) will add
//! bandwidth / Plumtree counters; API-002 only needs enough shape for `stats()` to reflect stub
//! connection and broadcast activity.

/// Counters / gauges for the main gossip runtime.
#[derive(Debug, Clone, Default)]
pub struct GossipStats {
    /// Count of stub or live connections (API-002 uses the connection map; CON-001 will align).
    pub connected_peers: usize,
    /// Monotonic counter incremented by [`GossipHandle::broadcast`](crate::service::gossip_handle::GossipHandle::broadcast)
    /// (successful fan-out count summed per call in the stub).
    pub messages_broadcast_total: u64,
}

/// Relay-side byte and message counters.
#[derive(Debug, Clone, Default)]
pub struct RelayStats {}
