//! Runtime observability snapshots for [`crate::service::gossip_handle::GossipHandle`].
//!
//! ## Requirements
//!
//! - **API-008** — [`docs/requirements/domains/crate_api/specs/API-008.md`](../../../docs/requirements/domains/crate_api/specs/API-008.md)
//! - **SPEC** — [`docs/resources/SPEC.md`](../../../docs/resources/SPEC.md) §3.4 (statistics)
//!
//! ## Design
//!
//! These are **plain data** types (`Debug` + `Clone` + `Default`) so callers can log, diff, or
//! export metrics without pulling async locks. [`GossipHandle::stats`](crate::service::gossip_handle::GossipHandle::stats)
//! and [`GossipHandle::relay_stats`](crate::service::gossip_handle::GossipHandle::relay_stats) assemble snapshots from
//! [`crate::service::state::ServiceState`] atomics and short-lived mutex guards — see implementation
//! notes in API-008 (“cheap to compute; avoid holding locks while assembling the struct”).

/// Aggregate gossip-layer counters and gauges (connections, traffic, dedup, relay summary).
///
/// Returned by [`GossipHandle::stats`](crate::service::gossip_handle::GossipHandle::stats). Field
/// meanings follow SPEC §3.4 / API-008; pre–CON-001 builds use **stub** peers and may leave byte
/// counters at zero until real I/O metering lands.
#[derive(Debug, Clone, Default)]
pub struct GossipStats {
    /// Total connections ever established (cumulative; never decreases on disconnect).
    pub total_connections: usize,
    /// Currently connected peers (`inbound_connections + outbound_connections` in a consistent snapshot).
    pub connected_peers: usize,
    /// Current inbound stub/live connection count.
    pub inbound_connections: usize,
    /// Current outbound stub/live connection count.
    pub outbound_connections: usize,
    /// Total messages sent (cumulative). Stub: broadcast sums per-peer deliveries; `send_to` adds one.
    pub messages_sent: u64,
    /// Total messages received (cumulative). Stub: incremented on synthetic inbound inject for tests.
    pub messages_received: u64,
    /// Total bytes sent (cumulative). Stub: `0` until send path meters bytes (CON-*).
    pub bytes_sent: u64,
    /// Total bytes received (cumulative). Stub: `0` until receive path meters bytes (CON-*).
    pub bytes_received: u64,
    /// Entries in the address manager (DSC-001). Stub [`crate::discovery::address_manager::AddressManager`] → `0`.
    pub known_addresses: usize,
    /// Distinct message hashes currently tracked in the LRU seen set (API-003 `max_seen_messages` cap).
    pub seen_messages: usize,
    /// Whether the relay fallback transport is connected (RLY-*). Stub: `false` until relay client exists.
    pub relay_connected: bool,
    /// Peers discovered reachable via relay. Stub: `0` until RLY peer list is wired.
    pub relay_peer_count: usize,
}

/// Relay-specific metrics snapshot.
///
/// Exposed only when [`crate::types::config::GossipConfig::relay`] is `Some` — see
/// [`GossipHandle::relay_stats`](crate::service::gossip_handle::GossipHandle::relay_stats).
/// Fields mirror API-008; defaults are zero/`false`/`None` until the `relay` feature implements
/// a live client (RLY-001+).
#[derive(Debug, Clone, Default)]
pub struct RelayStats {
    /// Whether we currently hold a relay WebSocket/session.
    pub connected: bool,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Reconnect attempts since the last successful session (RLY-004).
    pub reconnect_attempts: u32,
    /// Unix seconds of last successful relay connect.
    pub last_connected_at: Option<u64>,
    pub relay_peer_count: usize,
    /// Last measured RTT to relay (ms), when available.
    pub latency_ms: Option<u64>,
}
