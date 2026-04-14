//! Aggregate statistics exposed via `GossipHandle` at the crate root (future API-008).

/// Counters / gauges for the main gossip runtime.
#[derive(Debug, Clone, Default)]
pub struct GossipStats {}

/// Relay-side byte and message counters.
#[derive(Debug, Clone, Default)]
pub struct RelayStats {}
