//! Configuration types for the gossip service, introducer, and relay.
//!
//! **Re-export:** STR-003; **fill in:** API-003, API-010.

/// Top-level knobs: listen address, network id, bootstrap targets, etc.
#[derive(Debug, Clone, Default)]
pub struct GossipConfig {}

/// Introducer host, registration policy, retry cadence.
#[derive(Debug, Clone, Default)]
pub struct IntroducerConfig {}

/// Relay URL, credentials, reconnect policy.
#[derive(Debug, Clone, Default)]
pub struct RelayConfig {}
