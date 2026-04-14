//! Cheap clone handle for callers to broadcast, query stats, and shut down.
//!
//! **Re-export:** STR-003; **methods:** API-002.

/// `Arc`-backed façade (implementation lands in API-002).
#[derive(Debug, Default)]
pub struct GossipHandle {}
