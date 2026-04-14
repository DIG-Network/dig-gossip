//! Primary service type: binds listeners, runs discovery, owns subsystem handles.
//!
//! **Re-export:** STR-003; **constructor / lifecycle:** API-001.

/// Owns long-lived tasks and configuration for a gossip node.
#[derive(Debug, Default)]
pub struct GossipService {}
