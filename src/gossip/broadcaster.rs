//! Top-level broadcast orchestration — delegates to Plumtree vs ERLAY paths.
//!
//! **SPEC §10.1** — `gossip/broadcaster.rs`: "Top-level broadcast orchestration
//! (delegates to plumtree/erlay)."
//!
//! # Requirements
//!
//! - **INT-001** — Plumtree eager/lazy routing
//! - **INT-002** — Priority lane enqueuing
//! - **INT-003** — Backpressure checks
//! - **INT-004** — ERLAY flood set routing for NewTransaction
//! - **INT-005** — Relay broadcast in Plumtree step 7
//! - **Master SPEC:** §8.1 (Plumtree), §8.3 (ERLAY), §8.4 (Priority), §8.5 (Backpressure)
//!
//! # Design
//!
//! This module provides the `BroadcastDecision` type and `classify_broadcast()` function
//! that determines how a message should be disseminated based on its type and the
//! current gossip configuration.
//!
//! The actual sending is performed by `GossipHandle::broadcast()` in `service/gossip_handle.rs`
//! which calls into this module for routing decisions.
//!
//! # Broadcast flow (SPEC §8.1 steps 1-8)
//!
//! 1. Compute hash = SHA256(msg_type || data)
//! 2. Check seen_set — if already seen, drop (return 0)
//! 3. Insert into seen_set
//! 4. Cache message for GRAFT responses (PLT-007)
//! 5. Eager push: full message to eager_peers (excluding origin)
//! 6. Lazy push: hash-only LazyAnnounce to lazy_peers (excluding origin)
//! 7. Relay broadcast: if relay connected, send via relay (INT-005)
//! 8. Return count sent

use chia_protocol::ProtocolMessageTypes;

use crate::gossip::priority::MessagePriority;

/// How a message should be disseminated.
///
/// Returned by [`classify_broadcast()`] to guide `GossipHandle::broadcast()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastStrategy {
    /// Use Plumtree eager/lazy push (default for most message types).
    /// SPEC §8.1 — full message to eager, hash-only to lazy.
    Plumtree,
    /// Use ERLAY low-fanout flooding (for NewTransaction only).
    /// SPEC §8.3 — flood to flood_set, reconcile with rest.
    Erlay,
    /// Unicast response — do not broadcast, send only to requesting peer.
    Unicast,
}

/// Classify how a message should be broadcast based on its type.
///
/// SPEC §8.6 message types table:
/// - NewPeak, NewUnfinishedBlock, DIG attestation/checkpoint → Plumtree
/// - NewTransaction → ERLAY (if feature enabled, else Plumtree)
/// - RespondPeers, RespondTransaction → Unicast (not broadcast)
pub fn classify_broadcast(
    msg_type: ProtocolMessageTypes,
    #[allow(unused_variables)] erlay_enabled: bool,
) -> BroadcastStrategy {
    use ProtocolMessageTypes::*;
    match msg_type {
        // ERLAY: NewTransaction uses low-fanout flooding + reconciliation
        #[cfg(feature = "erlay")]
        NewTransaction if erlay_enabled => BroadcastStrategy::Erlay,

        // Plumtree: gossip messages use eager/lazy push
        NewPeak | NewTransaction | NewUnfinishedBlock | RespondBlock | RespondUnfinishedBlock => {
            BroadcastStrategy::Plumtree
        }

        // Unicast: response messages are not broadcast
        RespondPeers | RespondTransaction | RespondBlocks | RejectBlock | RejectBlocks => {
            BroadcastStrategy::Unicast
        }

        // Default: Plumtree for anything else
        _ => BroadcastStrategy::Plumtree,
    }
}

/// Determine priority for a broadcast message.
///
/// Convenience wrapper combining Chia and DIG type classification.
/// Used by `GossipHandle::broadcast()` for priority lane routing (INT-002).
pub fn broadcast_priority(msg_type: ProtocolMessageTypes) -> MessagePriority {
    MessagePriority::from_chia_type(msg_type)
}

/// Check if relay broadcast should be included (Plumtree step 7).
///
/// SPEC §8.1 step 7: "If relay connected: relay.broadcast(message, exclude_list)."
/// Returns true if relay should be used for this broadcast.
///
/// INT-005: relay supplements Plumtree to reach peers only accessible via relay.
pub fn should_relay_broadcast(relay_connected: bool, strategy: BroadcastStrategy) -> bool {
    relay_connected && strategy != BroadcastStrategy::Unicast
}
