//! DIG L2 protocol message types (`200..=219`) and their per-opcode gossip routing.
//!
//! # Single source of truth: `dig-peer-protocol`
//!
//! [`DigMessageType`] and [`UnknownDigMessageType`] are **consumed from
//! [`dig_peer_protocol`]**, not hand-rolled here. `dig-peer-protocol` is the
//! ecosystem's authoritative wire crate (the rename of the former `dig-protocol`,
//! #1383): every peer crate that speaks the DIG L2 wire shares that one definition,
//! so the `200..=219` discriminants, their `u8` serde encoding, and the
//! `TryFrom<u8>` band-check can never drift between implementations. dig-gossip
//! re-exports them at this stable module path for its own consumers.
//!
//! # What this module OWNS
//!
//! The per-opcode **routing strategy** — [`RoutingStrategy`] and
//! [`route_dig_message`] — is dig-gossip's concern (dig-peer-protocol defines only
//! the discriminants + framing; the dissemination strategy is the transport's
//! responsibility). The mapping below is authoritative and mirrors the
//! `dig-peer-protocol` variant-grouping table:
//!
//! | Opcodes | Strategy |
//! |---------|----------|
//! | 200 `NewAttestation`, 201 `NewCheckpointProposal`, 202 `NewCheckpointSignature`, 207 `NewCheckpointSubmission` | [`RoutingStrategy::PlumtreeEager`] |
//! | 203 `RequestCheckpointSignatures`, 205 `RequestStatus`, 209 `RequestBlockTransactions` | [`RoutingStrategy::UnicastRequest`] |
//! | 204 `RespondCheckpointSignatures`, 206 `RespondStatus`, 210 `RespondBlockTransactions` | [`RoutingStrategy::UnicastResponse`] |
//! | 208 `ValidatorAnnounce` | [`RoutingStrategy::BroadcastFlood`] |
//! | 211 `ReconciliationSketch`, 212 `ReconciliationResponse` | [`RoutingStrategy::ErlayReconciliation`] |
//! | 213 `StemTransaction` | [`RoutingStrategy::DandelionStem`] |
//! | 214 `PlumtreeLazyAnnounce` | [`RoutingStrategy::PlumtreeLazy`] |
//! | 215 `PlumtreePrune`, 216 `PlumtreeGraft` | [`RoutingStrategy::PlumtreeControl`] |
//! | 217 `PlumtreeRequestByHash` | [`RoutingStrategy::PlumtreePull`] |
//! | 218 `RegisterPeer` | [`RoutingStrategy::UnicastToIntroducer`] |
//! | 219 `RegisterAck` | [`RoutingStrategy::UnicastFromIntroducer`] |
//!
//! ## Requirements
//!
//! - **API-009:** [`docs/requirements/domains/crate_api/specs/API-009.md`](../../../docs/requirements/domains/crate_api/specs/API-009.md)
//! - **SPEC:** [`docs/resources/SPEC.md`](../../../docs/resources/SPEC.md) §2.3, §8

// DigMessageType / UnknownDigMessageType are re-exported from the authoritative wire crate.
// Consumers keep importing them from this stable module path (and via the `dig_gossip::` prelude).
pub use dig_peer_protocol::{DigMessageType, UnknownDigMessageType};

/// How a [`DigMessageType`] must be disseminated on the DIG L2 gossip overlay.
///
/// Each DIG opcode carries exactly one declared strategy (see the module-level table);
/// [`route_dig_message`] is the single authority that maps an opcode to its strategy so
/// no message is ever mis-routed (e.g. a Plumtree-eager consensus type flooded naively, or
/// a unicast response broadcast to every peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoutingStrategy {
    /// Full payload eager-pushed along the Plumtree spanning tree (SPEC §8.1).
    /// Latency-critical consensus data: attestations + checkpoint proposal/signature/submission.
    PlumtreeEager,
    /// Hash-only announcement to lazy (non-tree) peers (SPEC §8.1, opcode 214).
    PlumtreeLazy,
    /// Plumtree tree-maintenance control: PRUNE (215) / GRAFT (216).
    PlumtreeControl,
    /// Explicit pull of a full payload by hash after a lazy announce (SPEC §8.1, opcode 217).
    PlumtreePull,
    /// Point-to-point request to a specific peer (no fan-out).
    UnicastRequest,
    /// Point-to-point response paired with a prior [`UnicastRequest`](Self::UnicastRequest).
    UnicastResponse,
    /// Flooded to every connected peer (validator directory announce, opcode 208).
    BroadcastFlood,
    /// ERLAY set-reconciliation exchange (SPEC §8.3, opcodes 211/212).
    ErlayReconciliation,
    /// Dandelion++ stem-phase forwarding — one hop along the stem before fluff (SPEC §1.9.1).
    DandelionStem,
    /// Self-registration sent TO the introducer (opcode 218).
    UnicastToIntroducer,
    /// Registration acknowledgement received FROM the introducer (opcode 219).
    UnicastFromIntroducer,
}

/// Map a [`DigMessageType`] opcode to its authoritative [`RoutingStrategy`].
///
/// This is the single per-opcode routing authority for the DIG L2 band. It is exhaustive
/// over [`DigMessageType`], so adding a new opcode upstream forces a routing decision here
/// at compile time rather than silently falling through to a default.
#[must_use]
pub fn route_dig_message(msg_type: DigMessageType) -> RoutingStrategy {
    use DigMessageType::*;
    match msg_type {
        // Plumtree eager push — latency-critical consensus data (SPEC §8.1).
        NewAttestation | NewCheckpointProposal | NewCheckpointSignature | NewCheckpointSubmission => {
            RoutingStrategy::PlumtreeEager
        }

        // Unicast request → a specific peer.
        RequestCheckpointSignatures | RequestStatus | RequestBlockTransactions => {
            RoutingStrategy::UnicastRequest
        }

        // Unicast response ← the requesting peer.
        RespondCheckpointSignatures | RespondStatus | RespondBlockTransactions => {
            RoutingStrategy::UnicastResponse
        }

        // Broadcast flood — validator directory announcement.
        ValidatorAnnounce => RoutingStrategy::BroadcastFlood,

        // ERLAY set-reconciliation (SPEC §8.3).
        ReconciliationSketch | ReconciliationResponse => RoutingStrategy::ErlayReconciliation,

        // Dandelion++ stem-phase transaction (SPEC §1.9.1).
        StemTransaction => RoutingStrategy::DandelionStem,

        // Plumtree lazy / control / pull (SPEC §8.1).
        PlumtreeLazyAnnounce => RoutingStrategy::PlumtreeLazy,
        PlumtreePrune | PlumtreeGraft => RoutingStrategy::PlumtreeControl,
        PlumtreeRequestByHash => RoutingStrategy::PlumtreePull,

        // Introducer registration handshake — unicast, directed at the introducer.
        RegisterPeer => RoutingStrategy::UnicastToIntroducer,
        RegisterAck => RoutingStrategy::UnicastFromIntroducer,
    }
}
