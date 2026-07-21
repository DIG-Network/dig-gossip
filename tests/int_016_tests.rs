//! INT-016 — per-opcode DIG L2 routing map (#1391).
//!
//! Asserts that every [`DigMessageType`] opcode routes by its DECLARED gossip
//! strategy (the `dig-peer-protocol` variant-grouping table) and that the wire
//! types are CONSUMED from `dig-peer-protocol` rather than hand-rolled in
//! dig-gossip — so the `200..=219` band can never drift between peer crates.

use dig_gossip::{route_dig_message, DigMessageType, RoutingStrategy};

/// The DIG opcode enum dig-gossip exposes IS the one defined in `dig-peer-protocol`
/// (type identity, not a same-named local copy). If dig-gossip ever re-introduced a
/// hand-rolled `DigMessageType`, this would fail to compile.
#[test]
fn dig_message_type_is_consumed_from_dig_peer_protocol() {
    // Binding to the dig_peer_protocol path and comparing against the dig_gossip
    // re-export proves they are the SAME type — a local shadow would be a distinct
    // type and this assignment would not type-check.
    let from_crate: dig_peer_protocol::DigMessageType =
        dig_peer_protocol::DigMessageType::NewAttestation;
    let via_gossip: DigMessageType = from_crate;
    assert_eq!(via_gossip as u8, 200);
    assert_eq!(DigMessageType::MAX_ASSIGNED, 219);
}

/// Plumtree eager push — latency-critical consensus data (200/201/202/207).
#[test]
fn plumtree_eager_class_routes_eager() {
    for op in [
        DigMessageType::NewAttestation,
        DigMessageType::NewCheckpointProposal,
        DigMessageType::NewCheckpointSignature,
        DigMessageType::NewCheckpointSubmission,
    ] {
        assert_eq!(
            route_dig_message(op),
            RoutingStrategy::PlumtreeEager,
            "{op:?} must route as Plumtree eager push"
        );
    }
}

/// Unicast request → a specific peer (203/205/209).
#[test]
fn unicast_request_class_routes_unicast_request() {
    for op in [
        DigMessageType::RequestCheckpointSignatures,
        DigMessageType::RequestStatus,
        DigMessageType::RequestBlockTransactions,
    ] {
        assert_eq!(
            route_dig_message(op),
            RoutingStrategy::UnicastRequest,
            "{op:?}"
        );
    }
}

/// Unicast response ← the requesting peer (204/206/210).
#[test]
fn unicast_response_class_routes_unicast_response() {
    for op in [
        DigMessageType::RespondCheckpointSignatures,
        DigMessageType::RespondStatus,
        DigMessageType::RespondBlockTransactions,
    ] {
        assert_eq!(
            route_dig_message(op),
            RoutingStrategy::UnicastResponse,
            "{op:?}"
        );
    }
}

/// Broadcast flood — validator directory announce (208).
#[test]
fn validator_announce_routes_broadcast_flood() {
    assert_eq!(
        route_dig_message(DigMessageType::ValidatorAnnounce),
        RoutingStrategy::BroadcastFlood
    );
}

/// ERLAY set-reconciliation (211/212).
#[test]
fn erlay_class_routes_reconciliation() {
    for op in [
        DigMessageType::ReconciliationSketch,
        DigMessageType::ReconciliationResponse,
    ] {
        assert_eq!(
            route_dig_message(op),
            RoutingStrategy::ErlayReconciliation,
            "{op:?}"
        );
    }
}

/// Dandelion++ stem (213).
#[test]
fn stem_transaction_routes_dandelion_stem() {
    assert_eq!(
        route_dig_message(DigMessageType::StemTransaction),
        RoutingStrategy::DandelionStem
    );
}

/// Plumtree lazy announce / control / pull (214 / 215+216 / 217).
#[test]
fn plumtree_lazy_control_and_pull_route_correctly() {
    assert_eq!(
        route_dig_message(DigMessageType::PlumtreeLazyAnnounce),
        RoutingStrategy::PlumtreeLazy
    );
    for op in [DigMessageType::PlumtreePrune, DigMessageType::PlumtreeGraft] {
        assert_eq!(
            route_dig_message(op),
            RoutingStrategy::PlumtreeControl,
            "{op:?}"
        );
    }
    assert_eq!(
        route_dig_message(DigMessageType::PlumtreeRequestByHash),
        RoutingStrategy::PlumtreePull
    );
}

/// Introducer registration handshake — unicast, directed at the introducer (218/219).
#[test]
fn introducer_register_class_routes_unicast_directed() {
    assert_eq!(
        route_dig_message(DigMessageType::RegisterPeer),
        RoutingStrategy::UnicastToIntroducer
    );
    assert_eq!(
        route_dig_message(DigMessageType::RegisterAck),
        RoutingStrategy::UnicastFromIntroducer
    );
}

/// No opcode is mis-routed: every declared opcode maps to exactly the class the
/// `dig-peer-protocol` table assigns — no eager type flooded, no unicast broadcast.
#[test]
fn every_opcode_routes_by_declared_strategy() {
    let expected = |op: DigMessageType| -> RoutingStrategy {
        match op as u8 {
            200 | 201 | 202 | 207 => RoutingStrategy::PlumtreeEager,
            203 | 205 | 209 => RoutingStrategy::UnicastRequest,
            204 | 206 | 210 => RoutingStrategy::UnicastResponse,
            208 => RoutingStrategy::BroadcastFlood,
            211 | 212 => RoutingStrategy::ErlayReconciliation,
            213 => RoutingStrategy::DandelionStem,
            214 => RoutingStrategy::PlumtreeLazy,
            215 | 216 => RoutingStrategy::PlumtreeControl,
            217 => RoutingStrategy::PlumtreePull,
            218 => RoutingStrategy::UnicastToIntroducer,
            219 => RoutingStrategy::UnicastFromIntroducer,
            other => panic!("unassigned opcode {other} in DigMessageType::ALL"),
        }
    };
    for op in DigMessageType::ALL {
        assert_eq!(
            route_dig_message(op),
            expected(op),
            "opcode {} mis-routed",
            op as u8
        );
    }
}
