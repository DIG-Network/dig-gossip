//! INT-017 — `route_dig_message` as the live per-opcode dispatch authority (#1404).
//!
//! [`GossipHandle::broadcast_dig`] and [`GossipHandle::send_dig`] are the ONLY sanctioned
//! way to put a DIG 200-219 opcode on the wire. Both consult [`route_dig_message`] so a DIG
//! L2 message can never mis-route: a fan-out strategy MUST go through `broadcast_dig` (which
//! owns seen-set dedup + message-cache), a unicast strategy MUST go through `send_dig` (a
//! directed request is NOT content-deduped), introducer traffic is rejected toward its
//! dedicated socket, and a strategy with no live producer fails safe instead of silently
//! sending on the wrong shape.

mod common;

use std::net::SocketAddr;

use dig_gossip::{
    route_dig_message, DigMessageType, GossipError, GossipHandle, GossipService, NodeType, PeerId,
    RoutingStrategy,
};

/// The dispatch OUTCOME class an opcode resolves to — the observable shape of dispatch,
/// derived purely from behaviour (which entry point accepts it / which error it returns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Delivered via `broadcast_dig` (fan-out); `send_dig` rejects with `WrongDispatchShape`.
    FanOut,
    /// Delivered via `send_dig` (unicast); `broadcast_dig` rejects with `WrongDispatchShape`.
    Unicast,
    /// Both entry points reject toward the dedicated introducer socket.
    Introducer,
    /// Both entry points fail safe — no live producer yet.
    NoProducer,
}

/// The shape [`route_dig_message`] declares for `op` — the source of truth the dispatch
/// authority MUST agree with. Kept as a separate mapping so a mis-mapped leg is caught.
fn expected_shape(op: DigMessageType) -> Shape {
    match route_dig_message(op) {
        RoutingStrategy::PlumtreeEager | RoutingStrategy::BroadcastFlood => Shape::FanOut,
        RoutingStrategy::UnicastRequest | RoutingStrategy::UnicastResponse => Shape::Unicast,
        RoutingStrategy::UnicastToIntroducer | RoutingStrategy::UnicastFromIntroducer => {
            Shape::Introducer
        }
        RoutingStrategy::ErlayReconciliation
        | RoutingStrategy::DandelionStem
        | RoutingStrategy::PlumtreeLazy
        | RoutingStrategy::PlumtreeControl
        | RoutingStrategy::PlumtreePull => Shape::NoProducer,
    }
}

/// A running service plus one connected outbound stub peer (its [`PeerId`] returned).
async fn handle_with_peer() -> (GossipService, GossipHandle, PeerId) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    let addr: SocketAddr = "127.0.0.1:9701".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(addr, NodeType::FullNode, true)
        .await
        .expect("stub peer");
    (svc, h, pid)
}

/// Test 1 — an eager opcode dispatched via `broadcast_dig` reaches the broadcast path:
/// it delivers to the peer set AND is entered into the seen-set/message-cache (the tell-tale
/// that it went through `broadcast()`, not a raw directed send).
#[tokio::test]
async fn eager_opcode_dispatches_to_broadcast() {
    let (_s, h, _pid) = handle_with_peer().await;
    let delivered = h
        .broadcast_dig(DigMessageType::NewAttestation, vec![1, 2, 3])
        .await
        .expect("eager broadcast_dig");
    assert_eq!(delivered, 1, "one stub peer must receive the eager push");
    let st = h.stats().await;
    assert!(
        st.seen_messages >= 1,
        "broadcast() must record the message in the seen-set (dedup + cache)"
    );
}

/// Test 2 — a unicast-request opcode dispatched via `send_dig` reaches the peer as a directed
/// message and is NOT seen-set-deduped (a directed request must never be content-deduped).
#[tokio::test]
async fn unicast_request_opcode_dispatches_directed() {
    let (_s, h, pid) = handle_with_peer().await;
    h.send_dig(pid, DigMessageType::RequestStatus, vec![9, 9])
        .await
        .expect("unicast send_dig");
    let st = h.stats().await;
    assert_eq!(
        st.seen_messages, 0,
        "a directed unicast must NOT enter the seen-set (never content-deduped)"
    );
    assert!(
        st.messages_sent >= 1,
        "the directed message must have been delivered to the peer"
    );
}

/// Test 3 — every strategy with no live producer fails safe: `StrategyNotYetProduced`
/// carrying the matching strategy + opcode, and NOTHING is sent (no seen-set entry).
#[tokio::test]
async fn no_producer_strategy_is_fail_safe() {
    for op in [
        DigMessageType::ReconciliationSketch,   // 211
        DigMessageType::ReconciliationResponse, // 212
        DigMessageType::StemTransaction,        // 213
        DigMessageType::PlumtreeLazyAnnounce,   // 214
        DigMessageType::PlumtreePrune,          // 215
        DigMessageType::PlumtreeGraft,          // 216
        DigMessageType::PlumtreeRequestByHash,  // 217
    ] {
        let (_s, h, pid) = handle_with_peer().await;
        let via_broadcast = h.broadcast_dig(op, vec![0]).await;
        let via_send = h.send_dig(pid, op, vec![0]).await;
        for res in [via_broadcast.map(|_| ()), via_send] {
            match res {
                Err(GossipError::StrategyNotYetProduced { strategy, opcode }) => {
                    assert_eq!(strategy, route_dig_message(op), "{op:?} strategy");
                    assert_eq!(opcode, op as u8, "{op:?} opcode");
                }
                other => panic!("{op:?} must fail safe, got {other:?}"),
            }
        }
        assert_eq!(
            h.stats().await.seen_messages,
            0,
            "{op:?} must not have been sent"
        );
    }
}

/// Test 4 — introducer opcodes classify correctly but route to the dedicated method.
#[tokio::test]
async fn introducer_opcodes_route_to_dedicated_method() {
    for op in [DigMessageType::RegisterPeer, DigMessageType::RegisterAck] {
        let (_s, h, pid) = handle_with_peer().await;
        assert!(
            matches!(
                h.broadcast_dig(op, vec![0]).await,
                Err(GossipError::UseDedicatedIntroducerMethod)
            ),
            "{op:?} via broadcast_dig"
        );
        assert!(
            matches!(
                h.send_dig(pid, op, vec![0]).await,
                Err(GossipError::UseDedicatedIntroducerMethod)
            ),
            "{op:?} via send_dig"
        );
    }
}

/// Test 5 — calling the wrong entry point for a shape is rejected with `WrongDispatchShape`.
#[tokio::test]
async fn wrong_dispatch_shape_rejected() {
    let (_s, h, pid) = handle_with_peer().await;
    // Eager (fan-out) may only be broadcast — never sent unicast.
    assert!(matches!(
        h.send_dig(pid, DigMessageType::NewAttestation, vec![1])
            .await,
        Err(GossipError::WrongDispatchShape)
    ));
    // Unicast-request may only be sent unicast — never broadcast.
    assert!(matches!(
        h.broadcast_dig(DigMessageType::RequestStatus, vec![1])
            .await,
        Err(GossipError::WrongDispatchShape)
    ));
}

/// Test 6 (THE anti-drift guard) — for EVERY DIG opcode, the observable dispatch outcome-class
/// equals the class [`route_dig_message`] declares. This MUST fail if any leg is mis-mapped:
/// mis-routing (e.g. sending an eager type unicast, or a unicast type via broadcast) flips the
/// observed [`Shape`] and trips the assert, so the two mappings can never silently diverge.
#[tokio::test]
async fn dispatch_matches_router_for_every_opcode() {
    for op in DigMessageType::ALL {
        let (_s, h, pid) = handle_with_peer().await;
        let via_broadcast = h.broadcast_dig(op, vec![7]).await;
        let via_send = h.send_dig(pid, op, vec![7]).await;

        let observed = match (&via_broadcast, &via_send) {
            (Ok(_), Err(GossipError::WrongDispatchShape)) => Shape::FanOut,
            (Err(GossipError::WrongDispatchShape), Ok(())) => Shape::Unicast,
            (
                Err(GossipError::UseDedicatedIntroducerMethod),
                Err(GossipError::UseDedicatedIntroducerMethod),
            ) => Shape::Introducer,
            (
                Err(GossipError::StrategyNotYetProduced { .. }),
                Err(GossipError::StrategyNotYetProduced { .. }),
            ) => Shape::NoProducer,
            other => panic!(
                "opcode {} produced an unclassifiable pair {other:?}",
                op as u8
            ),
        };
        assert_eq!(
            observed,
            expected_shape(op),
            "opcode {} dispatch class disagrees with route_dig_message",
            op as u8
        );
    }
}
