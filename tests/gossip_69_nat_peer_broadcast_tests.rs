//! Regression tests for **dig-gossip#69 — a `dig-nat` peer received no broadcast at all.**
//!
//! ## The defect, and why it is a SECOND defect
//!
//! `fan_out` matched `PeerSlot::Nat(_)` and counted it `unreachable`, unconditionally. That is an
//! explicit filter in the broadcast path, entirely independent of whether the peer ever reaches the
//! pool: registering a relayed peer (#1871) makes it COUNTED, and it would still have received
//! nothing. A node that depends on a relay to hear announcements was silenced outright — measured
//! live as `announced_to_peers: 1` while the only peer that could act on it heard nothing.
//!
//! ## The fix under test
//!
//! A `dig-nat` peer has no `DigLink` and this crate frames nothing over the mux, so the broadcast
//! path had nothing to push into. The peer's session is owned by whoever serves it (#1871), so that
//! owner supplies a [`NatBroadcastSink`], drains it, and writes the frames. The fan-out treats such a
//! peer as an ordinary broadcast target and counts it as delivered only when the message was actually
//! queued for it.
//!
//! ## Fixture shape
//!
//! Every assertion is on the **bytes the peer received**, never on the delivery count alone: a count
//! is satisfied by a list containing the WRONG peers, which is precisely the half-fix shape this
//! change exists to avoid. Each fixture varies ONE actor and keeps a truthful control — a second NAT
//! peer that must hear the message when the first is excluded, and a sink-less peer beside a sinked
//! one so "delivered" cannot be read off a whole-pool default.

mod common;

use std::net::SocketAddr;

use dig_gossip::{DigMessage, GossipHandle, GossipService, NatBroadcastSink, PeerId};

/// Opcode 223 — PROFILE_ROOT_ANNOUNCE, the announcement a relayed node was never hearing.
const PROFILE_ROOT_ANNOUNCE: u8 = 223;

/// The unspecified IPv6 address recorded as the remote of an accepted relayed circuit (§5.2).
fn accepted_relayed_remote() -> SocketAddr {
    SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
}

fn announce(payload: u8) -> DigMessage {
    DigMessage::new(PROFILE_ROOT_ANNOUNCE, None, vec![payload; 64].into())
}

async fn running_handle() -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    (svc, handle, dir)
}

/// A relayed peer registered the way a node serving it does: liveness by handle, and a sink its
/// session owner drains. The live session is returned so the peer is not reaped mid-test.
async fn nat_peer(
    handle: &GossipHandle,
    id: u8,
    sinked: bool,
) -> (
    PeerId,
    Option<tokio::sync::mpsc::Receiver<DigMessage>>,
    dig_nat::PeerSession,
) {
    let (client_io, _server_io) = tokio::io::duplex(64 * 1024);
    let session = dig_nat::PeerSession::client(client_io);
    let peer_id = PeerId::from([id; 32]);
    let (sink, rx) = if sinked {
        let (s, r) = NatBroadcastSink::new(8);
        (Some(s), Some(r))
    } else {
        (None, None)
    };
    handle
        .adopt_relayed_inbound_handle(
            peer_id,
            accepted_relayed_remote(),
            session.closed_handle(),
            sink,
        )
        .await
        .expect("relayed peer adopted");
    (peer_id, rx, session)
}

/// The bytes a peer actually received, or `None` when it received nothing.
fn received(rx: &mut tokio::sync::mpsc::Receiver<DigMessage>) -> Option<DigMessage> {
    rx.try_recv().ok()
}

/// **The #69 core regression: a NAT peer RECEIVES the broadcast.**
///
/// The assertion is on the delivered frame — opcode and payload — because a count-only assertion is
/// satisfied by a send list holding any peer at all, including the one that was already reachable.
#[tokio::test]
async fn a_nat_peer_receives_the_broadcast_it_was_previously_denied() {
    let (svc, handle, _dir) = running_handle().await;
    let (_pid, rx, _session) = nat_peer(&handle, 0x41, true).await;
    let mut rx = rx.expect("a sinked peer has a receiver");

    let delivered = handle
        .broadcast_local(announce(0xAB), None)
        .await
        .expect("broadcast");

    let got = received(&mut rx).expect("the NAT peer must receive the announcement");
    assert_eq!(
        got.msg_type, PROFILE_ROOT_ANNOUNCE,
        "the peer receives the opcode that was broadcast"
    );
    assert_eq!(
        got.data.to_vec(),
        vec![0xABu8; 64],
        "and its payload, unaltered"
    );
    assert_eq!(delivered, 1, "and it is counted as a real delivery");

    svc.stop().await.expect("stop");
}

/// **The delivery list must hold the RIGHT peers.** Excluding one NAT peer must silence exactly that
/// peer and no other: the second NAT peer is the truthful control, so a fan-out that dropped every
/// NAT peer (the defect) and one that dropped the wrong peer are both distinguishable from correct.
#[tokio::test]
async fn excluding_one_nat_peer_silences_only_that_peer() {
    let (svc, handle, _dir) = running_handle().await;
    let (excluded_id, excluded_rx, _s1) = nat_peer(&handle, 0x51, true).await;
    let (_other_id, other_rx, _s2) = nat_peer(&handle, 0x52, true).await;
    let mut excluded_rx = excluded_rx.expect("receiver");
    let mut other_rx = other_rx.expect("receiver");

    let delivered = handle
        .broadcast_local(announce(0xCD), Some(excluded_id))
        .await
        .expect("broadcast");

    assert!(
        received(&mut excluded_rx).is_none(),
        "the excluded peer must receive nothing"
    );
    let got = received(&mut other_rx).expect("the other NAT peer must still receive it");
    assert_eq!(got.data.to_vec(), vec![0xCDu8; 64]);
    assert_eq!(delivered, 1, "exactly one peer was delivered to");

    svc.stop().await.expect("stop");
}

/// **A peer nobody can write to is still reported unreachable, not delivered.** The sinked peer
/// beside it is the control that keeps this from passing on a fan-out that reaches nobody: one
/// delivery, not two, and the bytes prove which peer got it (#3063 honesty preserved).
#[tokio::test]
async fn a_nat_peer_without_a_sink_is_not_counted_as_delivered() {
    let (svc, handle, _dir) = running_handle().await;
    let (_silent_id, none_rx, _s1) = nat_peer(&handle, 0x61, false).await;
    assert!(none_rx.is_none(), "a sink-less peer has no receiver");
    let (_reachable_id, reachable_rx, _s2) = nat_peer(&handle, 0x62, true).await;
    let mut reachable_rx = reachable_rx.expect("receiver");

    let delivered = handle
        .broadcast_local(announce(0xEF), None)
        .await
        .expect("broadcast");

    assert_eq!(
        delivered, 1,
        "only the peer that could be written to counts as delivered"
    );
    assert_eq!(
        received(&mut reachable_rx)
            .expect("the reachable peer receives it")
            .data
            .to_vec(),
        vec![0xEFu8; 64],
    );

    svc.stop().await.expect("stop");
}

/// **The sink may be attached AFTER adoption** — the dialer path adopts without one, and a caller may
/// start serving a peer later. A peer that was silent before the attach must hear the next broadcast.
/// Asserting the second announce alone would pass against a fan-out that ignores sinks entirely up to
/// some other condition, so the pre-attach silence is asserted first, on the same peer.
#[tokio::test]
async fn attaching_a_sink_after_adoption_makes_a_silent_peer_reachable() {
    let (svc, handle, _dir) = running_handle().await;
    let (peer_id, none_rx, _session) = nat_peer(&handle, 0x71, false).await;
    assert!(none_rx.is_none());

    assert_eq!(
        handle
            .broadcast_local(announce(0x01), None)
            .await
            .expect("broadcast"),
        0,
        "before a sink exists the peer is unreachable"
    );

    let (sink, mut rx) = NatBroadcastSink::new(8);
    handle
        .set_nat_broadcast_sink(peer_id, sink)
        .expect("the peer holds a dig-nat slot");

    let delivered = handle
        .broadcast_local(announce(0x02), None)
        .await
        .expect("broadcast");
    assert_eq!(delivered, 1, "after the attach it is a delivery target");
    assert_eq!(
        received(&mut rx)
            .expect("it receives the announcement")
            .data
            .to_vec(),
        vec![0x02u8; 64],
        "and receives the message broadcast after the attach"
    );

    svc.stop().await.expect("stop");
}

/// A sink cannot be attached to a peer that holds no `dig-nat` slot — the error names the peer rather
/// than silently doing nothing, which would leave a caller believing its peer was reachable.
#[tokio::test]
async fn attaching_a_sink_to_an_unknown_peer_is_an_error() {
    let (svc, handle, _dir) = running_handle().await;
    let (sink, _rx) = NatBroadcastSink::new(8);
    let err = handle
        .set_nat_broadcast_sink(PeerId::from([0x99; 32]), sink)
        .expect_err("no such dig-nat peer");
    assert!(
        matches!(err, dig_gossip::GossipError::PeerNotConnected(_)),
        "unexpected error: {err}"
    );
    svc.stop().await.expect("stop");
}

/// **A TRANSIENTLY full sink must not permanently hide a healthy peer.**
///
/// `offer` is a `try_send` on a `Sender` the slot RETAINS, and a full-sink failure never clears it —
/// so the next broadcast retries and the peer comes back the moment its owner drains. Nothing pinned
/// that, and the nearest wrong implementation is one line: treat a failed `try_send` as the peer
/// going away and drop (or `None`) the sink, which permanently silences a peer that was merely one
/// message behind. Under that version step 4 below receives nothing.
///
/// The fixture varies ONE actor. The peer under test gets a capacity-**1** sink so a single
/// un-drained message fills it exactly; a second NAT peer with room is the truthful control, so
/// "the full peer was skipped" is distinguishable from "the broadcast reached nobody" — the shape a
/// single-peer fixture cannot see. Each of the three broadcasts carries a DISTINCT payload, because
/// asserting merely that something arrived after the drain is satisfied by the pre-fill message
/// still sitting in the queue.
#[tokio::test]
async fn a_transiently_full_sink_does_not_permanently_hide_a_peer() {
    let (svc, handle, _dir) = running_handle().await;

    // The peer under test: adopted sink-less, then given a sink one message deep.
    let (peer_id, none_rx, _session) = nat_peer(&handle, 0x81, false).await;
    assert!(none_rx.is_none());
    let (sink, mut rx) = NatBroadcastSink::new(1);
    handle
        .set_nat_broadcast_sink(peer_id, sink)
        .expect("the peer holds a dig-nat slot");

    // The control: room for every message in this test, so it must hear all three.
    let (_control_id, control_rx, _control_session) = nat_peer(&handle, 0x82, true).await;
    let mut control_rx = control_rx.expect("receiver");

    // 1. Fill the sink. One message is its entire capacity, and nothing drains it.
    assert_eq!(
        handle
            .broadcast_local(announce(0xB1), None)
            .await
            .expect("broadcast"),
        2,
        "both peers are reachable while the sink has room"
    );

    // 2. Broadcast into the now-full sink. The peer is reported unreachable, NOT delivered — this
    //    is what proves the sink was genuinely full rather than the test asserting a no-op.
    assert_eq!(
        handle
            .broadcast_local(announce(0xB2), None)
            .await
            .expect("broadcast"),
        1,
        "a full sink makes only that peer unreachable; the control still receives it"
    );

    // 3. The session owner catches up. Only the first message was ever queued.
    let drained = received(&mut rx).expect("the first broadcast is still queued");
    assert_eq!(drained.data.to_vec(), vec![0xB1u8; 64]);
    assert!(
        received(&mut rx).is_none(),
        "the message offered to a full sink was never queued",
    );

    // 4. The peer is healthy again on the very next broadcast, with no re-attach and no re-adoption.
    assert_eq!(
        handle
            .broadcast_local(announce(0xB3), None)
            .await
            .expect("broadcast"),
        2,
        "a drained peer is a delivery target again",
    );
    assert_eq!(
        received(&mut rx)
            .expect("the recovered peer must receive the next broadcast")
            .data
            .to_vec(),
        vec![0xB3u8; 64],
        "and receives the message broadcast AFTER the drain, not the backlog",
    );

    // The control heard every broadcast, so no step above passed by silencing the whole fan-out.
    for expected in [0xB1u8, 0xB2, 0xB3] {
        assert_eq!(
            received(&mut control_rx)
                .unwrap_or_else(|| panic!("control missed the {expected:#04x} broadcast"))
                .data
                .to_vec(),
            vec![expected; 64],
        );
    }

    svc.stop().await.expect("stop");
}
