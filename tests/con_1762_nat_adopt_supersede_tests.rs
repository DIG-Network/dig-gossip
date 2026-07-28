//! Regression tests for **dig_ecosystem#1762 — a stale `dig-nat` pool slot must not refuse the
//! adoption that would work.**
//!
//! ## The defect
//!
//! [`GossipHandle::adopt_nat_connection`] is the single path EVERY `dig-nat` connection is adopted
//! through — relayed and direct alike. Up to v0.17.11 it refused on a bare
//! `peers.contains_key(&peer_id)` with no liveness check and no reap, so a relay circuit that
//! registered a slot and then died (its mTLS failed — #1761 — or the circuit simply timed out) left an
//! entry that refused the DIRECT adoption which would have succeeded: `duplicate connection to peer`
//! on one side, `connected_peers: 0` on the other. A broken path poisoned a working one.
//!
//! ## The fix under test — newest-wins supersession (over the CLASS, not one cause)
//!
//! Adoption no longer refuses a held slot at all; the freshly mTLS-authenticated `dig-nat` session
//! SUPERSEDES it at insert time, matching the policy already shipped for the inbound path (#1691) and
//! `connect_to` (#1703). Staleness has many causes — a dead relay circuit, a half-open TCP link, a
//! vanished peer, a timed-out mapping — and a guard justified by any single one is bypassed by the
//! next variant, so the rule is stated over the class: **a held slot never refuses a newer verified
//! session for the same identity.** The two admission budgets are exempted only where the arithmetic
//! demands it (a replacement does not grow the map; a re-dial of a peer already occupying a group is
//! not net-new occupancy) — every NET-NEW identity still faces the full cap, which each test below
//! pins from BOTH sides.
//!
//! Every assertion is on OBSERVABLE pool state (`pool_stats`, `connected_pool_peers`,
//! `connected_pool_peers_with_via`) — never a log line, which prints on the broken path too. In
//! particular the `Via` assertion distinguishes a genuine supersede from a guard that returns `Ok`
//! while leaving the dead relayed slot in place.

mod common;

use std::net::SocketAddr;

use dig_gossip::{GossipError, GossipHandle, GossipService, PeerPoolConfig};
use dig_nat::TraversalKind;

/// Build a `NatPeerConnection` over a loopback duplex with a chosen `peer_id`, remote address, and
/// traversal tier, so it can be adopted WITHOUT a real network (the `con_1716` technique — a real
/// yamux session, just not over TLS). The returned [`dig_nat::PeerSession`] is the SERVER half: hold
/// it to keep the session live, **drop it to kill the session** (which is how these tests make a
/// relay circuit genuinely dead rather than merely asserting about one).
fn loopback_nat_conn(
    peer_id_bytes: [u8; 32],
    remote: SocketAddr,
    method: TraversalKind,
) -> (dig_gossip::NatPeerConnection, dig_nat::PeerSession) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let inner = dig_nat::PeerConnection {
        peer_id: dig_nat::PeerId::from_bytes(peer_id_bytes),
        method,
        remote_addr: remote,
        peer_bls_pub: None,
        session: dig_nat::PeerSession::client(client_io),
    };
    let server = dig_nat::PeerSession::server(server_io);
    (dig_gossip::NatPeerConnection::new(inner), server)
}

/// A running handle whose overall connection cap and outbound target are caller-chosen (the two
/// budgets adoption enforces).
async fn running_handle(
    max_connections: usize,
    target_outbound: usize,
) -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = max_connections;
    cfg.target_outbound_count = target_outbound;
    cfg.peer_pool = Some(PeerPoolConfig {
        min_peers: 1,
        target_peers: 8,
        max_peers: 32,
        // Long interval so the background maintenance loop never fires mid-test.
        maintenance_interval_secs: 3600,
        ..Default::default()
    });
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    (svc, handle, dir)
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// The traversal tier the pool currently reaches `peer` over, or `None` if it is not a pool member.
fn via_of(handle: &GossipHandle, peer: dig_gossip::PeerId) -> Option<dig_gossip::Via> {
    handle
        .connected_pool_peers_with_via()
        .into_iter()
        .find(|(id, _)| *id == peer)
        .map(|(_, via)| via)
}

/// **The defect, in its real ORDER: dead relay circuit FIRST, then the direct dial.**
///
/// The relayed adoption is admitted (dig-gossip cannot know the circuit is doomed), its circuit then
/// dies, and the direct adoption of the SAME peer must succeed and become the path the pool reports.
/// Addresses are IPv6 (§5.2 IPv6-first): the live fleet transfer that surfaced this ran over IPv6, so
/// the fixture must not quietly prove the property only for v4.
#[tokio::test]
async fn a_dead_relay_circuit_does_not_refuse_the_direct_adoption() {
    let (svc, handle, _dir) = running_handle(64, 8).await;
    let peer = dig_gossip::PeerId::from([0x3c; 32]);

    // An honest, UNRELATED peer stays connected throughout — the truthful control. It proves the
    // supersede is surgical (it replaces exactly one slot) rather than a pool-wide reset that would
    // make the direct adoption "succeed" for the wrong reason.
    let (bystander, keep_bystander) = loopback_nat_conn(
        [0x11; 32],
        addr("[2001:db8:1::5]:9251"),
        TraversalKind::Direct,
    );
    handle
        .adopt_nat_connection(bystander)
        .await
        .expect("bystander admitted");

    // 1. The relayed circuit is adopted — `remote` is the RELAY endpoint, as dig-nat reports it.
    let (relayed, relay_server) = loopback_nat_conn(
        [0x3c; 32],
        addr("[2001:db8:2::9]:9440"),
        TraversalKind::Relayed,
    );
    handle
        .adopt_nat_connection(relayed)
        .await
        .expect("relayed circuit adopted");
    assert_eq!(
        via_of(&handle, peer),
        Some(dig_gossip::Via::Relay),
        "precondition: the pool reaches the peer over the relay"
    );

    // 2. The circuit dies (its mTLS failed / it timed out) — the server half goes away.
    drop(relay_server);

    // 3. The direct dial that WORKS is adopted. Before the fix this returned
    //    `DuplicateConnection` and the peer stayed unreachable behind the dead circuit.
    let (direct, keep_direct) = loopback_nat_conn(
        [0x3c; 32],
        addr("[2001:db8:3::7]:9250"),
        TraversalKind::Direct,
    );
    handle
        .adopt_nat_connection(direct)
        .await
        .expect("the direct adoption must not be refused by the dead relay circuit's slot");

    assert_eq!(
        via_of(&handle, peer),
        Some(dig_gossip::Via::Direct),
        "the DIRECT session must have superseded the dead relayed slot, not merely been accepted \
         while the pool still points at the relay"
    );
    assert_eq!(
        handle
            .connected_pool_peers()
            .into_iter()
            .find(|(id, _, _)| *id == peer)
            .map(|(_, a, _)| a),
        Some(addr("[2001:db8:3::7]:9250")),
        "the pool must report the peer's own direct address, not the dead relay endpoint"
    );
    assert_eq!(
        handle.pool_stats().connected,
        2,
        "one slot per peer_id: the bystander plus the superseded peer, never a third entry"
    );

    let _ = (keep_bystander, keep_direct);
    svc.stop().await.expect("stop");
}

/// **The overall connection cap must not strand a peer behind its own stale slot** — and must still
/// refuse a net-new identity. A replacement does not grow the map, so it is exempt; a NET-NEW peer at
/// the cap is refused. Pinning the bound from both sides is what makes the exemption honest rather
/// than a hole.
#[tokio::test]
async fn at_the_connection_cap_a_stale_slot_yields_to_its_own_redial_but_not_to_a_new_peer() {
    // `target_outbound_count` must not exceed `max_connections` (config validation), so the cap of 2
    // carries an outbound target of 2 here; the relayed budget is exercised by the test below.
    let (svc, handle, _dir) = running_handle(2, 2).await;
    let peer = dig_gossip::PeerId::from([0x3c; 32]);

    let (bystander, keep_bystander) = loopback_nat_conn(
        [0x11; 32],
        addr("[2001:db8:1::5]:9251"),
        TraversalKind::Direct,
    );
    handle
        .adopt_nat_connection(bystander)
        .await
        .expect("bystander admitted");
    let (relayed, relay_server) = loopback_nat_conn(
        [0x3c; 32],
        addr("[2001:db8:2::9]:9440"),
        TraversalKind::Relayed,
    );
    handle
        .adopt_nat_connection(relayed)
        .await
        .expect("relayed circuit adopted — the pool is now at max_connections=2");
    drop(relay_server);

    // At the cap: the same peer's working direct session replaces its own slot (map size unchanged).
    let (direct, keep_direct) = loopback_nat_conn(
        [0x3c; 32],
        addr("[2001:db8:3::7]:9250"),
        TraversalKind::Direct,
    );
    handle
        .adopt_nat_connection(direct)
        .await
        .expect("a replacement does not grow the map, so the cap must not strand the peer");
    assert_eq!(via_of(&handle, peer), Some(dig_gossip::Via::Direct));
    assert_eq!(handle.pool_stats().connected, 2, "still exactly at the cap");

    // One over the bound: a NET-NEW identity genuinely would grow the map and is refused.
    let (newcomer, keep_newcomer) = loopback_nat_conn(
        [0x22; 32],
        addr("[2001:db8:4::8]:9252"),
        TraversalKind::Direct,
    );
    let err = handle.adopt_nat_connection(newcomer).await;
    assert!(
        matches!(err, Err(GossipError::MaxConnectionsReached(2))),
        "a net-new identity at the cap must still be refused, got {err:?}"
    );

    let _ = (keep_bystander, keep_direct, keep_newcomer);
    svc.stop().await.expect("stop");
}

/// **The relayed-outbound cap (INT-006a) must not refuse a relayed peer's own re-dial** — its slot is
/// counted in the very total being checked, so an unexempted count is off by one and the last relayed
/// peer could never recover from a dead circuit. The net-new bound is asserted from both sides in the
/// same test: at the cap, a distinct new relayed identity is still refused.
#[tokio::test]
async fn at_the_relayed_cap_a_relayed_peer_can_redial_but_a_new_relayed_identity_cannot() {
    // target_outbound_count = 8 → max_relayed_outbound = 6 (the published bound).
    let (svc, handle, _dir) = running_handle(64, 8).await;
    let mut keep = Vec::new();

    for i in 1..=6u8 {
        let (conn, server) = loopback_nat_conn(
            [i; 32],
            addr(&format!("[2001:db8:2::{i}]:9440")),
            TraversalKind::Relayed,
        );
        keep.push(server);
        handle
            .adopt_nat_connection(conn)
            .await
            .expect("relayed adoption below the cap");
    }
    assert_eq!(handle.pool_stats().connected, 6, "at the relayed cap");

    // At the cap, peer 6's circuit dies and it re-dials over the relay: admitted (it already occupies
    // one of the six relayed slots — replacing it is not a seventh).
    keep.pop();
    let (redial, keep_redial) = loopback_nat_conn(
        [6u8; 32],
        addr("[2001:db8:2::66]:9441"),
        TraversalKind::Relayed,
    );
    handle
        .adopt_nat_connection(redial)
        .await
        .expect("a relayed peer already holding a slot must be able to re-dial at the cap");
    assert_eq!(handle.pool_stats().connected, 6, "still six relayed peers");

    // One over the bound: a SEVENTH distinct relayed identity is refused.
    let (over, keep_over) = loopback_nat_conn(
        [0x77; 32],
        addr("[2001:db8:2::77]:9442"),
        TraversalKind::Relayed,
    );
    let err = handle.adopt_nat_connection(over).await;
    assert!(
        matches!(err, Err(GossipError::ConnectionFiltered(ref m)) if m.contains("INT-006a")),
        "a net-new relayed identity at the cap must still be refused, got {err:?}"
    );

    let _ = (keep, keep_redial, keep_over);
    svc.stop().await.expect("stop");
}

/// **A banned peer holding a slot is still refused.** Supersession relaxes the DUPLICATE rule only;
/// the ban (CON-007) and self-connection (#1584) guards run before it and are unaffected — a
/// re-adoption is not a way around them.
#[tokio::test]
async fn supersession_does_not_let_a_banned_peer_re_enter_the_pool() {
    let (svc, handle, _dir) = running_handle(64, 8).await;
    let peer = dig_gossip::PeerId::from([0x3c; 32]);

    let (relayed, relay_server) = loopback_nat_conn(
        [0x3c; 32],
        addr("[2001:db8:2::9]:9440"),
        TraversalKind::Relayed,
    );
    handle
        .adopt_nat_connection(relayed)
        .await
        .expect("relayed circuit adopted");
    drop(relay_server);

    handle
        .ban_peer(&peer, dig_gossip::PenaltyReason::MalformedMessage)
        .await
        .expect("ban");

    let (direct, keep_direct) = loopback_nat_conn(
        [0x3c; 32],
        addr("[2001:db8:3::7]:9250"),
        TraversalKind::Direct,
    );
    let err = handle.adopt_nat_connection(direct).await;
    assert!(
        matches!(err, Err(GossipError::PeerBanned(_))),
        "a banned peer must not be re-adopted via supersession, got {err:?}"
    );

    let _ = keep_direct;
    svc.stop().await.expect("stop");
}
