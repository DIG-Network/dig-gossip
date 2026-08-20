//! Integration tests for **dig_ecosystem#3128 requirement 8 — content discovery must be able to
//! displace an UNUSED persistent connection to admit a holder it found.**
//!
//! ## The gap these close
//!
//! Eviction in this pool was failure-only: `PoolRemovalReason` could express `Disconnected`, `Dead`,
//! `Banned` and `Reaped` and nothing else, and at the connection cap admission was simply REFUSED. So
//! a holder the DHT found outside the persistent set was dialled once, read from, and dropped — and
//! rediscovered from scratch on every future read.
//!
//! ## Why these fixtures are shaped the way they are
//!
//! The pure policy (which peer, under which bounds) is unit-tested next to
//! [`dig_gossip::plan_displacement`], each bound pinned from both sides. What only an integration
//! fixture can show is that the policy is WIRED: that the discovery entry point reaches it, that the
//! ordinary entry point does NOT (so the capability is scoped rather than a general loosening of the
//! cap), that the eclipse caps still refuse a discovered peer BEFORE anything is evicted for it, and
//! that a displaced observed session's owner is told — which is why dig-gossip#71 was a prerequisite
//! rather than a follow-up.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dig_gossip::{
    GossipError, GossipHandle, GossipService, ObservedSession, PeerPoolConfig, PoolEvent,
    PoolRemovalReason,
};
use dig_nat::TraversalKind;

/// Build a `NatPeerConnection` over a loopback duplex with a chosen `peer_id`, remote address and
/// traversal tier, so it can be adopted WITHOUT a real network (the `con_1762` technique). The
/// returned server half must be held: dropping it kills the session.
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
    (
        dig_gossip::NatPeerConnection::new(inner),
        dig_nat::PeerSession::server(server_io),
    )
}

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("test address")
}

/// A running handle at a caller-chosen connection cap, with the three displacement bounds set
/// explicitly so a fixture never depends on the shipped 300s/600s/600s defaults.
async fn running_handle(
    max_connections: usize,
    pool: PeerPoolConfig,
) -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = max_connections;
    cfg.target_outbound_count = max_connections;
    cfg.peer_pool = Some(pool);
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    (svc, handle, dir)
}

/// Bounds that permit a displacement immediately — the fixtures that exercise the WIRING rather than
/// the thresholds, which the pure planner tests already pin from both sides.
fn unbounded_displacement(min_peers: usize) -> PeerPoolConfig {
    PeerPoolConfig {
        min_peers,
        target_peers: min_peers.max(2),
        max_peers: 16,
        min_idle_secs: 0,
        min_established_secs: 0,
        displacement_interval_secs: 0,
        ..Default::default()
    }
}

/// **The core of requirement 8, with the control that scopes it.**
///
/// At the cap, a net-new identity offered through the ORDINARY entry point is refused — unchanged,
/// and asserted here because without it "discovery admitted a peer at the cap" is equally consistent
/// with having simply raised the cap for everyone. Offered through the DISCOVERY entry point the same
/// identity is admitted, an incumbent is cycled out, and the map does not grow.
#[tokio::test]
async fn at_the_cap_discovery_displaces_an_unused_peer_where_ordinary_admission_is_refused() {
    let (svc, handle, _dir) = running_handle(2, unbounded_displacement(1)).await;
    let mut churn = handle
        .subscribe_pool_events()
        .expect("the churn bus is wired once the service is running");

    let (first, keep_first) = loopback_nat_conn(
        [0x11; 32],
        addr("[2001:db8::5]:9251"),
        TraversalKind::Direct,
    );
    handle
        .adopt_nat_connection(first)
        .await
        .expect("first peer");
    let (second, keep_second) = loopback_nat_conn(
        [0x22; 32],
        addr("[2001:dc8::5]:9251"),
        TraversalKind::Direct,
    );
    handle
        .adopt_nat_connection(second)
        .await
        .expect("second peer — the pool is now at max_connections=2");

    // The control: the same net-new identity, offered the ordinary way, is still refused.
    let (refused, keep_refused) = loopback_nat_conn(
        [0x33; 32],
        addr("[2001:dd8::5]:9251"),
        TraversalKind::Direct,
    );
    assert!(
        matches!(
            handle.adopt_nat_connection(refused).await,
            Err(GossipError::MaxConnectionsReached(2))
        ),
        "the maintenance path must keep refusing at the cap"
    );

    // The treatment: discovery found this holder, so an unused incumbent yields to it.
    let (holder, keep_holder) = loopback_nat_conn(
        [0x33; 32],
        addr("[2001:dd8::5]:9251"),
        TraversalKind::Direct,
    );
    let admission = handle
        .adopt_discovered_nat_connection(holder)
        .await
        .expect("a discovered holder is admitted at the cap by cycling a peer out");

    assert_eq!(admission.peer_id, dig_gossip::PeerId::from([0x33; 32]));
    let victim = admission
        .displaced
        .expect("the pool was full, so somebody had to be cycled out");
    assert!(
        !handle.is_pool_peer(&victim),
        "the displaced peer must actually leave the pool, not merely be named"
    );
    assert!(
        handle.is_pool_peer(&dig_gossip::PeerId::from([0x33; 32])),
        "and the discovered holder must actually be in it"
    );
    assert_eq!(
        handle.pool_stats().connected,
        2,
        "still exactly at the cap: a displacement trades a peer, it does not add one"
    );

    // Churn consumers must be able to tell a cycled-out healthy peer from a broken one.
    let mut saw_displaced = false;
    while let Ok(event) = churn.try_recv() {
        if let PoolEvent::PeerRemoved { peer_id, reason } = event {
            if peer_id == victim {
                assert_eq!(
                    reason,
                    PoolRemovalReason::Displaced,
                    "a healthy peer cycled out must not be reported as dead, banned or reaped"
                );
                saw_displaced = true;
            }
        }
    }
    assert!(saw_displaced, "the displacement must reach the churn bus");

    let _ = (keep_first, keep_second, keep_refused, keep_holder);
    svc.stop().await.expect("stop");
}

/// **Why #71 was a prerequisite.** Displacing an OBSERVED slot closes nothing by itself: the pool
/// holds a liveness observer, not the transport. Without the notice, every displacement would leak a
/// live session that the caller keeps serving and the pool no longer counts — the #1871 defect, once
/// per eviction.
///
/// The other incumbent is held BUSY so the observed peer is the only eligible victim. A fixture where
/// the pool could have evicted either would pass whenever it happened to pick the other one, and prove
/// nothing about the notice.
#[tokio::test]
async fn displacing_an_observed_session_tells_its_owner() {
    let (svc, handle, _dir) = running_handle(2, unbounded_displacement(0)).await;
    let served_id = dig_gossip::PeerId::from([0x44; 32]);
    let busy_id = dig_gossip::PeerId::from([0x11; 32]);

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let served_session = dig_nat::PeerSession::client(client_io);
    let keep_peer_end = dig_nat::PeerSession::server(server_io);

    let owner_told = Arc::new(AtomicUsize::new(0));
    let told = Arc::clone(&owner_told);
    handle
        .adopt_relayed_inbound_handle(
            served_id,
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
            ObservedSession::new(served_session.closed_handle(), move || {
                told.fetch_add(1, Ordering::SeqCst);
            }),
            None,
        )
        .await
        .expect("a relayed circuit this node is serving");

    let (busy, keep_busy) = loopback_nat_conn(
        [0x11; 32],
        addr("[2001:dc8::5]:9251"),
        TraversalKind::Direct,
    );
    handle
        .adopt_nat_connection(busy)
        .await
        .expect("the pool is now at max_connections=2");
    let guard = handle
        .peer_activity_guard(busy_id)
        .expect("the second peer is held, so it can be marked busy");
    assert_eq!(
        owner_told.load(Ordering::SeqCst),
        0,
        "filling the pool retires nobody"
    );

    let (holder, keep_holder) = loopback_nat_conn(
        [0x66; 32],
        addr("[2001:dd8::5]:9251"),
        TraversalKind::Direct,
    );
    let admission = handle
        .adopt_discovered_nat_connection(holder)
        .await
        .expect("a discovered holder displaces the one peer that is not busy");

    assert_eq!(
        admission.displaced,
        Some(served_id),
        "the busy peer sorts FIRST on the tie-break, so only its in-flight work can explain the observed session being chosen instead"
    );
    assert_eq!(
        owner_told.load(Ordering::SeqCst),
        1,
        "its owner must be told exactly once, or the pool leaks a live session it stopped counting"
    );
    assert!(
        !handle.is_pool_peer(&served_id),
        "and the displaced peer is gone from the pool"
    );

    drop(guard);
    let _ = (served_session, keep_peer_end, keep_busy, keep_holder);
    svc.stop().await.expect("stop");
}

/// **Never evict a peer mid-request, structurally.** The guard is the only thing separating the two
/// halves here: with it held the pool has no eligible victim and refuses; released, the very same
/// request succeeds. Both bounds are zero in this config, so the guard — not a timer — is what makes
/// the difference, which is the point: a long transfer that emits no intermediate signal stays
/// protected where a last-used stamp would have decayed.
#[tokio::test]
async fn a_peer_with_a_live_activity_guard_is_not_displaced() {
    let (svc, handle, _dir) = running_handle(1, unbounded_displacement(0)).await;
    let busy_id = dig_gossip::PeerId::from([0x77; 32]);

    let (busy, keep_busy) = loopback_nat_conn(
        [0x77; 32],
        addr("[2001:db8::5]:9251"),
        TraversalKind::Direct,
    );
    handle
        .adopt_nat_connection(busy)
        .await
        .expect("the only peer, and the pool is at max_connections=1");

    let guard = handle
        .peer_activity_guard(busy_id)
        .expect("a held peer can be marked busy");

    let (holder, keep_holder) = loopback_nat_conn(
        [0x88; 32],
        addr("[2001:dc8::5]:9251"),
        TraversalKind::Direct,
    );
    let refused = handle.adopt_discovered_nat_connection(holder).await;
    assert!(
        matches!(refused, Err(GossipError::ConnectionFiltered(_))),
        "a peer with work in flight must not be cycled out, got {refused:?}"
    );
    assert!(
        handle.is_pool_peer(&busy_id),
        "and must still be in the pool"
    );

    drop(guard);

    let (holder_again, keep_again) = loopback_nat_conn(
        [0x88; 32],
        addr("[2001:dc8::5]:9251"),
        TraversalKind::Direct,
    );
    let admission = handle
        .adopt_discovered_nat_connection(holder_again)
        .await
        .expect("once the work finishes the same peer becomes displaceable");
    assert_eq!(
        admission.displaced,
        Some(busy_id),
        "and it is the peer whose guard was released"
    );

    let _ = (keep_busy, keep_holder, keep_again);
    svc.stop().await.expect("stop");
}

/// **A discovered peer is not exempt from the eclipse caps, and the caps are decided FIRST.** A peer
/// sharing an incumbent's /16 is refused by INT-006 — and no incumbent is spent on it, which is the
/// half worth pinning: evicting for an admission that then fails would let a hostile peer churn the
/// pool without ever joining it.
#[tokio::test]
async fn a_discovered_peer_refused_by_the_eclipse_caps_costs_no_incumbent() {
    let (svc, handle, _dir) = running_handle(2, unbounded_displacement(1)).await;

    let (first, keep_first) =
        loopback_nat_conn([0x99; 32], addr("10.7.0.1:9251"), TraversalKind::Direct);
    handle
        .adopt_nat_connection(first)
        .await
        .expect("first peer");
    let (second, keep_second) =
        loopback_nat_conn([0xaa; 32], addr("10.8.0.1:9251"), TraversalKind::Direct);
    handle
        .adopt_nat_connection(second)
        .await
        .expect("the pool is now at max_connections=2");

    // Same /16 as the first incumbent: INT-006 refuses it.
    let (same_subnet, keep_same) =
        loopback_nat_conn([0xbb; 32], addr("10.7.0.2:9251"), TraversalKind::Direct);
    let refused = handle.adopt_discovered_nat_connection(same_subnet).await;
    assert!(
        matches!(refused, Err(GossipError::ConnectionFiltered(_))),
        "a discovered peer must still face the /16 cap, got {refused:?}"
    );
    assert!(
        handle.is_pool_peer(&dig_gossip::PeerId::from([0x99; 32]))
            && handle.is_pool_peer(&dig_gossip::PeerId::from([0xaa; 32])),
        "and neither incumbent may have been spent on an admission that was going to fail"
    );
    assert_eq!(handle.pool_stats().connected, 2);

    let _ = (keep_first, keep_second, keep_same);
    svc.stop().await.expect("stop");
}
