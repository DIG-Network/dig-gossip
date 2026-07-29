//! Regression tests for **dig_ecosystem#1703 item 2 — the departed-peer reaper.**
//!
//! ## The defect
//!
//! A `dig-nat` pool member ([`PeerSlot::Nat`]) carries no keepalive (unlike a live TLS peer, torn
//! down by the CON-004 keepalive within `PEER_TIMEOUT_SECS`). So a NAT peer that leaves and never
//! returns lingers in the peer map until `stop()` — a slow leak that over-counts `peer_count` and the
//! `max_connections` budget under high peer turnover.
//!
//! ## The fix under test
//!
//! A periodic reaper ([`GossipHandle::spawn_reaper`], driven here via
//! [`GossipHandle::__reap_departed_peers_for_tests`]) sweeps the map and evicts every slot whose
//! transport is provably closed — decide-and-remove under ONE `peers`-lock hold, so a departed peer
//! is removed while a live-but-quiet one, and a same-`peer_id` reconnect that superseded a dead
//! session, are never touched.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use dig_gossip::{GossipHandle, GossipService, PeerPoolConfig, PoolEvent, PoolRemovalReason};

/// Build a `NatPeerConnection` over a loopback duplex with a chosen `peer_id` + remote address, plus
/// its transport-closed observer. Returns `(conn, server_half, closed_handle)`. Dropping the returned
/// `server_half` closes the peer's transport; `closed_handle.closed().await` then resolves
/// deterministically, so a test can prove the transport is down BEFORE running the reaper (no timing
/// guesswork). Keeping `server_half` alive keeps the session open (a live peer).
fn loopback_nat_conn(
    peer_id_bytes: [u8; 32],
    remote: SocketAddr,
) -> (
    dig_gossip::NatPeerConnection,
    dig_nat::PeerSession,
    dig_nat::ClosedHandle,
) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let client_session = dig_nat::PeerSession::client(client_io);
    let closed = client_session.closed_handle();
    let inner = dig_nat::PeerConnection {
        peer_id: dig_nat::PeerId::from_bytes(peer_id_bytes),
        method: dig_nat::TraversalKind::Direct,
        remote_addr: remote,
        peer_bls_pub: None,
        session: client_session,
    };
    let server = dig_nat::PeerSession::server(server_io);
    (dig_gossip::NatPeerConnection::new(inner), server, closed)
}

/// A running service whose reaper timer is effectively idle (1 h), so the DETERMINISTIC tests drive
/// the sweep themselves via the test hook and the timer never races them.
async fn manual_reaper_handle() -> (GossipService, GossipHandle, tempfile::TempDir) {
    handle_with_reaper_interval(3600).await
}

async fn handle_with_reaper_interval(
    reaper_interval_secs: u64,
) -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 32;
    cfg.reaper_interval_secs = Some(reaper_interval_secs);
    cfg.peer_pool = Some(PeerPoolConfig {
        min_peers: 1,
        target_peers: 8,
        max_peers: 16,
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

/// **#1703 item 2 core regression:** a NAT peer whose transport has closed is reaped, and
/// `peer_count` drops accordingly. Fails before the fix — nothing reaps a departed NAT slot, so it
/// lingers and `peer_count` stays 1.
#[tokio::test]
async fn departed_nat_peer_is_reaped() {
    let (svc, handle, _dir) = manual_reaper_handle().await;

    let (conn, server, closed) = loopback_nat_conn([1; 32], addr("203.0.113.1:9445"));
    handle.adopt_nat_connection(conn).await.expect("adopt");
    assert_eq!(
        handle.peer_count().await,
        1,
        "peer is connected after adoption"
    );

    // Depart: drop the server half, then wait until the client session's transport is provably closed.
    drop(server);
    closed.closed().await;

    let reaped = handle.__reap_departed_peers_for_tests();
    assert_eq!(reaped, 1, "the departed peer must be reaped");
    assert_eq!(
        handle.peer_count().await,
        0,
        "peer_count drops once the departed slot is evicted"
    );

    svc.stop().await.expect("stop");
}

/// **Guard:** a live-but-quiet NAT peer (its transport still open) is NEVER reaped — a false reap of
/// a live peer is worse than a slow leak.
#[tokio::test]
async fn live_nat_peer_is_never_reaped() {
    let (svc, handle, _dir) = manual_reaper_handle().await;

    let (conn, server, _closed) = loopback_nat_conn([2; 32], addr("198.51.100.1:9445"));
    handle.adopt_nat_connection(conn).await.expect("adopt");
    assert_eq!(handle.peer_count().await, 1);

    // Server half kept alive => transport open => the peer is live-but-quiet.
    let reaped = handle.__reap_departed_peers_for_tests();
    assert_eq!(reaped, 0, "a live peer must not be reaped");
    assert_eq!(
        handle.peer_count().await,
        1,
        "the live peer stays connected"
    );

    drop(server);
    svc.stop().await.expect("stop");
}

/// **Critical race:** a `peer_id` whose FIRST session departed but was already SUPERSEDED by a fresh
/// LIVE session (newest-wins reconnect, #1762) must NOT be reaped by a stale judgement about the dead
/// session. Because the reaper judges + removes under ONE lock, it only ever sees the CURRENT slot
/// (the live reconnect), whose transport is open — so it keeps it.
#[tokio::test]
async fn superseded_then_live_peer_id_is_not_reaped() {
    let (svc, handle, _dir) = manual_reaper_handle().await;

    // First session for the identity.
    let (conn1, server1, closed1) = loopback_nat_conn([3; 32], addr("192.0.2.1:9445"));
    handle.adopt_nat_connection(conn1).await.expect("adopt 1");

    // A fresh LIVE session for the SAME identity supersedes the first (newest-wins). This drops the
    // displaced first slot, so its transport closes.
    let (conn2, server2, _closed2) = loopback_nat_conn([3; 32], addr("192.0.2.1:9445"));
    handle.adopt_nat_connection(conn2).await.expect("adopt 2");

    // Confirm the first (superseded) session is genuinely closed — the stale departure signal.
    closed1.closed().await;
    assert_eq!(
        handle.peer_count().await,
        1,
        "the identity holds exactly one slot"
    );

    // The reaper must NOT evict the live reconnect on the strength of the dead session's departure.
    let reaped = handle.__reap_departed_peers_for_tests();
    assert_eq!(
        reaped, 0,
        "a superseded-then-live peer_id must not be reaped by a stale judgement"
    );
    assert_eq!(handle.peer_count().await, 1, "the live reconnect survives");

    drop((server1, server2));
    svc.stop().await.expect("stop");
}

/// **End-to-end wiring:** the spawned periodic reaper task (not the test hook) removes a departed peer
/// on its own timer. Proves `start()` actually wires the loop.
#[tokio::test]
async fn periodic_reaper_task_evicts_departed_peer() {
    let (svc, handle, _dir) = handle_with_reaper_interval(1).await;

    let (conn, server, closed) = loopback_nat_conn([4; 32], addr("203.0.113.9:9445"));
    handle.adopt_nat_connection(conn).await.expect("adopt");
    assert_eq!(handle.peer_count().await, 1);

    drop(server);
    closed.closed().await;

    // Wait for the 1 s reaper tick to fire (bounded — fail loudly rather than hang).
    let mut reaped = false;
    for _ in 0..40 {
        if handle.peer_count().await == 0 {
            reaped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        reaped,
        "the periodic reaper task must evict the departed peer"
    );

    svc.stop().await.expect("stop");
}

/// **#1703 gate follow-up (Finding 1 — leak parity):** a reaped NAT peer must be removed from
/// Plumtree state too, exactly as `disconnect()` does — otherwise its `peer_id` lingers in the
/// eager/lazy sets, a sibling unbounded-growth leak of the same class. Fails before the fix: the
/// reaper cleared only the peer map, leaving the id in Plumtree.
#[tokio::test]
async fn reaped_peer_is_removed_from_plumtree() {
    let (svc, handle, _dir) = manual_reaper_handle().await;

    let peer_id_bytes = [5u8; 32];
    let (conn, server, closed) = loopback_nat_conn(peer_id_bytes, addr("203.0.113.5:9445"));
    let peer_id = handle.adopt_nat_connection(conn).await.expect("adopt");
    assert!(
        handle.__plumtree_contains_for_tests(&peer_id),
        "adoption registers the peer in Plumtree (starts eager)"
    );

    drop(server);
    closed.closed().await;
    let reaped = handle.__reap_departed_peers_for_tests();
    assert_eq!(reaped, 1);

    assert!(
        !handle.__plumtree_contains_for_tests(&peer_id),
        "the reaped peer_id must be gone from Plumtree (parity with disconnect())"
    );

    svc.stop().await.expect("stop");
}

/// **#1703 gate follow-up (Finding 2 — consumer consistency):** reaping a departed peer must emit a
/// `PoolEvent::PeerRemoved` (reason `Reaped`) on the churn stream, so event-driven consumers drop
/// their stale "connected" view — exactly as `disconnect()` does. Fails before the fix: the reaper
/// emitted nothing.
#[tokio::test]
async fn reaped_peer_emits_pool_removed_event() {
    let (svc, handle, _dir) = manual_reaper_handle().await;

    // Subscribe BEFORE adopting so both the PeerAdded and the later PeerRemoved land on this stream.
    let mut events = handle.subscribe_pool_events().expect("subscribe");

    let peer_id_bytes = [6u8; 32];
    let (conn, server, closed) = loopback_nat_conn(peer_id_bytes, addr("203.0.113.6:9445"));
    let peer_id = handle.adopt_nat_connection(conn).await.expect("adopt");

    drop(server);
    closed.closed().await;
    assert_eq!(handle.__reap_departed_peers_for_tests(), 1);

    // Drain the buffered events and assert a Reaped PeerRemoved for this id is present.
    let mut saw_reaped = false;
    while let Ok(evt) = events.try_recv() {
        if let PoolEvent::PeerRemoved {
            peer_id: removed,
            reason,
        } = evt
        {
            if removed == peer_id {
                assert_eq!(
                    reason,
                    PoolRemovalReason::Reaped,
                    "the reaper's churn event carries reason Reaped"
                );
                saw_reaped = true;
            }
        }
    }
    assert!(
        saw_reaped,
        "reaping must emit PoolEvent::PeerRemoved for the departed peer"
    );

    svc.stop().await.expect("stop");
}
