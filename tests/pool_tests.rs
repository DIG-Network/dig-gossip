//! POOL-* — the connected peer pool: the maintained set of ready, CONNECTED peers a DIG Node keeps
//! for peer-RPC + downloads, driven through the public `GossipHandle` API with NO real network.
//!
//! This suite exercises the pool's DISCOVER → CONNECT → MAINTAIN policy through the handle's pool
//! surface (`adopt_nat_connection`, `connected_pool_peers`, `pool_stats`, `subscribe_pool_events`,
//! `disconnect`): a `dig-nat` connection is built over a loopback duplex (the same technique as
//! `nat_transport_tests.rs` — a real yamux session, just not over TLS) and adopted into the pool,
//! proving dedup-by-`peer_id`, the `max` cap, churn events, ban-refusal, and replenishment accounting.
//! (The pure maintenance driver — fill-to-target / replenish / backoff with a mock `Dialer` — is
//! covered by the `peer_pool` module unit tests.) All without a real socket.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use dig_gossip::{
    GossipHandle, GossipService, PeerId, PeerPoolConfig, PoolEvent, PoolRemovalReason,
};

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

/// Start a running service+handle whose pool is configured with the given `(min, target, max)`.
async fn running_handle_with_pool(
    min: usize,
    target: usize,
    max: usize,
) -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    // Make room for the pool cap in the overall connection limit.
    cfg.max_connections = max + 8;
    cfg.peer_pool = Some(PeerPoolConfig {
        min_peers: min,
        target_peers: target,
        max_peers: max,
        // Long interval so the background loop does not fire during these deterministic tests — we
        // drive maintenance explicitly. (The loop-spawn path is covered separately.)
        maintenance_interval_secs: 3600,
        ..Default::default()
    });
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    (svc, handle, dir)
}

/// Build a `NatPeerConnection` over a loopback duplex with a chosen peer_id + remote address, so it
/// can be adopted into the pool WITHOUT a real network. Returns the connection and the server half of
/// the duplex (kept alive by the caller so the session stays open).
fn loopback_nat_conn(
    peer_id_bytes: [u8; 32],
    remote: SocketAddr,
) -> (dig_gossip::NatPeerConnection, dig_nat::PeerSession) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let inner = dig_nat::PeerConnection {
        peer_id: dig_nat::PeerId::from_bytes(peer_id_bytes),
        method: dig_nat::TraversalKind::Direct,
        remote_addr: remote,
        session: dig_nat::PeerSession::client(client_io),
    };
    let server = dig_nat::PeerSession::server(server_io);
    (dig_gossip::NatPeerConnection::new(inner), server)
}

fn addr(n: u16) -> SocketAddr {
    format!("127.0.0.1:{n}").parse().unwrap()
}

// -------------------------------------------------------------------------------------------------
// Adoption + dedup + cap + stats + churn through the handle API
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn adopting_nat_connections_fills_the_pool_and_reports_stats() {
    let (svc, handle, _dir) = running_handle_with_pool(2, 4, 8).await;
    let mut keep_alive = Vec::new();

    for i in 1..=4u8 {
        let (conn, server) = loopback_nat_conn([i; 32], addr(9000 + i as u16));
        keep_alive.push(server);
        let pid = handle.adopt_nat_connection(conn).await.expect("adopt");
        assert_eq!(pid.as_ref(), &[i; 32]);
    }

    let stats = handle.pool_stats();
    assert_eq!(stats.connected, 4);
    assert_eq!(stats.target, 4);
    assert!(stats.is_at_target());
    assert!(!stats.is_under_connected());
    assert_eq!(handle.connected_pool_peers().len(), 4);

    svc.stop().await.expect("stop");
}

#[tokio::test]
async fn pool_dedups_by_peer_id() {
    let (svc, handle, _dir) = running_handle_with_pool(1, 4, 8).await;

    let (c1, s1) = loopback_nat_conn([7; 32], addr(9001));
    let _pid = handle.adopt_nat_connection(c1).await.expect("first adopt");

    // Same peer_id, different address — must be refused as a duplicate (pool dedups by peer_id).
    let (c2, s2) = loopback_nat_conn([7; 32], addr(9002));
    let err = handle.adopt_nat_connection(c2).await;
    assert!(
        matches!(err, Err(dig_gossip::GossipError::DuplicateConnection(_))),
        "same peer_id must be rejected as a duplicate, got {err:?}"
    );
    assert_eq!(handle.pool_stats().connected, 1);

    let _ = (s1, s2);
    svc.stop().await.expect("stop");
}

#[tokio::test]
async fn pool_caps_at_max_connections() {
    // max_connections gates adoption; set the overall cap low to prove the cap is enforced.
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 3;
    cfg.peer_pool = Some(PeerPoolConfig {
        min_peers: 1,
        target_peers: 3,
        max_peers: 3,
        maintenance_interval_secs: 3600,
        ..Default::default()
    });
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    let mut keep = Vec::new();

    for i in 1..=3u8 {
        let (conn, server) = loopback_nat_conn([i; 32], addr(9100 + i as u16));
        keep.push(server);
        handle.adopt_nat_connection(conn).await.expect("adopt");
    }
    // The 4th exceeds max_connections — refused.
    let (conn, server) = loopback_nat_conn([9; 32], addr(9199));
    keep.push(server);
    let err = handle.adopt_nat_connection(conn).await;
    assert!(
        matches!(err, Err(dig_gossip::GossipError::MaxConnectionsReached(3))),
        "adoption past the cap must be refused, got {err:?}"
    );
    assert_eq!(handle.pool_stats().connected, 3);

    svc.stop().await.expect("stop");
}

#[tokio::test]
async fn pool_emits_churn_events_on_add_and_remove() {
    let (svc, handle, _dir) = running_handle_with_pool(1, 4, 8).await;
    let mut events = handle.subscribe_pool_events().expect("subscribe");

    let (conn, _s) = loopback_nat_conn([5; 32], addr(9300));
    let pid = handle.adopt_nat_connection(conn).await.expect("adopt");

    // PeerAdded churn.
    let added = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("added event within timeout")
        .expect("event");
    assert_eq!(
        added,
        PoolEvent::PeerAdded {
            peer_id: pid,
            addr: addr(9300)
        }
    );

    // Disconnect -> PeerRemoved churn.
    handle.disconnect(&pid).await.expect("disconnect");
    let removed = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("removed event within timeout")
        .expect("event");
    assert_eq!(
        removed,
        PoolEvent::PeerRemoved {
            peer_id: pid,
            reason: PoolRemovalReason::Disconnected
        }
    );
    assert_eq!(handle.pool_stats().connected, 0);

    svc.stop().await.expect("stop");
}

#[tokio::test]
async fn dropping_below_target_shows_under_connected_then_replenishes() {
    let (svc, handle, _dir) = running_handle_with_pool(3, 4, 8).await;
    let mut keep = Vec::new();

    // Fill to target (4).
    for i in 1..=4u8 {
        let (conn, server) = loopback_nat_conn([i; 32], addr(9400 + i as u16));
        keep.push(server);
        handle.adopt_nat_connection(conn).await.expect("adopt");
    }
    assert!(handle.pool_stats().is_at_target());

    // Two peers churn away -> below min (3): under-connected.
    handle
        .disconnect(&PeerId::from([1u8; 32]))
        .await
        .expect("disconnect 1");
    handle
        .disconnect(&PeerId::from([2u8; 32]))
        .await
        .expect("disconnect 2");
    let stats = handle.pool_stats();
    assert_eq!(stats.connected, 2);
    assert!(stats.is_under_connected(), "2 < min(3) is under-connected");

    // Replenish by adopting new peers back toward target (simulating the maintenance loop's dials).
    for i in 5..=6u8 {
        let (conn, server) = loopback_nat_conn([i; 32], addr(9400 + i as u16));
        keep.push(server);
        handle.adopt_nat_connection(conn).await.expect("re-adopt");
    }
    let stats = handle.pool_stats();
    assert_eq!(stats.connected, 4);
    assert!(stats.is_at_target(), "replenished back to target");
    assert!(!stats.is_under_connected());

    svc.stop().await.expect("stop");
}

#[tokio::test]
async fn banned_peer_cannot_be_adopted_into_the_pool() {
    let (svc, handle, _dir) = running_handle_with_pool(1, 4, 8).await;

    let pid = PeerId::from([0xab; 32]);
    // Ban the peer first.
    handle
        .ban_peer(&pid, dig_gossip::PenaltyReason::MalformedMessage)
        .await
        .expect("ban");

    let (conn, _s) = loopback_nat_conn([0xab; 32], addr(9500));
    let err = handle.adopt_nat_connection(conn).await;
    assert!(
        matches!(err, Err(dig_gossip::GossipError::PeerBanned(_))),
        "a banned peer must not be adopted, got {err:?}"
    );
    assert_eq!(handle.pool_stats().connected, 0);

    svc.stop().await.expect("stop");
}

#[tokio::test]
async fn pool_api_is_gated_after_stop() {
    let (svc, handle, _dir) = running_handle_with_pool(1, 4, 8).await;
    svc.stop().await.expect("stop");

    assert!(
        handle.subscribe_pool_events().is_err(),
        "subscribe_pool_events must be gated after stop()"
    );
    let (conn, _s) = loopback_nat_conn([1; 32], addr(9600));
    assert!(
        handle.adopt_nat_connection(conn).await.is_err(),
        "adopt_nat_connection must be gated after stop()"
    );
}

// -------------------------------------------------------------------------------------------------
// The maintenance loop drives a pass on demand: a pool with no candidates + no peers stays empty and
// under-connected (never panics, never over-dials) — the graceful "nothing to dial yet" path.
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn maintenance_pass_on_an_empty_address_book_is_a_clean_noop() {
    let (svc, handle, _dir) = running_handle_with_pool(2, 4, 8).await;
    // No addresses discovered yet -> the pass finds no candidates and adds nothing (bounded, no hang).
    let added = handle.run_pool_maintenance_once().await;
    assert_eq!(added, 0);
    let stats = handle.pool_stats();
    assert_eq!(stats.connected, 0);
    assert!(stats.is_under_connected());
    svc.stop().await.expect("stop");
}
