//! Regression tests for **dig_ecosystem#1703 (item 1) — the OUTBOUND mirror of #1691**.
//!
//! ## The defect
//!
//! #1691 fixed the INBOUND side: a restarted peer redialing a holder was refused because a stale
//! peer-map slot survived the prior (dropped) connection. The OUTBOUND dial path
//! ([`GossipHandle::connect_to`](dig_gossip)) had the SAME latent bug in reverse. After a dropped
//! outbound link, this node's slot for that peer survives (dig-gossip never reaps a slot on
//! disconnect), so a re-dial to the same endpoint hit the duplicate guard
//! (`GossipError::DuplicateConnection`) and this node could never re-establish the outbound link — an
//! outbound peer, once dropped, was permanently unreachable from this node until the slot was cleared.
//!
//! ## The fix under test — newest-wins, symmetric with #1691
//!
//! `connect_to` no longer rejects a re-dial to an endpoint it already holds a slot for. The freshly
//! mTLS-authenticated outbound session **supersedes** the stale slot (newest-wins, keyed by the
//! handshake-verified `peer_id`, `HashMap::insert` replace-not-grow), aborts the displaced slot's
//! keepalive, and closes the displaced `Peer`. The stale slot's diversity-filter registrations
//! (INT-006 /16, INT-007 AS) — which it populated on the first dial and which would otherwise
//! self-block the re-dial — are recognised as a reconnect and not re-applied against the same endpoint.
//! Every per-session teardown remains generation-guarded (the #1691 machinery), so a stale outbound
//! session's lingering keepalive cannot evict the reconnect.
//!
//! ## Proof strategy (real wire)
//!
//! Each test drives the **real** [`GossipService`] over native-tls: TCP -> TLS -> WSS -> Chia
//! handshake. The dialer establishes an outbound link, then re-dials the same live server; the stale
//! outbound slot is what a dropped link leaves behind (dig-gossip does not reap it), so re-dialing is
//! the faithful driver of the exact guard the fix removes. A dedicated test also drops and restarts
//! the server at the same address to exercise a genuine dropped-then-re-established link end-to-end.

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use dig_gossip::{GossipConfig, GossipHandle, GossipService};

/// Start a [`GossipService`] from an existing cert directory, letting `configure` adjust the config
/// (used to pin a fixed `listen_addr` when restarting a "server" at the same endpoint).
async fn service_with_config(
    dir: &Path,
    configure: impl FnOnce(&mut GossipConfig),
) -> (GossipService, GossipHandle) {
    let mut cfg = common::test_gossip_config(dir);
    configure(&mut cfg);
    let svc = GossipService::new(cfg).expect("GossipService::new");
    let handle = svc.start().await.expect("GossipService::start");
    (svc, handle)
}

/// Start a full [`GossipService`] (TLS listener + accept loop) from an existing cert directory.
async fn service_from_dir(dir: &Path) -> (GossipService, GossipHandle) {
    service_with_config(dir, |_| {}).await
}

/// **#1703 core regression:** a re-dial to an endpoint whose stale outbound slot still sits in the
/// peer map is **accepted** (newest-wins supersede), not refused as `DuplicateConnection`, and the
/// superseding session serves a round-trip request.
///
/// Fails before the fix: the address-level duplicate guard in `connect_to` returns
/// `GossipError::DuplicateConnection` on the second dial.
#[tokio::test]
async fn redial_to_same_peer_is_accepted_and_supersedes_stale_slot() {
    let server_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(server_dir.path());
    let (_server_svc, server_h) = service_from_dir(server_dir.path()).await;
    let bound = server_h
        .__listen_bound_addr_for_tests()
        .expect("server listen addr");

    let client_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(client_dir.path());
    let (_client_svc, client_h) = service_from_dir(client_dir.path()).await;

    // First outbound dial: the dialer registers exactly one outbound slot (session generation 0).
    let server_pid = client_h.connect_to(bound).await.expect("first outbound dial");
    assert_eq!(client_h.peer_count().await, 1, "one outbound peer after dial");
    assert_eq!(
        client_h.__peer_generation_for_tests(server_pid),
        Some(0),
        "first outbound session is generation 0"
    );

    // A dropped outbound link leaves that slot in the map (dig-gossip never reaps). Re-dial the SAME
    // endpoint: on the unfixed code this returns DuplicateConnection; the fix supersedes newest-wins.
    let redial_pid = client_h
        .connect_to(bound)
        .await
        .expect("RE-DIAL must be accepted despite the stale outbound slot (#1703)");
    assert_eq!(
        redial_pid, server_pid,
        "the re-dialed slot is keyed by the same handshake-verified peer_id"
    );

    // Bounded + superseded: still exactly one slot, now a strictly-newer session generation.
    assert_eq!(
        client_h.peer_count().await,
        1,
        "newest-wins keeps exactly one outbound slot per peer_id (map stays bounded)"
    );
    assert_eq!(
        client_h.__peer_generation_for_tests(server_pid),
        Some(1),
        "the reconnect supersedes generation 0 with a fresh generation 1"
    );

    // The superseding outbound session serves a real round-trip.
    client_h
        .request_peers_from(&server_pid)
        .await
        .expect("the superseding outbound session must serve a RequestPeers round-trip");
}

/// **Map-boundedness under outbound reconnect churn:** repeated re-dials of the same endpoint never
/// grow the peer map beyond one slot, and each re-dial advances the session generation.
#[tokio::test]
async fn outbound_reconnect_churn_keeps_map_bounded() {
    let server_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(server_dir.path());
    let (_server_svc, server_h) = service_from_dir(server_dir.path()).await;
    let bound = server_h
        .__listen_bound_addr_for_tests()
        .expect("server listen addr");

    let client_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(client_dir.path());
    let (_client_svc, client_h) = service_from_dir(client_dir.path()).await;

    let mut last_pid = None;
    for round in 0..5u64 {
        let pid = client_h
            .connect_to(bound)
            .await
            .unwrap_or_else(|e| panic!("outbound re-dial round {round} accepted: {e}"));
        assert_eq!(
            client_h.peer_count().await,
            1,
            "round {round}: outbound churn to one endpoint must not grow the map"
        );
        assert_eq!(
            client_h.__peer_generation_for_tests(pid),
            Some(round),
            "round {round}: each re-dial advances the session generation"
        );
        match last_pid {
            Some(p) => assert_eq!(p, pid, "same endpoint keeps the same peer_id across churn"),
            None => last_pid = Some(pid),
        }
    }
}

/// **Genuine dropped-then-re-established link:** the server is dropped abruptly (leaving the dialer's
/// outbound slot stale), then restarted at the SAME address with the SAME identity; the dialer's
/// re-dial is accepted and round-trips over the fresh link.
#[tokio::test]
async fn outbound_reconnect_after_server_restart_round_trips() {
    let server_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(server_dir.path());
    let (server1_svc, server1_h) = service_from_dir(server_dir.path()).await;
    let bound: SocketAddr = server1_h
        .__listen_bound_addr_for_tests()
        .expect("server listen addr");

    let client_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(client_dir.path());
    let (_client_svc, client_h) = service_from_dir(client_dir.path()).await;

    let server_pid = client_h.connect_to(bound).await.expect("first outbound dial");
    assert_eq!(client_h.peer_count().await, 1);

    // Abrupt server teardown — the dialer's outbound slot survives (no clean disconnect).
    drop(server1_h);
    drop(server1_svc);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        client_h.peer_count().await,
        1,
        "the stale outbound slot survives the dropped link (dig-gossip does not reap)"
    );

    // Server restarts at the SAME address + identity (same cert dir -> same peer_id).
    let (_server2_svc, _server2_h) = service_with_config(server_dir.path(), |cfg| {
        cfg.listen_addr = bound;
    })
    .await;

    let redial_pid = client_h
        .connect_to(bound)
        .await
        .expect("re-dial after a dropped link must be accepted (#1703)");
    assert_eq!(redial_pid, server_pid, "same identity across the restart");
    assert_eq!(client_h.peer_count().await, 1, "map stays bounded");
    client_h
        .request_peers_from(&server_pid)
        .await
        .expect("the re-established outbound link must serve a round-trip");
}
