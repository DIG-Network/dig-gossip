//! Regression tests for **dig_ecosystem#1710 — the outbound /16 (INT-006) + AS (INT-007) diversity
//! caps must gate the AUTO-POOL adoption path, not only manual `connect_to`.**
//!
//! ## The defect
//!
//! The eclipse caps shipped in v0.17.2 were enforced only in
//! [`GossipHandle::connect_to`](dig_gossip) (the operator-initiated dial). The live auto-peering path
//! — pool maintenance → `HandleDialer::dial` → `connect_via_nat_full_ladder` →
//! [`GossipHandle::adopt_nat_connection`] — adopted peers WITHOUT the gate. Its insert block checked
//! only self-connection, ban, duplicate `peer_id`, and `max_connections`, so an adversary who seeds
//! many same-/16 reservations (pool candidates originate from `RespondPeers`) could occupy the whole
//! outbound budget the diversity caps exist to protect — the automatic path is the actual
//! attacker-influenceable surface.
//!
//! ## The fix under test
//!
//! `adopt_nat_connection` now calls the SAME `outbound_diversity_conflict` gate `connect_to` uses,
//! under the same held `peers` lock, immediately before the insert. Because adoption already refuses a
//! duplicate `peer_id` outright, every adopted connection is a NET-NEW identity = net-new outbound
//! occupancy, so the gate is UNCONDITIONAL here (no reconnect-exemption branch). A second net-new
//! adoption into an already-occupied /16 is refused with `GossipError::ConnectionFiltered` (INT-006).

mod common;

use std::net::SocketAddr;

use dig_gossip::{GossipError, GossipHandle, GossipService, PeerPoolConfig};

/// Build a `NatPeerConnection` over a loopback duplex with a chosen `peer_id` + remote address, so it
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
        peer_bls_pub: None,
        session: dig_nat::PeerSession::client(client_io),
    };
    let server = dig_nat::PeerSession::server(server_io);
    (dig_gossip::NatPeerConnection::new(inner), server)
}

async fn running_handle() -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 32;
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

/// **#1710 core regression:** two net-new adoptions in the SAME /16 (both `127.0.0.x`, which share the
/// `127.0` group) with DIFFERENT verified `peer_id`s — the first is adopted, the second is refused
/// with INT-006 `ConnectionFiltered`. Fails before the fix (both adopted, the /16 cap silently
/// skipped on the auto-pool path).
#[tokio::test]
async fn second_adoption_in_same_slash16_is_filtered_int006() {
    let (svc, handle, _dir) = running_handle().await;

    let (first, s1) = loopback_nat_conn([1; 32], addr("127.0.0.1:9445"));
    handle
        .adopt_nat_connection(first)
        .await
        .expect("first adoption into an empty /16 is admitted");

    // A DIFFERENT identity in the SAME /16 (127.0) — must be refused by the outbound /16 cap.
    let (second, s2) = loopback_nat_conn([2; 32], addr("127.0.0.9:9450"));
    let err = handle.adopt_nat_connection(second).await;
    assert!(
        matches!(&err, Err(GossipError::ConnectionFiltered(msg)) if msg.contains("INT-006")),
        "a second net-new adoption into an occupied /16 must be ConnectionFiltered (INT-006), got {err:?}"
    );
    assert_eq!(
        handle.pool_stats().connected,
        1,
        "the filtered peer must NOT enter the pool"
    );

    let _ = (s1, s2);
    svc.stop().await.expect("stop");
}

/// **Control:** two adoptions in DIFFERENT /16 groups are both admitted — the gate constrains
/// diversity, it does not block distinct-group peering.
#[tokio::test]
async fn adoptions_in_distinct_slash16_are_both_admitted() {
    let (svc, handle, _dir) = running_handle().await;

    let (first, s1) = loopback_nat_conn([1; 32], addr("203.0.113.1:9445"));
    handle.adopt_nat_connection(first).await.expect("first");

    let (second, s2) = loopback_nat_conn([2; 32], addr("198.51.100.1:9450"));
    handle
        .adopt_nat_connection(second)
        .await
        .expect("distinct /16 admitted");

    assert_eq!(
        handle.pool_stats().connected,
        2,
        "both distinct-/16 peers join"
    );

    let _ = (s1, s2);
    svc.stop().await.expect("stop");
}
