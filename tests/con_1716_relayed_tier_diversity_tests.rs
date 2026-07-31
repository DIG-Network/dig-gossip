//! Regression tests for **dig_ecosystem#1716 — the auto-pool /16 (INT-006) + AS (INT-007) diversity
//! caps must NOT apply to the RELAYED transport tier, which is instead bounded by a separate relayed
//! outbound cap (INT-006a).**
//!
//! ## The defect
//!
//! The v0.17.4 diversity gate keyed INT-006(/16) + INT-007(AS) on `conn.remote_addr()`. For a RELAYED
//! link that address is the RELAY ENDPOINT (dig-nat by design), not the peer's own routable address.
//! So every relayed peer collapsed into ONE /16 → at most one relayed outbound peer could be adopted
//! (a self-throttle that harms NAT'd nodes), AND a relayed slot wrongly blocked a DIRECT candidate that
//! happened to share the relay's /16. The /16 cap gives zero eclipse value on the relayed tier.
//!
//! ## The fix under test
//!
//! Relayed adoptions are EXEMPT from the /16//AS cap (a relayed slot neither is checked against it nor
//! occupies a group), and are bounded instead by `max_relayed_outbound` (6 with the default target of
//! 8), which reserves ≥2 outbound slots for the diversity-checked non-relayed tier and closes the
//! relayed-Sybil-flood window.

mod common;

use std::net::SocketAddr;

use dig_gossip::{GossipError, GossipHandle, GossipService, PeerPoolConfig};
use dig_nat::TraversalKind;

/// Build a `NatPeerConnection` over a loopback duplex with a chosen `peer_id`, remote address, and
/// traversal tier, so it can be adopted into the pool WITHOUT a real network. Returns the connection
/// and the server half of the duplex (kept alive by the caller so the session stays open).
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

async fn running_handle() -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 64;
    cfg.target_outbound_count = 8; // → max_relayed_outbound = 6
    cfg.peer_pool = Some(PeerPoolConfig {
        min_peers: 1,
        target_peers: 8,
        max_peers: 32,
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

/// **Test 1 — relayed candidate + a direct peer in the relay's /16 → BOTH admitted.** A relayed link's
/// `remote_addr` is the relay endpoint; it must not be blocked by a direct peer already occupying that
/// /16, nor does adopting it consume the group.
#[tokio::test]
async fn relayed_candidate_and_direct_peer_in_relays_slash16_both_admitted() {
    let (svc, handle, _dir) = running_handle().await;

    // A DIRECT peer in 203.0.113.0/16.
    let (direct, s1) = loopback_nat_conn([1; 32], addr("203.0.113.5:9445"), TraversalKind::Direct);
    handle
        .adopt_nat_connection(direct)
        .await
        .expect("direct peer admitted");

    // A RELAYED peer whose remote is the RELAY endpoint in the SAME /16 (203.0.x) → still admitted.
    let (relayed, s2) =
        loopback_nat_conn([2; 32], addr("203.0.113.9:9450"), TraversalKind::Relayed);
    handle
        .adopt_nat_connection(relayed)
        .await
        .expect("relayed peer exempt from /16 cap");

    assert_eq!(handle.pool_stats().connected, 2, "both admitted");
    let _ = (s1, s2);
    svc.stop().await.expect("stop");
}

/// **Test 3 — a relayed slot does NOT block a later DIRECT candidate sharing the relay's /16.** The
/// relayed slot's relay-IP group must be excluded from occupancy, so the direct tier stays open.
#[tokio::test]
async fn relayed_slot_does_not_block_a_direct_candidate_in_the_relays_slash16() {
    let (svc, handle, _dir) = running_handle().await;

    // A RELAYED peer first, remote = relay endpoint in 198.51.0.0/16.
    let (relayed, s1) =
        loopback_nat_conn([1; 32], addr("198.51.100.1:9445"), TraversalKind::Relayed);
    handle
        .adopt_nat_connection(relayed)
        .await
        .expect("relayed admitted");

    // A DIRECT peer in the SAME /16 as the relay → must NOT be blocked (relayed slot doesn't occupy).
    let (direct, s2) = loopback_nat_conn([2; 32], addr("198.51.100.9:9450"), TraversalKind::Direct);
    handle
        .adopt_nat_connection(direct)
        .await
        .expect("direct candidate not blocked by a relayed slot in the same /16");

    assert_eq!(handle.pool_stats().connected, 2, "both admitted");
    let _ = (s1, s2);
    svc.stop().await.expect("stop");
}

/// **Test 4 — the relayed tier is NOT throttled to one peer.** `max_relayed_outbound` (6) relayed peers
/// all reached via the SAME relay /16 are all admitted (the v0.17.4 bug capped this at 1).
#[tokio::test]
async fn relayed_tier_admits_up_to_the_cap_all_via_one_relay_slash16() {
    let (svc, handle, _dir) = running_handle().await;

    // 6 relayed peers, all with a relay endpoint in the SAME /16 (100.64.x) — distinct identities.
    for i in 0..6u8 {
        let (relayed, s) = loopback_nat_conn(
            [i + 1; 32],
            addr(&format!("100.64.0.{}:9445", i + 1)),
            TraversalKind::Relayed,
        );
        handle
            .adopt_nat_connection(relayed)
            .await
            .unwrap_or_else(|e| panic!("relayed peer {i} within cap must be admitted, got {e:?}"));
        std::mem::forget(s); // keep the server session alive for the test duration
    }

    assert_eq!(
        handle.pool_stats().connected,
        6,
        "all 6 relayed peers admitted via one relay /16"
    );
    svc.stop().await.expect("stop");
}

/// **Test 5 — the relayed cap is ENFORCED.** The 7th relayed adoption (cap+1) is refused with INT-006a,
/// while a non-relayed peer into a free /16 still succeeds — the bound reserves the direct tier.
#[tokio::test]
async fn seventh_relayed_adoption_is_filtered_but_a_direct_peer_still_joins() {
    let (svc, handle, _dir) = running_handle().await;

    for i in 0..6u8 {
        let (relayed, s) = loopback_nat_conn(
            [i + 1; 32],
            addr(&format!("100.64.0.{}:9445", i + 1)),
            TraversalKind::Relayed,
        );
        handle
            .adopt_nat_connection(relayed)
            .await
            .expect("within cap");
        std::mem::forget(s);
    }

    // The 7th relayed adoption exceeds max_relayed_outbound (6) → filtered.
    let (over, s7) = loopback_nat_conn([7; 32], addr("100.64.0.7:9450"), TraversalKind::Relayed);
    let err = handle.adopt_nat_connection(over).await;
    assert!(
        matches!(&err, Err(GossipError::ConnectionFiltered(msg)) if msg.as_str().contains("INT-006a")),
        "the 7th relayed adoption must be ConnectionFiltered (INT-006a), got {err:?}"
    );

    // A DIRECT peer into a fresh /16 still joins — the relayed cap doesn't starve the direct tier.
    let (direct, s8) = loopback_nat_conn([8; 32], addr("8.8.0.1:9455"), TraversalKind::Direct);
    handle
        .adopt_nat_connection(direct)
        .await
        .expect("direct peer into a free /16 still admitted");

    assert_eq!(handle.pool_stats().connected, 7, "6 relayed + 1 direct");
    let _ = (s7, s8);
    svc.stop().await.expect("stop");
}
