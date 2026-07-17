//! RLY-* / #870 — consuming `dig-nat`'s persistent-reservation peer discovery.
//!
//! CONNECT-leg WU-B: dig-gossip stops doing its own ephemeral open-register-getpeers-close relay
//! discovery (whose sub-second registration windows never overlapped) and instead READS the peer set
//! `dig-nat`'s ONE live reservation socket has discovered
//! ([`RelayStatus::known_peers`](dig_nat::relay::RelayStatus::known_peers)). A relay-reachable peer
//! carries no directly-dialable address — this suite proves such a peer now SURVIVES as
//! connected-via-relay (counted in the pool + stats) instead of being DROPPED, while direct peers are
//! unaffected.
//!
//! `dig-nat`'s discovery internals are private, so the supported injection seam is
//! [`GossipHandle::fold_relay_known_peers`](dig_gossip::GossipHandle::fold_relay_known_peers) — the
//! same method the pool-maintenance loop calls with the live `known_peers()`.

mod common;

use std::sync::Arc;

use dig_gossip::nat::{PeerRecord, Via};
use dig_gossip::{GossipHandle, GossipService, PeerPoolConfig};
use dig_nat::relay::RelayStatus;
use dig_nat::wire::RelayPeerInfo;

/// A relay-discovered peer, addressed by `peer_id` only (the shape `dig-nat` exposes).
fn relay_peer(peer_id: &str) -> RelayPeerInfo {
    RelayPeerInfo::new(peer_id.to_string(), "DIG_MAINNET".to_string(), 1)
}

/// Start a running service+handle with a pool configured `(min, target, max)`.
async fn running_handle(
    min: usize,
    target: usize,
    max: usize,
) -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = max + 8;
    cfg.peer_pool = Some(PeerPoolConfig {
        min_peers: min,
        target_peers: target,
        max_peers: max,
        // Long interval so the background loop never fires — we drive maintenance explicitly.
        maintenance_interval_secs: 3600,
        ..Default::default()
    });
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    (svc, handle, dir)
}

/// The unified `PeerRecord` built from a `dig-nat` relay peer is an identity-only, `Via::Relay`
/// record with NO dialable address — matching the relay's `peer_id`-only addressing.
#[test]
fn from_nat_relay_peer_info_is_identity_only_via_relay() {
    let rpi = relay_peer(&"ab".repeat(32));
    let record = PeerRecord::from_nat_relay_peer_info(&rpi);

    assert_eq!(record.peer_id, "ab".repeat(32));
    assert_eq!(record.via, Via::Relay);
    assert!(
        record.addresses.is_empty(),
        "relay peers are addressed by peer_id — no dialable candidate"
    );
    assert!(
        record.best_address().is_none(),
        "an identity-only relay record has no dialable address"
    );
    assert!(
        record.to_timestamped_peer_info().is_none(),
        "a relay-only record is not placed in the by-address book"
    );
}

/// The regression at the heart of WU-B: relay-only peers (no direct address) must NOT be dropped.
/// After folding `dig-nat`'s discovered set, they are COUNTED as relay-reachable (stats
/// `relay_peer_count`) even though NONE of them enter the dial-by-address book.
#[tokio::test]
async fn relay_only_peers_survive_the_fold_and_are_counted_not_dropped() {
    let (svc, handle, _dir) = running_handle(1, 4, 8).await;

    let known = vec![relay_peer(&"11".repeat(32)), relay_peer(&"22".repeat(32))];
    handle.fold_relay_known_peers(&known);

    let stats = handle.stats().await;
    assert_eq!(
        stats.relay_peer_count, 2,
        "both relay-reachable peers survive the fold and are counted"
    );
    assert_eq!(
        stats.known_addresses, 0,
        "relay-only peers carry no dialable address, so the by-address book stays empty"
    );

    svc.stop().await.expect("stop");
}

/// Folding is a wholesale replace, mirroring `dig-nat`'s live set: a peer that dropped
/// (`PeerDisconnected`, gone from `known_peers`) disappears from the count on the next fold.
#[tokio::test]
async fn folding_replaces_the_relay_reachable_set() {
    let (svc, handle, _dir) = running_handle(1, 4, 8).await;

    handle.fold_relay_known_peers(&[relay_peer(&"11".repeat(32)), relay_peer(&"22".repeat(32))]);
    assert_eq!(handle.stats().await.relay_peer_count, 2);

    // One peer left the relay; the next snapshot has only the other.
    handle.fold_relay_known_peers(&[relay_peer(&"22".repeat(32))]);
    assert_eq!(
        handle.stats().await.relay_peer_count,
        1,
        "the dropped peer is no longer counted"
    );

    // Empty snapshot clears the set.
    handle.fold_relay_known_peers(&[]);
    assert_eq!(handle.stats().await.relay_peer_count, 0);

    svc.stop().await.expect("stop");
}

/// A relay that echoes THIS node back in its peer list must not count us as our own peer.
#[tokio::test]
async fn own_peer_id_is_excluded_from_the_relay_reachable_count() {
    let (svc, handle, _dir) = running_handle(1, 4, 8).await;
    let self_hex = handle.local_peer_id().expect("peer id").to_string();

    handle.fold_relay_known_peers(&[relay_peer(&self_hex), relay_peer(&"33".repeat(32))]);

    assert_eq!(
        handle.stats().await.relay_peer_count,
        1,
        "self is skipped; only the genuine peer is counted"
    );

    svc.stop().await.expect("stop");
}

/// Relay-reachable peers count toward the pool's connected total, so they shrink the free-slot dial
/// budget exactly like direct peers — the pool does not keep dialing for slots already filled via the
/// relay. With `target` peers all reached via the relay, a maintenance pass adds none.
#[tokio::test]
async fn relay_reachable_peers_count_toward_the_pool_and_consume_the_dial_budget() {
    let (svc, handle, _dir) = running_handle(1, 2, 8).await;

    handle.fold_relay_known_peers(&[relay_peer(&"11".repeat(32)), relay_peer(&"22".repeat(32))]);

    let added = handle.run_pool_maintenance_once().await;
    assert_eq!(
        added, 0,
        "the pool is already at target via the relay — no direct dials are planned"
    );

    svc.stop().await.expect("stop");
}

/// `relay_connected` in the stats reflects `dig-nat`'s attached reservation status: false with no
/// reservation, true once the live socket is held.
#[tokio::test]
async fn stats_relay_connected_reflects_the_attached_reservation() {
    let (svc, handle, _dir) = running_handle(1, 4, 8).await;
    assert!(
        !handle.stats().await.relay_connected,
        "no reservation attached yet"
    );

    let status = RelayStatus::new();
    handle.attach_relay_status(Arc::clone(&status));
    assert!(
        !handle.stats().await.relay_connected,
        "attached but the reservation is still resting (Disconnected)"
    );

    status.set_connected(0);
    assert!(
        handle.stats().await.relay_connected,
        "a held reservation reports connected"
    );

    svc.stop().await.expect("stop");
}
