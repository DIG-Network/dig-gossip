//! Regression tests for **dig_ecosystem#1792 — the Plumtree map-remove → plumtree-remove reconnect
//! guard.**
//!
//! ## The defect
//!
//! Both peer-departure paths — [`GossipHandle::disconnect`] and the reaper's
//! [`reap_departed_peers`](dig_gossip) Phase 2 — remove a peer id from the `peers` map under the
//! lock, RELEASE the lock, then call `plumtree.remove_peer(id)`. A concurrent reconnect
//! (`adopt_nat_connection` / `connect_to` → `plumtree.add_peer(id)`) landing in that gap re-inserts
//! the id into `peers` and re-adds it to Plumtree with a FRESH eager membership; the trailing,
//! unconditional `plumtree.remove_peer(id)` then WIPES that live membership — a transient partition
//! of a healthy peer.
//!
//! ## The fix under test
//!
//! A best-effort re-check guard shared by both sites
//! (`ServiceState::remove_from_plumtree_unless_reconnected`, exercised here via
//! [`GossipHandle::__remove_from_plumtree_unless_reconnected_for_tests`]): before the trailing
//! `plumtree.remove_peer`, re-read `peers`; if the id is present again (a reconnect re-inserted it),
//! SKIP the removal so the reconnect's `add_peer` wins. The two locks stay separate (no
//! `peers`+`plumtree` nesting), so the guard NARROWS — does not eliminate — the window; the residual
//! is self-healing via IHAVE/GRAFT.

mod common;

use std::net::SocketAddr;

use dig_gossip::{GossipHandle, GossipService, NodeType, PeerId};

/// A running service with an idle (1 h) reaper timer, so nothing races the deterministic drives here.
async fn running_handle() -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 32;
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    (svc, handle, dir)
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// **#1792 core regression:** when a reconnect has re-inserted the id into the `peers` map before the
/// trailing Plumtree cleanup, the guard MUST skip `plumtree.remove_peer` so the reconnect's fresh
/// membership survives. RED before the fix: the unconditional `plumtree.remove_peer` wipes the
/// reconnected peer's eager membership — a transient partition of a live peer.
#[tokio::test]
async fn reconnect_in_gap_keeps_plumtree_membership() {
    let (svc, handle, _dir) = running_handle().await;

    // Model the state as it is AFTER a reconnect landed in the map→plumtree gap: the id is present in
    // BOTH the peer map (a fresh slot) and Plumtree (a fresh eager membership).
    let pid = handle
        .__connect_stub_peer_with_direction(addr("203.0.113.92:9445"), NodeType::FullNode, true)
        .await
        .expect("stub connect re-inserts the reconnecting peer into the map");
    handle.__plumtree_add_peer_for_tests(pid);
    assert!(
        handle.__plumtree_contains_for_tests(&pid),
        "the reconnecting peer is registered in Plumtree"
    );

    // The departing path's trailing cleanup runs — but the peer is present in the map again.
    handle.__remove_from_plumtree_unless_reconnected_for_tests(&pid);

    assert!(
        handle.__plumtree_contains_for_tests(&pid),
        "the guard must SKIP the Plumtree removal — the reconnect's add_peer wins"
    );

    svc.stop().await.expect("stop");
}

/// **#1792 guard fidelity:** when the id is genuinely gone from the map (the ordinary departure with
/// no reconnect), the guard MUST still remove it from Plumtree — parity with the pre-#1792 behaviour,
/// so a real disconnect/reap does not leak the id in the eager/lazy sets.
#[tokio::test]
async fn absent_peer_is_removed_from_plumtree() {
    let (svc, handle, _dir) = running_handle().await;

    // An id present in Plumtree but NOT in the peer map — the state right after an atomic map removal.
    let pid = PeerId::from([92u8; 32]);
    handle.__plumtree_add_peer_for_tests(pid);
    assert!(handle.__plumtree_contains_for_tests(&pid));

    handle.__remove_from_plumtree_unless_reconnected_for_tests(&pid);

    assert!(
        !handle.__plumtree_contains_for_tests(&pid),
        "with no reconnect, the guard removes the departed id from Plumtree (leak parity)"
    );

    svc.stop().await.expect("stop");
}
