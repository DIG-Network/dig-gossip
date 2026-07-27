//! Regression tests for **dig_ecosystem#1691 — a restarted peer cannot reconnect**.
//!
//! ## The defect
//!
//! The inbound guard ([`precheck_inbound_peer`]) rejected any new session whose `peer_id` already
//! had a slot in [`ServiceState::peers`](dig_gossip). A held slot carries no liveness value a guard
//! can consult: dig-gossip never removes a peer-map slot when the connection drops (the inbound
//! forwarder task simply ends), and the CON-004 keepalive REMOVES a slot on failure rather than
//! stamping a per-slot freshness timestamp. So after a peer restarts (upgrade / crash / service
//! bounce) and redials with the **same** `peer_id` (= `SHA-256(TLS SPKI DER)`, bound to its DIG
//! identity), the holder still had the stale slot and refused the reconnect — every subsequent read
//! that peer attempted 404'd. Observed live on the #1640 step-4a EC2 fleet.
//!
//! ## The fix under test — newest-wins, gated on the mTLS-proven identity
//!
//! Because there is no per-slot liveness signal to consult, the guard adopts **newest-wins**: the
//! freshly mTLS-authenticated inbound session supersedes the stale slot for the same `peer_id`. This
//! is safe because the inbound TLS handshake has already authenticated the newcomer as the holder of
//! the private key for `peer_id` — only the genuine peer can complete it — and the peer map keeps
//! exactly one slot per `peer_id` (replace, never grow), so the map stays bounded by distinct
//! authenticated identities.
//!
//! ## The ghost-keepalive hazard (also covered here)
//!
//! CON-004 keepalive is **on by default** (`keepalive_*_secs = None` resolves to 30 s ping / 90 s
//! timeout), so the superseded session's keepalive task must be stopped or it would fire a blind
//! teardown that evicts the *reconnect*. The fix aborts the displaced slot's keepalive on supersede
//! AND generation-guards every per-session teardown (a stale task compare-and-removes against its
//! own generation, so it can never evict a newer slot). [`stale_keepalive_does_not_evict_reconnect`]
//! drives this with short keepalive overrides and waits past the timeout.
//!
//! ## Proof strategy (real wire, not a symmetric mock)
//!
//! Every test drives the **real** [`GossipService`] listener over native-tls: TCP → TLS → WSS →
//! Chia handshake. A "restart" is a *fresh* client [`GossipService`] built from the **same TLS cert
//! files** (hence the same `peer_id`), after the prior client is dropped **without** a clean
//! shutdown so the server's slot survives.

mod common;

use std::path::Path;
use std::time::Duration;

use dig_gossip::{GossipConfig, GossipHandle, GossipService, PeerId};

/// Start a [`GossipService`] whose config is produced by `configure` — used to set short keepalive
/// timings so a stale keepalive actually fires inside the test window.
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

/// Start a full [`GossipService`] (TLS listener + accept loop) from an **existing** cert directory.
///
/// Reusing the same directory across restarts is the crux of the reconnect tests: the derived
/// `peer_id` is a hash of the TLS SPKI, so a client rebuilt from the same `test.crt`/`test.key`
/// presents the **same identity** — exactly what a real peer does across an upgrade/crash/bounce.
///
/// Returns `(service, handle)`; the caller keeps both alive for the connection's lifetime and drops
/// them to simulate an abrupt teardown.
async fn service_from_dir(dir: &Path) -> (GossipService, GossipHandle) {
    let cfg = common::test_gossip_config(dir);
    let svc = GossipService::new(cfg).expect("GossipService::new");
    let handle = svc.start().await.expect("GossipService::start");
    (svc, handle)
}

/// **#1691 core regression:** a restarted peer redialing with the same `peer_id` is **accepted**,
/// even though the holder still has the stale slot from the prior (abruptly-dropped) connection.
///
/// Fails before the fix because the duplicate guard rejected the reconnect at TLS time (the client's
/// `connect_to` errors out when the server drops the session pre-handshake).
#[tokio::test]
async fn restarted_peer_reconnects_and_supersedes_stale_slot() {
    // --- Server ---
    let server_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(server_dir.path());
    let (_server_svc, server_h) = service_from_dir(server_dir.path()).await;
    let bound = server_h
        .__listen_bound_addr_for_tests()
        .expect("listen addr after start");

    // --- Client identity, fixed across the restart ---
    let client_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(client_dir.path());

    // First connection: the server registers exactly one inbound slot.
    let (client1_svc, client1_h) = service_from_dir(client_dir.path()).await;
    client1_h.connect_to(bound).await.expect("first connect");
    let keys = server_h.__peer_ids_for_tests();
    assert_eq!(keys.len(), 1, "server registers exactly one inbound peer");
    let peer_pid = keys[0];

    // Abrupt teardown — drop the client WITHOUT `stop()`, so the server's slot is NOT reaped.
    drop(client1_h);
    drop(client1_svc);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        server_h.__peer_ids_for_tests().len(),
        1,
        "the stale inbound slot survives the abrupt disconnect (dig-gossip does not reap)"
    );

    // The peer restarts: same cert dir -> same peer_id -> redial.
    let (_client2_svc, client2_h) = service_from_dir(client_dir.path()).await;
    client2_h
        .connect_to(bound)
        .await
        .expect("RECONNECT must be accepted despite the stale slot (#1691)");

    // Accepted + bounded: still exactly one slot, for the same authenticated identity.
    let keys_after = server_h.__peer_ids_for_tests();
    assert_eq!(
        keys_after.len(),
        1,
        "newest-wins keeps exactly one slot per peer_id (map stays bounded)"
    );
    assert_eq!(
        keys_after[0], peer_pid,
        "the reconnected slot is keyed by the same cert-derived peer_id"
    );
    assert_eq!(
        server_h.peer_count().await,
        1,
        "one live peer after reconnect"
    );
}

/// **Map-boundedness under reconnect churn:** repeated restarts of the same identity never grow the
/// peer map beyond one slot — a single identity cannot exhaust the map by reconnecting.
#[tokio::test]
async fn reconnect_churn_keeps_peer_map_bounded() {
    let server_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(server_dir.path());
    let (_server_svc, server_h) = service_from_dir(server_dir.path()).await;
    let bound = server_h
        .__listen_bound_addr_for_tests()
        .expect("listen addr");

    let client_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(client_dir.path());

    let mut seen_pid: Option<PeerId> = None;
    for round in 0..5 {
        let (svc, handle) = service_from_dir(client_dir.path()).await;
        handle
            .connect_to(bound)
            .await
            .unwrap_or_else(|e| panic!("reconnect round {round} accepted: {e}"));

        let keys = server_h.__peer_ids_for_tests();
        assert_eq!(
            keys.len(),
            1,
            "round {round}: churn from one identity must not grow the map"
        );
        match seen_pid {
            Some(pid) => assert_eq!(pid, keys[0], "same identity across churn rounds"),
            None => seen_pid = Some(keys[0]),
        }

        // Abrupt teardown before the next round.
        drop(handle);
        drop(svc);
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
}

/// **Adversarial — no displacement without the cert:** a *different* identity (different TLS cert,
/// hence a different `peer_id`) gets its **own** slot and does **not** evict the incumbent. Only a
/// party that can complete the mTLS handshake as `peer_id` can reach the newest-wins path for that
/// slot, so a live peer cannot be displaced by anyone who lacks its key.
#[tokio::test]
async fn foreign_identity_cannot_displace_incumbent() {
    let server_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(server_dir.path());
    let (_server_svc, server_h) = service_from_dir(server_dir.path()).await;
    let bound = server_h
        .__listen_bound_addr_for_tests()
        .expect("listen addr");

    // Incumbent (cert A).
    let dir_a = common::test_temp_dir();
    let _ = common::generate_test_certs(dir_a.path());
    let (_svc_a, handle_a) = service_from_dir(dir_a.path()).await;
    handle_a
        .connect_to(bound)
        .await
        .expect("incumbent connects");
    let incumbent = server_h.__peer_ids_for_tests();
    assert_eq!(incumbent.len(), 1);
    let incumbent_pid = incumbent[0];

    // A distinct identity (cert B) connects — different peer_id, its own slot.
    let dir_b = common::test_temp_dir();
    let _ = common::generate_test_certs(dir_b.path());
    let (_svc_b, handle_b) = service_from_dir(dir_b.path()).await;
    handle_b.connect_to(bound).await.expect("foreign connects");

    let keys = server_h.__peer_ids_for_tests();
    assert_eq!(
        keys.len(),
        2,
        "a distinct identity gets its own slot — it does not evict the incumbent"
    );
    assert!(
        keys.contains(&incumbent_pid),
        "the incumbent slot is untouched by a foreign identity"
    );
}

/// **The ghost-keepalive race:** the superseded session's keepalive, if left running, would fire a
/// blind teardown and evict the reconnect — reintroducing #1691 as a timed race. This test uses
/// short server keepalive timings and waits PAST the stale timeout, then asserts the reconnect
/// survives and still serves.
///
/// Fails on a fix that only closes the displaced socket (the stale keepalive still ticks, its blind
/// `peers.remove(peer_id)` deletes the reconnect). Passes once the displaced keepalive is aborted on
/// supersede AND the teardown is generation-guarded.
#[tokio::test]
async fn stale_keepalive_does_not_evict_reconnect() {
    // Short keepalive so the STALE session's probe fails well inside the test window: 1 s ping, 2 s
    // staleness timeout. The server runs the per-inbound keepalive that would otherwise ghost-evict.
    let server_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(server_dir.path());
    let (_server_svc, server_h) = service_with_config(server_dir.path(), |cfg| {
        cfg.keepalive_ping_interval_secs = Some(1);
        cfg.keepalive_peer_timeout_secs = Some(2);
    })
    .await;
    let bound = server_h
        .__listen_bound_addr_for_tests()
        .expect("listen addr");

    let client_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(client_dir.path());

    // S1 connects, then is dropped abruptly — its server-side keepalive task keeps ticking.
    let (client1_svc, client1_h) = service_from_dir(client_dir.path()).await;
    client1_h.connect_to(bound).await.expect("first connect");
    let peer_pid = server_h.__peer_ids_for_tests()[0];
    drop(client1_h);
    drop(client1_svc);

    // S2 reconnects (same identity) BEFORE the stale keepalive's timeout elapses — the exact #1691
    // window. This supersedes S1; the fix must abort S1's keepalive.
    let (_client2_svc, client2_h) = service_from_dir(client_dir.path()).await;
    client2_h
        .connect_to(bound)
        .await
        .expect("reconnect accepted");
    assert_eq!(server_h.peer_count().await, 1, "reconnect registered");

    // Wait well past the stale keepalive's 2 s timeout. On the unfixed code S1's ghost keepalive now
    // blindly removes peer_pid — i.e. evicts S2. The reconnect (client2_h) is kept alive so the
    // server's keepalive on S2 itself keeps succeeding.
    tokio::time::sleep(Duration::from_secs(4)).await;

    let keys = server_h.__peer_ids_for_tests();
    assert_eq!(
        keys.len(),
        1,
        "the reconnect must survive the stale keepalive's timeout (no ghost eviction)"
    );
    assert_eq!(keys[0], peer_pid, "the surviving slot is the reconnect");
    assert_eq!(
        server_h.peer_count().await,
        1,
        "peer still connected after the stale keepalive would have fired"
    );
}
