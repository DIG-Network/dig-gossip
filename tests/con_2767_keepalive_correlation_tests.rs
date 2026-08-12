//! **#2767** — two connected dig-gossip peers must not tear each other's link down.
//!
//! ## The defect
//!
//! `DigLink` matches an inbound frame on correlation id *before* forwarding it to the application.
//! Both peers allocate correlation ids from a counter that starts at zero, and both keepalive loops
//! start at handshake on a shared interval — so two probes can carry the **same id**. Each side's
//! waiter then receives the peer's `RequestPeers` instead of a `RespondPeers`; the peer's request
//! never reaches the forwarder, its auto-reply never fires, neither side records a success, and both
//! disconnect at the staleness check while logging a timeout that names the wrong cause.
//!
//! ## Why these tests are shaped this way
//!
//! - **The teardown is silent and slow.** It surfaces as *"no successful probe within
//!   PEER_TIMEOUT_SECS"*, which is the wrong cause — so the assertion is **link survival across
//!   several probe intervals**, never a log line.
//! - **The collision must be forced, not hoped for.** An outbound dial burns correlation id 0 on
//!   `RequestPeers` (DSC-007) before its keepalive starts, leaving the two counters permanently
//!   offset by one. [`connect_and_align`] burns the matching id on the *inbound* side so
//!   both loops probe from the same id — the state that a mutual dial, or any application
//!   `request()` on one side, reaches on its own in production.
//! - **Real `tokio::time`.** This is real loopback I/O; a paused clock would not exercise it.
//!
//! Traceability: CON-004 (keepalive), SPEC §2.13, §5.1 step 7.

mod common;

use std::time::Duration;

use dig_gossip::{GossipHandle, GossipService, LinkOptions, PeerId};

/// Probe interval. Production is `PING_INTERVAL_SECS` (30); 1s keeps the test near its lower bound.
const PING_SECS: u64 = 1;
/// Staleness window. Production is `PEER_TIMEOUT_SECS` (90); 3s means the buggy build tears the
/// link down well inside [`OBSERVE_SECS`].
const TIMEOUT_SECS: u64 = 3;
/// How long the link is observed. Six probe intervals — two full staleness windows — so a build
/// that never records a success cannot survive by luck.
const OBSERVE_SECS: u64 = 6;

/// Build a started service whose keepalive runs on the fast test timings.
async fn service(dir: &tempfile::TempDir) -> (GossipService, GossipHandle) {
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.keepalive_ping_interval_secs = Some(PING_SECS);
    cfg.keepalive_peer_timeout_secs = Some(TIMEOUT_SECS);
    // `RequestPeers` is capped by `V2_RATE_LIMITS` (~6/min at the default factor); sub-second
    // probes need headroom or keepalive throttles instead of probing.
    let mut link_options = LinkOptions::default();
    link_options.rate_limit_factor = 20.0;
    cfg.peer_options = link_options;
    let svc = GossipService::new(cfg).expect("new service");
    let handle = svc.start().await.expect("start service");
    (svc, handle)
}

/// Connect `a -> b` and leave both keepalive loops probing from the SAME correlation id.
///
/// The dialer burns id 0 on its DSC-007 `RequestPeers`; issuing one application request from the
/// accepting side burns its id 0 too. Without this the counters stay offset and the collision — the
/// whole subject of this file — never occurs.
async fn connect_and_align(
    a: &GossipHandle,
    b: &GossipHandle,
    b_addr: std::net::SocketAddr,
) -> (PeerId, PeerId) {
    let b_on_a = a.connect_to(b_addr).await.expect("A dials B");

    // The inbound slot lands as `negotiate_inbound_over_ws` finishes; poll rather than guess, and
    // stay well inside the first probe interval.
    let a_on_b = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if let Some(id) = b.__peer_ids_for_tests().first().copied() {
                return id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("B registers the inbound peer before the first probe");

    b.request_peers_from(&a_on_b)
        .await
        .expect("the align request must be answered");

    (b_on_a, a_on_b)
}

/// **The regression.** Two live peers whose keepalive loops probe from identical correlation ids
/// must both still be connected after six probe intervals, with no reconnect in between.
///
/// Before the fix both loops steal each other's probe, never record a success, and disconnect at
/// the staleness check inside three seconds.
#[tokio::test]
async fn colliding_correlation_ids_do_not_tear_the_link_down() {
    let dir_b = common::test_temp_dir();
    let (_svc_b, h_b) = service(&dir_b).await;
    let bound = h_b.__listen_bound_addr_for_tests().expect("B listening");

    let dir_a = common::test_temp_dir();
    let (_svc_a, h_a) = service(&dir_a).await;

    let (b_on_a, a_on_b) = connect_and_align(&h_a, &h_b, bound).await;

    tokio::time::sleep(Duration::from_secs(OBSERVE_SECS)).await;

    assert!(
        h_a.__peer_ids_for_tests().contains(&b_on_a),
        "A must still hold B after {OBSERVE_SECS}s of probing"
    );
    assert!(
        h_b.__peer_ids_for_tests().contains(&a_on_b),
        "B must still hold A after {OBSERVE_SECS}s of probing"
    );
    assert_eq!(
        h_a.stats().await.total_connections,
        1,
        "the surviving link must be the ORIGINAL one — a reconnect would also leave a peer present"
    );
    assert_eq!(
        h_b.stats().await.total_connections,
        1,
        "same, from B's side"
    );

    // The probes must have been observed, not merely survived: a build that stopped probing
    // altogether would also pass the assertions above.
    let rtt = h_a
        .__con004_peer_reputation_for_tests(b_on_a)
        .expect("A's live slot")
        .rtt_history;
    assert!(
        rtt.len() >= 2,
        "A must have recorded successful probes, got {rtt:?}"
    );
}

/// **Fail open.** The reply is observed on the service-wide inbound broadcast, which does not exist
/// while the service is starting or stopping. A probe we cannot observe is not evidence the peer is
/// dead, and the only action this loop can take is to disconnect — so the round is skipped and the
/// peer is kept.
#[tokio::test]
async fn an_unobservable_probe_does_not_disconnect_the_peer() {
    let dir_b = common::test_temp_dir();
    let (_svc_b, h_b) = service(&dir_b).await;
    let bound = h_b.__listen_bound_addr_for_tests().expect("B listening");

    let dir_a = common::test_temp_dir();
    let (_svc_a, h_a) = service(&dir_a).await;

    let b_on_a = h_a.connect_to(bound).await.expect("A dials B");

    // Remove A's inbound broadcast: A can still send, but can no longer observe any reply.
    {
        let state = h_a.__state_arc_for_tests();
        *state.inbound_tx.lock().expect("inbound_tx mutex") = None;
    }

    tokio::time::sleep(Duration::from_secs(OBSERVE_SECS)).await;

    assert!(
        h_a.__peer_ids_for_tests().contains(&b_on_a),
        "an unobservable probe must keep the peer, not tear it down"
    );
    assert!(
        h_a.__con004_penalty_points_for_tests(b_on_a).unwrap_or(0) == 0,
        "no keepalive-failure penalty may be charged for a probe we could not observe"
    );
}
