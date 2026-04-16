//! Integration and focused unit tests for **CON-004: keepalive + peer timeout**.
//!
//! ## Traceability
//!
//! - **Spec:** [`CON-004.md`](../docs/requirements/domains/connection/specs/CON-004.md) — §Test Plan,
//!   §Acceptance Criteria (Ping/C pong semantics, 30s / 90s production defaults, RTT, penalties).
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/connection/NORMATIVE.md) §CON-004
//! - **Constants:** production defaults `PING_INTERVAL_SECS` / `PEER_TIMEOUT_SECS` in `dig_gossip::constants`.
//!
//! ## Proof strategy
//!
//! Production uses **`RequestPeers` → `RespondPeers`** as the application keepalive round-trip
//! (see [`dig_gossip::connection::keepalive`] rustdoc — `chia-protocol` 0.26 has no separate
//! `Ping`/`Pong` message types). **`GossipConfig::keepalive_*_secs`** overrides shorten sleeps so
//! these tests finish in seconds without changing default SPEC numbers for real nodes.

mod common;

use std::time::Duration;

use dig_gossip::{GossipHandle, GossipService, PeerOptions, PenaltyReason};
use dig_gossip::{PeerId, PeerReputation};

/// Short keepalive period for tests (seconds between probes).
/// Production uses 30s (PING_INTERVAL_SECS); 1s here keeps test wall-time under 15s.
const TEST_PING_SECS: u64 = 1;

/// Allow several missed ticks before asserting staleness in RTT test.
/// Set high enough that a healthy peer never times out during `test_keepalive_probe_records_rtt`.
const TEST_TIMEOUT_SECS: u64 = 30;

/// Shorter `keepalive_peer_timeout_secs` for the dead-peer test.
/// Must be long enough for at least one successful probe but short enough that the
/// timeout-disconnect test completes in reasonable wall-time.
const TEST_DISCONNECT_PEER_TIMEOUT_SECS: u64 = 8;

/// Build a [`GossipService`] + [`GossipHandle`] with custom keepalive timings.
///
/// `ping` controls how often probes are sent; `timeout` controls how long we wait
/// for a pong before declaring the peer dead. The rate limit factor is set high (20.0)
/// to avoid `V2_RATE_LIMITS` throttling on rapid `RequestPeers` probes.
///
/// Used by: all `test_keepalive_*` and `test_timeout_*` tests.
async fn service_with_keepalive(
    dir: &tempfile::TempDir,
    ping: u64,
    timeout: u64,
) -> (GossipService, GossipHandle) {
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.keepalive_ping_interval_secs = Some(ping);
    cfg.keepalive_peer_timeout_secs = Some(timeout);
    // [`RequestPeers`] is capped by `V2_RATE_LIMITS` (~6/min with default `rate_limit_factor` 0.6);
    // sub-second probes in this file need a higher factor so keepalive is not stuck throttling.
    cfg.peer_options = PeerOptions {
        rate_limit_factor: 20.0,
    };
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    (svc, h)
}

/// **Row:** `test_keepalive_probe_records_rtt` — periodic successful probes append RTT samples on
/// [`PeerReputation`] (CON-004 + API-006 circular buffer).
/// SPEC §2.13 — `PING_INTERVAL_SECS` (30s production default); test overrides to 1s.
/// SPEC §1.6#7 — timestamp update on message: outbound peer timestamps updated in
/// address manager on message receipt.
#[tokio::test]
async fn test_keepalive_probe_records_rtt() {
    let dir_b = common::test_temp_dir();
    let (_svc_b, h_b) = service_with_keepalive(&dir_b, TEST_PING_SECS, TEST_TIMEOUT_SECS).await;
    let bound = h_b.__listen_bound_addr_for_tests().expect("B listen");

    let dir_a = common::test_temp_dir();
    let (_svc_a, h_a) = service_with_keepalive(&dir_a, TEST_PING_SECS, TEST_TIMEOUT_SECS).await;

    let peer_b_id: PeerId = h_a.connect_to(bound).await.expect("A→B");
    assert_eq!(
        h_a.peer_count().await,
        1,
        "peer should be registered immediately after connect_to"
    );
    // First probe runs after TEST_PING_SECS; accumulate a few round-trips.
    tokio::time::sleep(Duration::from_secs(TEST_PING_SECS * 4 + 1)).await;

    let rep = h_a
        .__con004_peer_reputation_for_tests(peer_b_id)
        .expect("live slot reputation");
    assert!(
        rep.rtt_history.len() >= 2,
        "expected multiple RTT samples from keepalive probes, got {:?}",
        rep.rtt_history
    );
    assert!(
        rep.avg_rtt_ms.is_some(),
        "avg_rtt_ms should be set after samples (CON-004 / API-006)"
    );
}

/// **Row:** `test_keepalive_bidirectional` — inbound and outbound paths both call
/// [`dig_gossip::connection::keepalive::spawn_keepalive_task`]; each side accumulates RTT toward
/// the remote [`PeerId`].
#[tokio::test]
async fn test_keepalive_bidirectional() {
    let dir_b = common::test_temp_dir();
    let (_svc_b, h_b) = service_with_keepalive(&dir_b, TEST_PING_SECS, TEST_TIMEOUT_SECS).await;
    let bound = h_b.__listen_bound_addr_for_tests().expect("B listen");

    let dir_a = common::test_temp_dir();
    let (_svc_a, h_a) = service_with_keepalive(&dir_a, TEST_PING_SECS, TEST_TIMEOUT_SECS).await;

    let peer_b_on_a = h_a.connect_to(bound).await.expect("connect");
    tokio::time::sleep(Duration::from_secs(1)).await;

    let keys_b = h_b.__peer_ids_for_tests();
    assert_eq!(keys_b.len(), 1, "B should see one inbound peer");
    let peer_a_on_b = keys_b[0];

    tokio::time::sleep(Duration::from_secs(TEST_PING_SECS * 3 + 1)).await;

    let rep_a = h_a
        .__con004_peer_reputation_for_tests(peer_b_on_a)
        .expect("A→B reputation");
    let rep_b = h_b
        .__con004_peer_reputation_for_tests(peer_a_on_b)
        .expect("B→A reputation");

    assert!(
        !rep_a.rtt_history.is_empty() && !rep_b.rtt_history.is_empty(),
        "both directions should record RTT: A={:?} B={:?}",
        rep_a.rtt_history,
        rep_b.rtt_history
    );
}

/// **Row:** `test_timeout_disconnect_applies_connection_issue_penalty` — when probes fail (peer
/// gone), we disconnect and add [`PenaltyReason::ConnectionIssue`] points (**10**) to the service
/// penalty map (CON-004 §Disconnect on Timeout).
/// SPEC §2.13 — `PEER_TIMEOUT_SECS` (90s production); test overrides to 8s.
#[tokio::test]
async fn test_timeout_disconnect_applies_connection_issue_penalty() {
    let dir_b = common::test_temp_dir();
    let (svc_b, h_b) =
        service_with_keepalive(&dir_b, TEST_PING_SECS, TEST_DISCONNECT_PEER_TIMEOUT_SECS).await;
    let bound = h_b.__listen_bound_addr_for_tests().expect("B listen");

    let dir_a = common::test_temp_dir();
    let (_svc_a, h_a) =
        service_with_keepalive(&dir_a, TEST_PING_SECS, TEST_DISCONNECT_PEER_TIMEOUT_SECS).await;

    let peer_b = h_a.connect_to(bound).await.expect("connect");
    // Ensure at least one successful probe so we are past handshake-only state.
    tokio::time::sleep(Duration::from_secs(TEST_PING_SECS + 1)).await;

    svc_b.stop().await.expect("stop B");
    drop(h_b);

    // One probe interval + `tokio::timeout(keepalive_peer_timeout_secs)` margin after B is gone.
    tokio::time::sleep(Duration::from_secs(
        TEST_PING_SECS + TEST_DISCONNECT_PEER_TIMEOUT_SECS + 2,
    ))
    .await;

    assert_eq!(
        h_a.peer_count().await,
        0,
        "A should drop dead peer after failed keepalive"
    );
    assert_eq!(
        h_a.__con004_penalty_points_for_tests(peer_b),
        Some(PenaltyReason::ConnectionIssue.penalty_points()),
        "ConnectionIssue penalty must match CON-007 weight table"
    );
}

/// **Row:** `test_rtt_measurement_unit` — RTT stored equals last injected sample for average
/// calculation (semantic link to CON-004 §Pong Handling; implementation is [`PeerReputation::record_rtt_ms`]).
#[test]
fn test_rtt_measurement_unit() {
    let mut rep = PeerReputation::default();
    rep.record_rtt_ms(10);
    rep.record_rtt_ms(20);
    assert_eq!(rep.avg_rtt_ms, Some(15));
}
