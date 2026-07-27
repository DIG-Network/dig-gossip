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
//! the faithful driver of the exact guard the fix removes — the surviving slot is indistinguishable,
//! at the `connect_to` guard, from a slot left by an abruptly-dropped connection.

mod common;

use std::path::Path;

use dig_gossip::{GossipError, GossipHandle, GossipService, NodeType};

/// Start a full [`GossipService`] (TLS listener + accept loop) from an existing cert directory.
async fn service_from_dir(dir: &Path) -> (GossipService, GossipHandle) {
    let cfg = common::test_gossip_config(dir);
    let svc = GossipService::new(cfg).expect("GossipService::new");
    let handle = svc.start().await.expect("GossipService::start");
    (svc, handle)
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
    let server_pid = client_h
        .connect_to(bound)
        .await
        .expect("first outbound dial");
    assert_eq!(
        client_h.peer_count().await,
        1,
        "one outbound peer after dial"
    );
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

/// **#1703 eclipse-admission regression (security gate).** The reconnect bypass must NOT let a peer
/// exceed the one-outbound-per-/16 (INT-006) diversity cap. A peer-map slot at the dialed address
/// that is NOT an outbound slot for the handshake-VERIFIED identity — here an inbound slot injected at
/// a second listener's address (its `remote` would, in the wild, come from attacker-influenced
/// `RespondPeers`) — does not consume this node's outbound diversity budget, so admitting past the
/// filters on address alone would place a SECOND outbound peer in an already-occupied /16.
///
/// Setup: a legitimate outbound to `L1` fills /16 group `127.0`. An inbound stub is injected at `L2`'s
/// address (same /16, a DIFFERENT peer_id than `L2`'s real cert). `connect_to(L2)` then completes a
/// real handshake yielding `L2`'s net-new verified peer_id.
///
/// RED (pre-fix): the address-keyed `is_reconnect` predicate matched the inbound stub, bypassed
/// INT-006, and admitted a second outbound in `127.0`. GREEN: the diversity decision is made against
/// the verified identity, so the dial is refused with the INT-006 error.
#[tokio::test]
async fn eclipse_admission_is_refused_for_verified_new_identity_in_full_group() {
    // L1 — the legitimate outbound that fills /16 group 127.0.
    let l1_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(l1_dir.path());
    let (_l1_svc, l1_h) = service_from_dir(l1_dir.path()).await;
    let l1_bound = l1_h
        .__listen_bound_addr_for_tests()
        .expect("L1 listen addr");

    // L2 — a distinct real listener (distinct cert => distinct verified peer_id), same /16.
    let l2_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(l2_dir.path());
    let (_l2_svc, l2_h) = service_from_dir(l2_dir.path()).await;
    let l2_bound = l2_h
        .__listen_bound_addr_for_tests()
        .expect("L2 listen addr");

    let client_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(client_dir.path());
    let (_client_svc, client_h) = service_from_dir(client_dir.path()).await;

    // Legitimate outbound to L1 — claims the outbound /16 budget for group 127.0. This is the
    // PRODUCTION path (`connect_to` is the only caller of `add_outbound`); a directly-seeded slot would
    // NOT populate the filter, and the eclipse gate below would then have nothing to fire against.
    client_h
        .connect_to(l1_bound)
        .await
        .expect("outbound to L1 fills the /16 budget");
    assert_eq!(
        client_h.__outbound_subnet_group_count_for_tests(),
        1,
        "the real outbound to L1 must have populated the /16 budget (group 127.0) — else the INT-006 \
         refusal below would be vacuous and the test would pass for the wrong reason"
    );

    // Inject an INBOUND slot at L2's address (peer_id_for_addr(l2_bound) — NOT L2's cert identity).
    // An inbound slot does not consume the outbound diversity budget; it only shares the address.
    client_h
        .__connect_stub_peer_with_direction(l2_bound, NodeType::FullNode, false)
        .await
        .expect("inject inbound slot sharing L2's address");

    // Dial L2: the handshake yields L2's net-new verified identity in the already-full /16 127.0.
    // The verified-identity diversity gate must REFUSE (INT-006).
    let err = client_h.connect_to(l2_bound).await.expect_err(
        "a net-new verified identity in a full /16 must be refused, not eclipse-admitted",
    );
    assert!(
        matches!(err, GossipError::ConnectionFiltered(ref m) if m.contains("INT-006")),
        "expected INT-006 diversity refusal, got {err:?}"
    );

    // The eclipse admission did not happen: no second outbound Live peer landed in group 127.0. The
    // client holds exactly the L1 outbound + the injected inbound stub (two entries, one outbound).
    assert_eq!(
        client_h.__stub_filter_count_for_tests(None, true).await,
        1,
        "exactly one OUTBOUND peer — L2 was not admitted as a second outbound in the full /16"
    );
}
