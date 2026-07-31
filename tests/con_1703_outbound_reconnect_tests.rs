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

    // Legitimate outbound to L1 — occupies /16 group 127.0 in the peer map (the single source of
    // truth for outbound diversity occupancy, #1703). A real `connect_to` inserts a live OUTBOUND
    // slot; occupancy is then derived from that map, not from any side-set.
    client_h
        .connect_to(l1_bound)
        .await
        .expect("outbound to L1 occupies the /16 group");
    assert_eq!(
        client_h.__stub_filter_count_for_tests(None, true).await,
        1,
        "the real outbound to L1 must occupy the /16 group (127.0) in the peer map — else the INT-006 \
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
        matches!(err, GossipError::ConnectionFiltered(ref m) if m.as_str().contains("INT-006")),
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

/// **#1703 round-5 under-count regression (the set-vs-map drift trap).** Proves outbound diversity
/// occupancy is derived from the peer map — the single source of truth — and NOT from a parallel
/// side-set that can under-count.
///
/// The round-4 code tracked outbound `/16` occupancy in a refcount-free `HashSet` that only
/// `connect_to` ever populated (`add_outbound`), and it deleted a group entry unconditionally on
/// supersede/disconnect even when another live outbound still occupied that group — so the set could
/// report a group as FREE while the peer map still held an outbound connection in it, wrongly
/// admitting a SECOND outbound into the group (the exact INT-006 eclipse cap this lane enforces).
///
/// This test constructs precisely that divergence WITHOUT any supersede gymnastics: seeding an
/// OUTBOUND slot directly into the peer map (via the stub helper) populates the map but NEVER touches
/// the side-set — so on round-4 the set is empty for group `127.0` while the map holds an outbound
/// there. A net-new verified identity then dials into that same `/16`.
///
/// RED (round-4 side-set): the empty set reports `127.0` free → the net-new dial is ADMITTED → two
/// outbound in one `/16`. GREEN (map-derived): the occupancy count sees the seeded outbound slot in
/// `127.0` and REFUSES with the INT-006 error.
#[tokio::test]
async fn map_derived_occupancy_refuses_new_identity_when_a_seeded_outbound_holds_the_group() {
    // A real listener the net-new dial will complete a handshake against — on loopback, so its `/16`
    // group is 127.0 (loopback is all one /16, so a same-group occupant is a different loopback IP).
    let listener_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(listener_dir.path());
    let (_listener_svc, listener_h) = service_from_dir(listener_dir.path()).await;
    let listener_bound = listener_h
        .__listen_bound_addr_for_tests()
        .expect("listener addr");

    let client_dir = common::test_temp_dir();
    let _ = common::generate_test_certs(client_dir.path());
    let (_client_svc, client_h) = service_from_dir(client_dir.path()).await;

    // Seed an OUTBOUND slot in the SAME /16 (127.0) directly into the peer map, at a DIFFERENT
    // loopback address than the listener (so a distinct `peer_id`). The stub path writes ONLY the peer
    // map — it never calls the round-4 `add_outbound` — so on the round-4 side-set code group 127.0 is
    // absent from the set (the under-count) while the map plainly holds an outbound there.
    let seeded_outbound: std::net::SocketAddr = "127.0.0.99:59999".parse().expect("valid addr");
    assert_ne!(
        seeded_outbound.ip(),
        listener_bound.ip(),
        "the seeded occupant must be a distinct address so it carries a distinct peer_id"
    );
    client_h
        .__connect_stub_peer_with_direction(seeded_outbound, NodeType::FullNode, true)
        .await
        .expect("seed an outbound slot occupying /16 127.0 in the peer map");

    // The seeded occupant must be present right up to the dial — the test config uses `peer_pool: None`
    // so no background loop touches the map, but assert it so any future regression that drops the
    // occupant fails LOUDLY here rather than silently weakening the INT-006 refusal below.
    assert_eq!(
        client_h.__stub_filter_count_for_tests(None, true).await,
        1,
        "the seeded outbound occupant must hold /16 127.0 when the net-new dial is made"
    );

    // Dial the listener: a real handshake yields its net-new verified identity, in the /16 127.0 the
    // seeded outbound slot already occupies. Map-derived occupancy must REFUSE (INT-006). On round-4
    // the empty side-set admitted it — a second outbound in the group.
    let err = client_h.connect_to(listener_bound).await.expect_err(
        "a net-new verified identity in a /16 the peer map already shows occupied must be refused",
    );
    assert!(
        matches!(err, GossipError::ConnectionFiltered(ref m) if m.as_str().contains("INT-006")),
        "expected INT-006 diversity refusal derived from the peer map, got {err:?}"
    );

    // No eclipse admission: still exactly one OUTBOUND slot (the seeded occupant); the listener was
    // not admitted as a second outbound in 127.0.
    assert_eq!(
        client_h.__stub_filter_count_for_tests(None, true).await,
        1,
        "the net-new dial must not have landed a second outbound in the occupied /16"
    );
}
