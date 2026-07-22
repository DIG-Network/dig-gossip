//! #1517 — the two auto-dial defects that blocked #1062 Leg B (relayed connect) on dig-node
//! v0.53.0 / dig-nat 0.10, once #1422's SPKI-pinned dialer resolved the prior `UnknownIssuer`.
//!
//! Both defects live in dig-gossip's pool auto-dial path (`HandleDialer` + the discovery →
//! pool-candidate pipeline), NOT in dig-nat (whose `PeerTarget`/strategy API already accepts a pin
//! and ranks the relay tier last) nor in dig-node.
//!
//! **Defect 1 — the auto-dial pinned an all-zeros peer_id.** The relay introducer / dig-nat
//! reservation resolves a peer's reflexive candidate ADDRESS *and* its `peer_id` together (RLY-005),
//! but the Chia address book stores only `host:port`, so the discovered id was DROPPED and the pool
//! dialed with a `[0u8; 32]` pin the (now-working) mTLS verifier correctly rejected
//! (`expected 0000… got 700b…`). The fix threads the discovered id into the [`PoolCandidate`] so the
//! SPKI pin is populated.
//!
//! **Defect 2 — no relay-circuit fallback.** The pool dialer enabled ONLY
//! [`TraversalKind::Direct`], so after Direct failed the strategy stopped — the SPKI-pinned RELAYED
//! transport was never exercised. The fix dials the FULL ladder (Direct … Relayed) so a truly-NAT'd
//! pair still reaches each other over the relay circuit.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use dig_gossip::nat::nat_connect_with_runtime;
use dig_gossip::{GossipHandle, GossipService, NatError, NatPeerId, PeerPoolConfig};
use dig_nat::relay::RelayStatus;
use dig_nat::wire::RelayPeerInfo;
use dig_nat::{NatConfig, PeerTarget, TraversalKind};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A relay-discovered peer carrying BOTH its resolved reflexive candidate address(es) AND its
/// `peer_id` (the RLY-005 record shape #870/#924 folds).
fn relay_peer_with_addrs(peer_id: &str, addrs: Vec<SocketAddr>) -> RelayPeerInfo {
    let mut rpi = RelayPeerInfo::new(peer_id.to_string(), "DIG_MAINNET".to_string(), 1);
    rpi.addresses = addrs;
    rpi
}

async fn running_handle() -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 32;
    cfg.peer_pool = Some(PeerPoolConfig {
        min_peers: 1,
        target_peers: 4,
        max_peers: 8,
        maintenance_interval_secs: 3600,
        ..Default::default()
    });
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    (svc, handle, dir)
}

// -------------------------------------------------------------------------------------------------
// Defect 1 — the discovered peer_id must reach the pool candidate's SPKI pin
// -------------------------------------------------------------------------------------------------

/// After folding a relay-discovered peer that carries a dialable candidate AND its `peer_id`, the
/// pool candidate gathered for that address MUST carry the discovered `peer_id` — never `None`
/// (which the dialer would turn into the all-zeros pin the mTLS verifier rejects).
#[tokio::test]
async fn gathered_candidate_pins_the_discovered_peer_id() {
    let (svc, handle, _dir) = running_handle().await;

    let peer_hex = "70".repeat(32); // 64-hex all-0x70, mirrors the real e2e's `700b…` remote id
    let cand_addr = addr("198.51.100.7:9445");
    handle.fold_relay_known_peers(&[relay_peer_with_addrs(&peer_hex, vec![cand_addr])]);

    let candidates = handle.__pool_gathered_candidates_with_stack_for_tests(8, true, true);
    let found = candidates
        .iter()
        .find(|c| c.addr == Some(cand_addr))
        .expect("the relay-discovered dialable candidate must be gathered for the pool");

    let expected = dig_gossip::PeerId::from([0x70u8; 32]);
    assert_eq!(
        found.peer_id,
        Some(expected),
        "the discovered peer_id must be threaded into the pool candidate so the SPKI pin is populated \
         (defect 1: a None pin becomes the all-zeros pin the mTLS verifier rejects)"
    );

    svc.stop().await.expect("stop");
}

// -------------------------------------------------------------------------------------------------
// Defect 2 — the pool auto-dial must attempt the relay circuit, not Direct-only
// -------------------------------------------------------------------------------------------------

/// The traversal ladder the pool auto-dialer enables MUST include [`TraversalKind::Relayed`] (the
/// TURN-last fallback) — not `[Direct]` alone — so a peer that fails every direct/mapping tier is
/// still reached over the SPKI-pinned relay circuit.
#[test]
fn pool_auto_dial_ladder_includes_the_relay_circuit() {
    let methods = dig_gossip::pool_auto_dial_traversal_methods();
    assert!(
        methods.contains(&TraversalKind::Direct),
        "the ladder still tries the cheapest direct path first"
    );
    assert!(
        methods.contains(&TraversalKind::Relayed),
        "defect 2: the ladder MUST also include the relay circuit as the last-resort fallback, \
         not stop at Direct"
    );
}

/// The static ladder (above) listing `Relayed` is necessary but NOT sufficient: the real root cause
/// of defect 2 was that the pool dial ran over the DEFAULT `NatRuntime`, which carries no relay
/// dialer, so dig-nat silently composed the Relayed tier AWAY. The fix is that
/// [`GossipHandle::pool_dial_runtime`] builds a `NatRuntime` from the held [`RelayStatus`] with a
/// `ReservationRelayedTransport` (a `RelayedDialer`) wired in.
///
/// This asserts that wiring WITHOUT a live relay, using dig-nat's own composition rule: a
/// Relayed-ONLY dial over the pool runtime returns [`NatError::NoMethodsEnabled`] iff the Relayed
/// tier was composed away (no dialer wired), and is actually ATTEMPTED (→ [`NatError::AllMethodsFailed`])
/// iff the dialer is present. So a default relay-less runtime and a reservation-wired one are
/// distinguishable by the error alone — no relay server required. The test FAILS against the old
/// relay-less-runtime behaviour (the wired case would return `NoMethodsEnabled`).
#[tokio::test]
async fn pool_dial_runtime_wires_the_relay_circuit_only_when_a_reservation_is_attached() {
    // A Relayed-only dial to a relay-only target: dig-nat composes the ladder from the runtime, so
    // whether the Relayed tier exists is decided purely by `runtime.relayed`.
    let relayed_only = NatConfig::builder()
        .enabled_methods(vec![TraversalKind::Relayed])
        .per_method_timeout(Duration::from_millis(200))
        .build();
    let target = PeerTarget::relay_only(NatPeerId::from_bytes([0x70u8; 32]), "DIG_MAINNET");

    // --- Baseline: NO reservation attached → the old relay-less runtime. Relayed composed away.
    let (svc, handle, _dir) = running_handle().await;
    let identity = handle.nat_identity().expect("nat identity");
    let runtime = handle.__pool_dial_runtime_for_tests();
    let err = nat_connect_with_runtime(&target, &identity, &relayed_only, &runtime)
        .await
        .expect_err("a Relayed-only dial with no relay dialer wired cannot succeed");
    assert!(
        matches!(err, NatError::NoMethodsEnabled),
        "without a relay reservation the pool runtime must NOT compose the Relayed tier \
         (got {err:?}) — this is the pre-fix relay-less behaviour"
    );
    svc.stop().await.expect("stop");

    // --- Fixed: a reservation attached → pool_dial_runtime wires the ReservationRelayedTransport,
    // so the Relayed tier is genuinely composed + attempted (and fails only because no relay is up).
    let (svc, handle, _dir) = running_handle().await;
    handle.attach_relay_status(RelayStatus::new());
    let identity = handle.nat_identity().expect("nat identity");
    let runtime = handle.__pool_dial_runtime_for_tests();
    let err = nat_connect_with_runtime(&target, &identity, &relayed_only, &runtime)
        .await
        .expect_err("no live relay is running, so the composed Relayed tier still fails to connect");
    assert!(
        !matches!(err, NatError::NoMethodsEnabled),
        "with a relay reservation attached the pool runtime MUST compose + ATTEMPT the Relayed tier \
         (the ReservationRelayedTransport is wired), not drop it (got {err:?}) — this is the \
         runtime-wiring half of defect 2 that e2e #1062 previously covered alone"
    );
    assert!(
        matches!(err, NatError::AllMethodsFailed(_)),
        "the wired Relayed tier is attempted and fails cleanly (no live relay), not composed away \
         (got {err:?})"
    );
    svc.stop().await.expect("stop");
}
