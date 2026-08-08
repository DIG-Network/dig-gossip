//! Regression tests for **dig_ecosystem#870 / #1871 — the RESPONDER half of a relayed circuit must
//! join the connected-peer pool, and must never be offered as a dial target.**
//!
//! ## The defect
//!
//! `adopt_nat_connection` is the only path into the pool, and it is the DIALER's path: it stamps
//! `is_outbound = true` and charges the outbound diversity budgets. The reservation-HOLDER — the node
//! that ACCEPTS an introduced relay circuit via `dig_nat::RelayAcceptor` — had no path at all, so a
//! node actively serving a peer over a relayed circuit reported `connected_peers = 0`. Every
//! subsystem that answers "am I connected" from the pool (health, metrics, peer selection) therefore
//! saw an isolated node while bytes were flowing.
//!
//! ## The fix under test
//!
//! [`GossipHandle::adopt_relayed_inbound`] registers the authenticated responder side as a
//! relay-typed, INBOUND, **non-dialable** pool member: it counts as connected everywhere the pool is
//! read, and [`GossipHandle::dialable_pool_peers`] structurally cannot return it (its
//! `ConnectedPoolPeer::dial_addr` is `None` — the relay endpoint is not an address at which the peer
//! can be reached).
//!
//! ## What these tests exercise, and what they do not
//!
//! Test 1 runs a **real dig-tls mTLS handshake** — the same `server_config_spki_pinned` /
//! `client_config_spki_pinned` pair `dig_nat::RelayAcceptor` and `MtlsDialer` use — over an in-memory
//! duplex, so the adopted `peer_id` is the one a REAL certificate produced rather than a literal
//! stamped into a mock. What it does NOT prove is the circuit itself: a `RelayTunnel` is only
//! constructible by `dig-nat` from a live reservation, so a genuine two-node-through-a-relay proof
//! needs a running relay and belongs to the #1871 multi-node e2e, not to this crate's harness.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use dig_gossip::{GossipError, GossipHandle, GossipService, NatPeerConnection, PeerPoolConfig};
use dig_nat::TraversalKind;
use dig_tls::BindingPolicy;

/// The unspecified IPv6 address `dig_nat::RelayAcceptor` records as the remote of an accepted relayed
/// circuit when no relay endpoint is known — the byte path is the tunnel, not an address anyone
/// dialed. IPv6 per §5.2.
fn accepted_relayed_remote() -> SocketAddr {
    SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
}

/// Mint a CA-signed dig-tls `NodeCert` from a deterministic BLS seed — the identity a node presents
/// on every transport.
fn node_cert(seed: [u8; 32]) -> Arc<dig_tls::NodeCert> {
    let bls_sk = dig_tls::bls::SecretKey::from_seed(&seed);
    Arc::new(dig_tls::NodeCert::generate_signed(&bls_sk).expect("mint a CA-signed NodeCert"))
}

/// Run a REAL mTLS handshake over an in-memory duplex and return the SERVER-side connection, typed
/// `Relayed` exactly as `dig_nat::RelayAcceptor::accept` types the circuits it authenticates.
///
/// The client half is returned so the caller keeps it alive (dropping it closes the session, which
/// the departed-peer reaper would then evict). `responder`/`initiator` are BLS seeds, so the adopted
/// `peer_id` is derived from the initiator's real certificate SPKI.
async fn authenticated_relayed_inbound(
    responder: [u8; 32],
    initiator: [u8; 32],
) -> (NatPeerConnection, dig_nat::PeerSession) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_node = node_cert(responder);
    let client_node = node_cert(initiator);

    let server = async move {
        let tls = dig_tls::server_config_spki_pinned(&server_node, BindingPolicy::Opportunistic)
            .expect("server tls config");
        let captured = tls.captured_peer_id.clone();
        let captured_bls = tls.captured_bls.clone();
        let stream = tokio_rustls::TlsAcceptor::from(tls.config)
            .accept(server_io)
            .await
            .expect("mtls accept");
        dig_nat::PeerConnection {
            peer_id: captured.get().expect("client presented a certificate"),
            method: TraversalKind::Relayed,
            remote_addr: accepted_relayed_remote(),
            peer_bls_pub: captured_bls.get(),
            session: dig_nat::PeerSession::server(stream),
        }
    };

    let client = async move {
        let tls =
            dig_tls::client_config_spki_pinned(&client_node, None, BindingPolicy::Opportunistic)
                .expect("client tls config");
        let name = rustls_pki_types::ServerName::try_from("peer.dig.invalid").expect("server name");
        let stream = tokio_rustls::TlsConnector::from(tls.config)
            .connect(name, client_io)
            .await
            .expect("mtls connect");
        dig_nat::PeerSession::client(stream)
    };

    let (server_conn, client_session) = tokio::join!(server, client);
    (NatPeerConnection::new(server_conn), client_session)
}

/// A cheap, non-authenticated connection over a loopback duplex — used only where the test is about
/// ADMISSION ARITHMETIC (caps, budgets) rather than about identity.
fn loopback_nat_conn(
    peer_id_bytes: [u8; 32],
    remote: SocketAddr,
    method: TraversalKind,
) -> (NatPeerConnection, dig_nat::PeerSession) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let inner = dig_nat::PeerConnection {
        peer_id: dig_nat::PeerId::from_bytes(peer_id_bytes),
        method,
        remote_addr: remote,
        peer_bls_pub: None,
        session: dig_nat::PeerSession::client(client_io),
    };
    (
        NatPeerConnection::new(inner),
        dig_nat::PeerSession::server(server_io),
    )
}

async fn running_handle() -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 8; // → max_relayed_inbound = 6
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

/// **The defect + the crux, in one fixture.** An authenticated relayed circuit this node ACCEPTED
/// counts as connected, and is never returned as a dial candidate — while a directly-reached peer
/// adopted alongside it IS returned. The direct peer is the truthful control: it fails if
/// `dialable_pool_peers` were merely returning nothing, which is what an "assert the result is empty"
/// test on its own would happily accept.
#[tokio::test]
async fn accepted_relayed_circuit_is_connected_but_never_a_dial_candidate() {
    let (svc, handle, _dir) = running_handle().await;

    let (relayed, client_session) = authenticated_relayed_inbound([9; 32], [11; 32]).await;
    let relayed_peer_id = relayed.peer_id();

    let (direct, s2) =
        loopback_nat_conn([2; 32], addr("[2001:db8::5]:9445"), TraversalKind::Direct);
    let direct_peer_id = direct.peer_id();
    handle.adopt_nat_connection(direct).await.expect("direct");

    let adopted = handle
        .adopt_relayed_inbound(relayed)
        .await
        .expect("an authenticated relayed circuit is adopted");
    assert_eq!(
        adopted, relayed_peer_id,
        "the adopted identity is the one the peer's certificate proved"
    );

    // (a) It is CONNECTED — the defect was that it was not.
    assert!(
        handle.is_pool_peer(&relayed_peer_id),
        "the responder half of a relayed circuit is a pool member"
    );
    assert_eq!(
        handle.pool_stats().connected,
        2,
        "both the direct peer and the accepted relayed peer are connected"
    );

    // (b) It is relay-typed and INBOUND.
    let detailed = handle.connected_pool_peers_detailed();
    let relayed_view = detailed
        .iter()
        .find(|p| p.peer_id == relayed_peer_id)
        .expect("the relayed peer is in the detailed pool view");
    assert_eq!(relayed_view.via, dig_gossip::Via::Relay);
    assert!(
        !relayed_view.is_outbound,
        "the responder did not initiate the circuit"
    );

    // (c) It is NON-DIALABLE, structurally — and the direct control still is dialable.
    assert!(
        relayed_view.dial_addr.is_none(),
        "a relayed peer has no address at which it can be reached"
    );
    let dialable: Vec<_> = handle
        .dialable_pool_peers()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(
        !dialable.contains(&relayed_peer_id),
        "a relayed peer must never be offered as a dial target"
    );
    assert!(
        dialable.contains(&direct_peer_id),
        "the direct peer IS a dial target — so the assertion above is not passing vacuously"
    );

    let _ = (client_session, s2);
    svc.stop().await.expect("stop");
}

/// **A relayed OUTBOUND peer is equally non-dialable.** The property belongs to the relayed TIER, not
/// to the direction: the recorded remote is the relay endpoint either way. Keying non-dialability on
/// direction instead of on the tier would leave the dialer's own relayed peers being re-dialed at the
/// relay's address.
#[tokio::test]
async fn a_relayed_outbound_peer_is_also_never_a_dial_candidate() {
    let (svc, handle, _dir) = running_handle().await;

    let (relayed, s1) =
        loopback_nat_conn([3; 32], addr("[2001:db8::9]:9450"), TraversalKind::Relayed);
    let relayed_peer_id = relayed.peer_id();
    handle
        .adopt_nat_connection(relayed)
        .await
        .expect("relayed outbound adopted");

    let (direct, s2) =
        loopback_nat_conn([4; 32], addr("[2001:db8::11]:9445"), TraversalKind::Direct);
    let direct_peer_id = direct.peer_id();
    handle.adopt_nat_connection(direct).await.expect("direct");

    let dialable: Vec<_> = handle
        .dialable_pool_peers()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(!dialable.contains(&relayed_peer_id));
    assert!(dialable.contains(&direct_peer_id), "control");

    let _ = (s1, s2);
    svc.stop().await.expect("stop");
}

/// **The inbound path accepts only the relayed tier.** A direct connection carries a routable peer
/// address and must go through `adopt_nat_connection`; letting it in here would register a dialable
/// peer as permanently non-dialable.
#[tokio::test]
async fn a_non_relayed_connection_is_refused_by_the_relayed_inbound_path() {
    let (svc, handle, _dir) = running_handle().await;

    let (direct, s1) =
        loopback_nat_conn([5; 32], addr("[2001:db8::7]:9445"), TraversalKind::Direct);
    let peer_id = direct.peer_id();
    let err = handle
        .adopt_relayed_inbound(direct)
        .await
        .expect_err("a direct connection is not a relayed circuit");
    assert!(matches!(err, GossipError::ConnectionFiltered(_)), "{err:?}");
    assert!(
        !handle.is_pool_peer(&peer_id),
        "the refused connection did not enter the pool"
    );

    let _ = s1;
    svc.stop().await.expect("stop");
}

/// **An accepted relayed circuit does not consume the outbound budget.** The responder dialed
/// nothing, so its slot must not count against `max_relayed_outbound` (6 at `target_outbound_count =
/// 8`) — otherwise a busy relay-serving node would be unable to dial out over the relay at all.
#[tokio::test]
async fn accepted_relayed_circuits_do_not_consume_the_relayed_outbound_cap() {
    let (svc, handle, _dir) = running_handle().await;

    let mut keep_alive = Vec::new();
    for i in 0..6u8 {
        let (conn, s) = loopback_nat_conn(
            [100 + i; 32],
            accepted_relayed_remote(),
            TraversalKind::Relayed,
        );
        handle
            .adopt_relayed_inbound(conn)
            .await
            .expect("inbound relayed circuit adopted");
        keep_alive.push(s);
    }

    let (outbound, s) = loopback_nat_conn(
        [200; 32],
        addr("[2001:db8::1]:9450"),
        TraversalKind::Relayed,
    );
    handle
        .adopt_nat_connection(outbound)
        .await
        .expect("the outbound relayed budget is untouched by six accepted circuits");
    keep_alive.push(s);

    svc.stop().await.expect("stop");
    drop(keep_alive);
}

/// **The accepted-relayed bound, from BOTH sides.** `max_relayed_inbound(8) == 6`: the sixth circuit
/// is admitted and the seventh is refused, so a relay cannot fill this node's whole pool with
/// circuits it introduced. Asserted at the bound and one over — a bound tested only from below
/// confirms nothing about where it is.
#[tokio::test]
async fn accepted_relayed_circuits_are_bounded_and_the_bound_is_where_it_says() {
    let (svc, handle, _dir) = running_handle().await; // max_connections = 8 → cap 6

    let mut keep_alive = Vec::new();
    for i in 0..6u8 {
        let (conn, s) = loopback_nat_conn(
            [50 + i; 32],
            accepted_relayed_remote(),
            TraversalKind::Relayed,
        );
        handle
            .adopt_relayed_inbound(conn)
            .await
            .unwrap_or_else(|e| panic!("circuit {i} is at or under the cap of 6: {e:?}"));
        keep_alive.push(s);
    }

    let (over, s) = loopback_nat_conn([250; 32], accepted_relayed_remote(), TraversalKind::Relayed);
    let err = handle
        .adopt_relayed_inbound(over)
        .await
        .expect_err("the seventh accepted circuit exceeds the cap");
    assert!(matches!(err, GossipError::ConnectionFiltered(_)), "{err:?}");
    keep_alive.push(s);

    // The reserved remainder is still open to a non-relayed peer.
    let (direct, s2) = loopback_nat_conn(
        [251; 32],
        addr("[2001:db8::20]:9445"),
        TraversalKind::Direct,
    );
    handle
        .adopt_nat_connection(direct)
        .await
        .expect("the cap reserves room for the non-relayed tier");
    keep_alive.push(s2);

    svc.stop().await.expect("stop");
    drop(keep_alive);
}
