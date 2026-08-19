//! Regression tests for **dig_ecosystem#1871 — a relayed inbound peer must be COUNTED without the
//! pool taking the session the caller is still SERVING it on.**
//!
//! ## The defect
//!
//! [`GossipHandle::adopt_relayed_inbound`] takes the `NatPeerConnection` **by value** into the pool
//! slot. `dig_nat::PeerSession` is not `Clone` (it owns the inbound-stream receiver) and there is no
//! split or lend-back API, so the node's relayed serve loop — which needs `&mut PeerSession` to answer
//! the peer's L7 RPC — cannot call it without giving the session up. Calling it as-is would buy the
//! connection count and silently stop serving the peer; so dig-node never called it, and a NAT'd peer
//! (most people) formed ZERO counted connections while being served perfectly well.
//!
//! ## The fix under test
//!
//! [`GossipHandle::adopt_relayed_inbound_handle`] takes `(peer_id, remote, ClosedHandle)`. The slot
//! only ever asked the transport whether the peer was still up (the #1703 departed-peer reaper), which
//! is exactly what a `ClosedHandle` answers — and it is `Clone`, so ownership stays with the caller.
//!
//! ## Why each fixture is shaped the way it is
//!
//! A test that only asserted "the peer is counted" would pass against the very implementation this
//! change replaces — the defect being fixed is *counted but no longer served*. So every fixture here
//! drives REAL bytes over the retained session AFTER adoption. The second fixture goes further and
//! removes the pool slot before serving, because the pool taking ownership is not observable while the
//! slot is alive: with the by-value shape, dropping the slot tears the mux down (#1717), so a serve
//! that still succeeds after the slot is gone is the discriminator between the two shapes at RUNTIME
//! rather than merely at compile time.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use dig_gossip::{GossipHandle, GossipService, PeerPoolConfig};
use dig_nat::TraversalKind;
use dig_tls::BindingPolicy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The unspecified IPv6 address `dig_nat::RelayAcceptor` records as the remote of an accepted circuit
/// — the byte path is the tunnel, not an address anyone dialed. IPv6 per §5.2.
fn accepted_relayed_remote() -> SocketAddr {
    SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
}

fn node_cert(seed: [u8; 32]) -> Arc<dig_tls::NodeCert> {
    let bls_sk = dig_tls::bls::SecretKey::from_seed(&seed);
    Arc::new(dig_tls::NodeCert::generate_signed(&bls_sk).expect("mint a CA-signed NodeCert"))
}

/// Run a REAL mTLS handshake over an in-memory duplex and return the RESPONDER's session plus the
/// `peer_id` its certificate proved — the shape `dig_nat::RelayAcceptor::accept` hands a reservation
/// holder. The initiator's session is returned so the test can drive traffic as the peer would.
async fn authenticated_relayed_circuit(
    responder: [u8; 32],
    initiator: [u8; 32],
) -> (
    dig_nat::PeerSession,
    dig_gossip::PeerId,
    dig_nat::PeerSession,
) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_node = node_cert(responder);
    let client_node = node_cert(initiator);

    let server = async move {
        let tls = dig_tls::server_config_spki_pinned(&server_node, BindingPolicy::Opportunistic)
            .expect("server tls config");
        let captured = tls.captured_peer_id.clone();
        let stream = tokio_rustls::TlsAcceptor::from(tls.config)
            .accept(server_io)
            .await
            .expect("mtls accept");
        let nat_peer_id = captured.get().expect("client presented a certificate");
        // The pool keys peers by the gossip `PeerId` (chia `Bytes32`); dig-nat's is the same 32 bytes
        // under a different type — the conversion dig-node makes at the same seam.
        (
            dig_nat::PeerSession::server(stream),
            dig_gossip::PeerId::from(*nat_peer_id.as_bytes()),
        )
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

    let ((responder_session, peer_id), initiator_session) = tokio::join!(server, client);
    (responder_session, peer_id, initiator_session)
}

async fn running_handle() -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 8;
    cfg.target_outbound_count = 8;
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

/// One round trip of the peer's L7 traffic over the RESPONDER's retained session: the initiator opens
/// a stream and sends a request, the responder accepts it and answers. Returns the bytes the initiator
/// got back, so a caller asserts on an answer that could only have come from a session still being
/// served.
async fn serve_one_request(
    responder: &mut dig_nat::PeerSession,
    initiator: &mut dig_nat::PeerSession,
    request: &[u8],
) -> Vec<u8> {
    let mut client_stream = initiator.open_stream().await.expect("peer opens a stream");
    client_stream.write_all(request).await.expect("peer writes");
    client_stream.flush().await.expect("peer flushes");

    let mut server_stream =
        tokio::time::timeout(std::time::Duration::from_secs(5), responder.accept_stream())
            .await
            .expect("the responder accepts the peer's stream before the timeout")
            .expect("the peer's stream arrives");

    let mut got = vec![0u8; request.len()];
    server_stream
        .read_exact(&mut got)
        .await
        .expect("the responder reads the peer's request");
    // Answer with the request reversed, so the reply cannot be confused with an echo of what the
    // initiator already holds — only a responder that actually READ the bytes can produce it.
    let mut answer: Vec<u8> = got.clone();
    answer.reverse();
    server_stream
        .write_all(&answer)
        .await
        .expect("the responder answers");
    server_stream.flush().await.expect("the responder flushes");

    let mut reply = vec![0u8; answer.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_stream.read_exact(&mut reply),
    )
    .await
    .expect("the peer's reply arrives before the timeout")
    .expect("the peer reads the reply");
    reply
}

/// **The whole point of #1871, in one fixture: COUNTED and STILL SERVED.**
///
/// Adopting by handle registers the peer in the connected pool, and the responder — which still owns
/// the session — goes on answering its L7 requests afterwards. Asserting only the count would pass
/// against the by-value path this replaces, which is precisely the bug (counted, no longer served).
#[tokio::test]
async fn a_relayed_peer_adopted_by_handle_is_counted_and_still_served() {
    let (svc, handle, _dir) = running_handle().await;
    let (mut responder, peer_id, mut initiator) =
        authenticated_relayed_circuit([21; 32], [22; 32]).await;

    let adopted = handle
        .adopt_relayed_inbound_handle(
            peer_id,
            accepted_relayed_remote(),
            responder.closed_handle(),
            None,
        )
        .await
        .expect("an authenticated relayed circuit is adopted by handle");
    assert_eq!(
        adopted, peer_id,
        "the adopted identity is the one the peer's certificate proved"
    );

    // (a) COUNTED — the half that was zero for every NAT'd peer.
    assert!(
        handle.is_pool_peer(&peer_id),
        "a relayed peer adopted by handle is a connected pool member"
    );
    assert_eq!(handle.peer_count().await, 1, "it counts as one connection");

    // (b) STILL SERVED — the half a count-only test cannot see. The responder never gave the session
    // up, so it answers the peer exactly as before the adoption.
    let reply = serve_one_request(&mut responder, &mut initiator, b"dig.getAvailability").await;
    assert_eq!(
        reply,
        b"ytilibaliavAteg.gid".to_vec(),
        "the responder must still be serving the peer it just registered"
    );

    svc.stop().await.expect("stop");
}

/// **The ownership discriminator.** Removing the peer from the POOL must not hang up on it: the pool
/// borrowed a liveness observer, not the transport. With the by-value shape the slot owns the mux and
/// dropping it tears the session down (#1717), so this serve would fail — which is what makes this
/// fixture sensitive to WHERE ownership sits rather than merely to the peer being counted.
#[tokio::test]
async fn removing_the_pool_slot_does_not_hang_up_on_a_peer_the_caller_is_serving() {
    let (svc, handle, _dir) = running_handle().await;
    let (mut responder, peer_id, mut initiator) =
        authenticated_relayed_circuit([23; 32], [24; 32]).await;

    handle
        .adopt_relayed_inbound_handle(
            peer_id,
            accepted_relayed_remote(),
            responder.closed_handle(),
            None,
        )
        .await
        .expect("adopted by handle");
    handle.disconnect(&peer_id).await.expect("leave the pool");
    assert!(
        !handle.is_pool_peer(&peer_id),
        "the slot is gone from the pool",
    );

    let reply = serve_one_request(&mut responder, &mut initiator, b"still here").await;
    assert_eq!(
        reply,
        b"ereh llits".to_vec(),
        "dropping the pool slot must not close a transport the pool never owned"
    );

    svc.stop().await.expect("stop");
}

/// **The handle must observe the REAL session.** A slot whose liveness signal is a dummy would either
/// reap a live peer immediately or never notice a departed one, and the pool count would drift from
/// reality in one direction or the other. Both directions are pinned here, in order: a live peer
/// survives a reaper sweep, and the SAME peer is reaped once its transport actually ends.
#[tokio::test]
async fn the_liveness_handle_keeps_a_live_peer_and_reaps_a_departed_one() {
    let (svc, handle, _dir) = running_handle().await;
    let (responder, peer_id, initiator) = authenticated_relayed_circuit([25; 32], [26; 32]).await;

    handle
        .adopt_relayed_inbound_handle(
            peer_id,
            accepted_relayed_remote(),
            responder.closed_handle(),
            None,
        )
        .await
        .expect("adopted by handle");

    assert_eq!(
        handle.__reap_departed_peers_for_tests(),
        0,
        "a live peer must survive a reaper sweep"
    );
    assert!(handle.is_pool_peer(&peer_id), "and stay in the pool");

    // The peer departs: both ends of the circuit go away, so the responder's mux driver ends.
    drop(initiator);
    drop(responder);
    let mut reaped = 0;
    for _ in 0..50 {
        reaped = handle.__reap_departed_peers_for_tests();
        if reaped > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(
        reaped, 1,
        "a departed peer must be reaped through the handle"
    );
    assert!(
        !handle.is_pool_peer(&peer_id),
        "and must no longer be counted"
    );

    svc.stop().await.expect("stop");
}

/// The relayed-only guard survives the new entry point: `adopt_relayed_inbound_handle` types the tier
/// as `Relayed` itself, and the by-value entry point still refuses a non-relayed connection — the
/// control proving both entry points share ONE admission rather than the handle path forking a second,
/// laxer one.
#[tokio::test]
async fn both_entry_points_share_one_admission_path() {
    let (svc, handle, _dir) = running_handle().await;

    // The handle path admits (Relayed by construction) ...
    let (responder, peer_id, _initiator) = authenticated_relayed_circuit([27; 32], [28; 32]).await;
    handle
        .adopt_relayed_inbound_handle(
            peer_id,
            accepted_relayed_remote(),
            responder.closed_handle(),
            None,
        )
        .await
        .expect("relayed circuit admitted");

    // ... and the by-value path still refuses a non-relayed connection, unchanged by the split.
    let (client_io, _server_io) = tokio::io::duplex(64 * 1024);
    let direct = dig_gossip::NatPeerConnection::new(dig_nat::PeerConnection {
        peer_id: dig_nat::PeerId::from_bytes([31; 32]),
        method: TraversalKind::Direct,
        remote_addr: "[2001:db8::7]:9444".parse().unwrap(),
        peer_bls_pub: None,
        session: dig_nat::PeerSession::client(client_io),
    });
    let err = handle
        .adopt_relayed_inbound(direct)
        .await
        .expect_err("a direct connection is not a relayed circuit");
    assert!(
        format!("{err}").contains("not a relayed circuit"),
        "unexpected error: {err}"
    );

    svc.stop().await.expect("stop");
}
