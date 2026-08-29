//! Regression tests for **dig_ecosystem#3124 — a DIRECT inbound peer must enter the connected pool,
//! typed as what it is.**
//!
//! ## The defect
//!
//! Before this change dig-gossip exposed four adoption entry points and not one of them accepted a
//! direct inbound connection: `adopt_nat_connection` and `adopt_discovered_nat_connection` are the
//! dialer's, and `adopt_relayed_inbound{,_handle}` refuse a non-relayed tier outright. A node that
//! ACCEPTED a direct mTLS connection and served the peer perfectly well therefore had nowhere to
//! register it, so `connected_peers` under-reported every inbound peer.
//!
//! ## Why a new entry point rather than reusing one
//!
//! Each available reuse corrupts a DIFFERENT downstream decision, which is why the fixtures below
//! assert three separate fields rather than only the count:
//!
//! * `adopt_relayed_inbound_handle` types the slot [`TraversalKind::Relayed`], and both the peer
//!   record's `via` and the relayed caps derive from that tier — a direct peer typed `Relayed` is
//!   mislabelled to peer selection and charged against the wrong cap.
//! * `adopt_nat_connection` stamps `is_outbound = true`, charging OUTBOUND diversity budgets
//!   (INT-006 /16, INT-007 AS) for a peer this node never dialed.
//! * Either way, the slot's `remote` is the peer's EPHEMERAL SOURCE PORT. Reporting that as
//!   `dial_addr` hands peer selection an address the peer does not answer on.
//!
//! ## Fixture design — a field no fixture VARIES is a field no test covers
//!
//! `dial_addr == None` is satisfied vacuously by "no `dig-nat` peer is ever dialable", so a fixture
//! holding only inbound peers cannot see the difference. Every fixture that asserts a field therefore
//! carries a CONTROL slot with the opposite value: an outbound direct peer (dialable, `is_outbound`)
//! beside the inbound one, and a relayed peer (`Via::Relay`) beside the direct one.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use dig_gossip::{GossipHandle, GossipService, PeerPoolConfig};
use dig_nat::TraversalKind;
use dig_tls::BindingPolicy;

/// Opcode 223 — PROFILE_ROOT_ANNOUNCE, an ordinary broadcast every pool peer should receive.
const PROFILE_ROOT_ANNOUNCE: u8 = 223;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A plausible ephemeral SOURCE address for an accepted TCP connection — a high port the peer does
/// NOT listen on. Nothing may report this as a dial target. IPv6 per §5.2.
fn inbound_source_addr() -> SocketAddr {
    "[2001:db8::5]:54321".parse().expect("inbound source addr")
}

/// An ephemeral inbound SOURCE address in a DISTINCT `/16` group per `n`.
///
/// `subnet_group` keys an IPv6 address on its first FOUR bytes, so varying the second hextet is what
/// puts each peer in a group of its own. Fixtures exercising a POOL-WIDE bound must use this rather
/// than one shared address, or the per-group bound fires first and the pool-wide bound is never the
/// thing under test.
fn inbound_source_in_group(n: u16) -> SocketAddr {
    format!("[2001:{n:x}::5]:54321")
        .parse()
        .expect("inbound source addr in its own /16 group")
}

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("socket addr")
}

fn node_cert(seed: [u8; 32]) -> Arc<dig_tls::NodeCert> {
    let bls_sk = dig_tls::bls::SecretKey::from_seed(&seed);
    Arc::new(dig_tls::NodeCert::generate_signed(&bls_sk).expect("mint a CA-signed NodeCert"))
}

/// A synthetic `dig-nat` connection for the CONTROL slots, which only need to exist with a given tier
/// and a dialable remote — the direct-inbound fixtures under test use a real mTLS handshake instead.
fn loopback_nat_conn(
    peer_id_bytes: [u8; 32],
    remote: SocketAddr,
    method: TraversalKind,
) -> (dig_gossip::NatPeerConnection, dig_nat::PeerSession) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let inner = dig_nat::PeerConnection {
        peer_id: dig_nat::PeerId::from_bytes(peer_id_bytes),
        method,
        remote_addr: remote,
        peer_bls_pub: None,
        session: dig_nat::PeerSession::client(client_io),
    };
    let server = dig_nat::PeerSession::server(server_io);
    (dig_gossip::NatPeerConnection::new(inner), server)
}

/// Run a REAL mTLS handshake over an in-memory duplex and return the RESPONDER's session plus the
/// `peer_id` the initiator's certificate proved — the shape dig-node's inbound peer-RPC listener
/// holds after accepting a direct connection. The initiator's session is returned so a fixture can
/// drive traffic exactly as the peer would.
async fn authenticated_inbound_connection(
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

/// The notice a fixture registers when it expects NO retirement; firing it is a real finding.
fn never_superseded() -> impl FnOnce() + Send + 'static {
    || panic!("the pool retired a slot this fixture does not displace")
}

/// One round trip of the peer's L7 traffic over the RESPONDER's retained session, answering with the
/// request REVERSED so the reply cannot be an echo — only a responder that actually read the bytes
/// can produce it.
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

/// **The whole ticket in one fixture: COUNTED, still SERVED, and REACHED by a broadcast.**
///
/// Each of the three has been a separate shipped defect in this family, and each is invisible to a
/// test asserting only the previous one: adopting by value bought the count and stopped the service,
/// and a slot with no sink was counted and served while receiving nothing. Delivery is asserted as
/// BYTES THE PEER'S OWNER RECEIVED, never as a send-list length.
#[tokio::test]
async fn a_direct_inbound_peer_is_counted_still_served_and_reached_by_a_broadcast() {
    let (svc, handle, _dir) = running_handle().await;
    let (mut responder, peer_id, mut initiator) =
        authenticated_inbound_connection([31; 32], [32; 32]).await;

    let (sink, mut broadcasts) = dig_gossip::NatBroadcastSink::new(8);
    let adopted = handle
        .adopt_direct_inbound_handle(
            peer_id,
            inbound_source_addr(),
            TraversalKind::Direct,
            dig_gossip::ObservedSession::new(responder.closed_handle(), never_superseded()),
            Some(sink),
        )
        .await
        .expect("an authenticated direct inbound connection is adopted");
    assert_eq!(
        adopted, peer_id,
        "the adopted identity is the one the peer's certificate proved"
    );

    // (a) COUNTED — the half that was zero for every inbound peer.
    assert!(
        handle.is_pool_peer(&peer_id),
        "a direct inbound peer is a connected pool member"
    );
    assert_eq!(handle.peer_count().await, 1, "it counts as one connection");

    // (b) STILL SERVED — the pool borrowed a liveness observer, not the session.
    let reply = serve_one_request(&mut responder, &mut initiator, b"dig.getAvailability").await;
    assert_eq!(
        reply,
        b"ytilibaliavAteg.gid".to_vec(),
        "the responder must still be serving the peer it just registered"
    );

    // (c) REACHED — the peer's own owner receives the broadcast bytes.
    let payload = vec![0xC3u8; 64];
    handle
        .broadcast_local(
            dig_gossip::DigMessage::new(PROFILE_ROOT_ANNOUNCE, None, payload.clone().into()),
            None,
        )
        .await
        .expect("broadcast");
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), broadcasts.recv())
        .await
        .expect("the broadcast reaches the peer's sink before the timeout")
        .expect("the sink is still open");
    assert_eq!(
        delivered.data.as_ref(),
        payload.as_slice(),
        "the peer's owner receives the broadcast BYTES, not merely a send-list entry"
    );

    svc.stop().await.expect("stop");
}

/// **The mislabelling the ticket is about, with every asserted field VARYING across the pool.**
///
/// Three peers are held at once, chosen so no assertion can pass vacuously:
///
/// | slot | `via` | `is_outbound` | `dial_addr` |
/// |---|---|---|---|
/// | direct INBOUND (under test) | `Direct` | `false` | `None` |
/// | direct OUTBOUND (control) | `Direct` | `true` | `Some` |
/// | relayed inbound (control) | `Relay` | `false` | `None` |
///
/// Reading down each column shows a distinct pair of values, so `Direct` cannot be a constant, and
/// `dial_addr == None` cannot be "no pool peer is dialable". Reading across the first row is the
/// defect: reusing the relayed entry point moves it to `Relay`, and reusing the dialer's moves
/// `is_outbound` to `true` and `dial_addr` to the ephemeral source port.
#[tokio::test]
async fn a_direct_inbound_peer_is_typed_direct_inbound_and_is_not_dialable() {
    let (svc, handle, _dir) = running_handle().await;

    // Under test: a direct connection this node ACCEPTED.
    let (responder, inbound_id, _initiator) =
        authenticated_inbound_connection([33; 32], [34; 32]).await;
    handle
        .adopt_direct_inbound_handle(
            inbound_id,
            inbound_source_addr(),
            TraversalKind::Direct,
            dig_gossip::ObservedSession::new(responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect("direct inbound adopted");

    // Control: a direct peer this node DIALED — dialable, and outbound.
    let dialed_at = addr("[2001:db8:1::9]:9445");
    let (outbound, _s1) = loopback_nat_conn([35; 32], dialed_at, TraversalKind::Direct);
    let outbound_id = dig_gossip::PeerId::from([35; 32]);
    handle
        .adopt_nat_connection(outbound)
        .await
        .expect("direct outbound adopted");

    // Control: a relayed circuit — the tier the inbound slot must NOT be confused with.
    let (relayed_responder, relayed_id, _r_initiator) =
        authenticated_inbound_connection([36; 32], [37; 32]).await;
    handle
        .adopt_relayed_inbound_handle(
            relayed_id,
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
            dig_gossip::ObservedSession::new(relayed_responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect("relayed inbound adopted");

    let detailed = handle.connected_pool_peers_detailed();
    assert_eq!(detailed.len(), 3, "all three slots are held at once");
    let find = |id: dig_gossip::PeerId| {
        detailed
            .iter()
            .find(|p| p.peer_id == id)
            .unwrap_or_else(|| panic!("{id} is in the pool"))
            .clone()
    };

    let inbound = find(inbound_id);
    let outbound_peer = find(outbound_id);
    let relayed = find(relayed_id);

    // `via` — Direct for the peer under test, and NOT a constant across the pool.
    assert_eq!(
        inbound.via,
        dig_gossip::nat::peer_record::Via::Direct,
        "a direct inbound peer is reached directly; typing it Relayed mislabels its data path"
    );
    assert_eq!(
        relayed.via,
        dig_gossip::nat::peer_record::Via::Relay,
        "control: the relayed slot reports Relay, so Direct above is a measured value"
    );

    // `is_outbound` — false for the peer under test, and NOT a constant across the pool.
    assert!(
        !inbound.is_outbound,
        "this node never dialed the inbound peer, so it charges no outbound diversity budget"
    );
    assert!(
        outbound_peer.is_outbound,
        "control: the dialed peer is outbound, so false above is a measured value"
    );

    // `dial_addr` — None for the peer under test, and NOT a constant across the pool.
    assert_eq!(
        inbound.dial_addr, None,
        "the inbound peer's remote is an ephemeral source port, never a dial target"
    );
    assert_eq!(
        inbound.session_addr,
        inbound_source_addr(),
        "the source address is still reported for observability, just never as dialable"
    );
    assert_eq!(
        outbound_peer.dial_addr,
        Some(dialed_at),
        "control: the dialed peer IS dialable, so None above is not 'no nat peer is dialable'"
    );
    assert_eq!(
        relayed.dial_addr, None,
        "control: a relayed peer is undialable for a different reason — its tier"
    );

    // The same distinction, through the surface peer selection actually reads.
    let dialable = handle.dialable_pool_peers();
    assert_eq!(
        dialable,
        vec![(outbound_id, dialed_at)],
        "only the dialed peer is offered to peer selection"
    );

    svc.stop().await.expect("stop");
}

/// A direct inbound adoption must not be reachable with a RELAYED tier — that is the other entry
/// point's job, and accepting it here would let a caller charge a circuit against the direct tier's
/// accounting, quietly defeating the reserved-quarter cap that bounds relay-chosen peers.
#[tokio::test]
async fn a_relayed_tier_is_refused_by_the_direct_inbound_entry_point() {
    let (svc, handle, _dir) = running_handle().await;
    let (responder, peer_id, _initiator) =
        authenticated_inbound_connection([38; 32], [39; 32]).await;

    let err = handle
        .adopt_direct_inbound_handle(
            peer_id,
            inbound_source_addr(),
            TraversalKind::Relayed,
            dig_gossip::ObservedSession::new(responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect_err("a relayed circuit is not a direct inbound connection");
    assert!(
        matches!(err, dig_gossip::GossipError::ConnectionFiltered(_)),
        "refused as filtered, got {err:?}"
    );
    assert!(
        !handle.is_pool_peer(&peer_id),
        "a refused adoption leaves no slot behind"
    );

    svc.stop().await.expect("stop");
}

/// Inbound peers may not fill the pool. Without a cap, anyone able to complete a handshake could take
/// every slot and leave the maintenance loop no room to dial peers of THIS node's choosing — the
/// eclipse the relayed tier's reserved quarter already guards against, on the path that is far easier
/// to reach because it needs no relay at all.
#[tokio::test]
async fn accepted_direct_inbound_peers_cannot_fill_the_pool() {
    let (svc, handle, _dir) = running_handle().await;
    // max_connections = 8 → inbound budget 6, of which the direct tier may hold 5.
    let cap = 5usize;

    let mut held = Vec::new();
    for i in 0..cap {
        let (responder, peer_id, initiator) =
            authenticated_inbound_connection([40 + i as u8; 32], [80 + i as u8; 32]).await;
        handle
            .adopt_direct_inbound_handle(
                peer_id,
                // A group of its own, so THIS fixture measures the pool-wide cap and the per-group
                // fixture below measures the per-group one. One shared source would conflate them.
                inbound_source_in_group(i as u16 + 1),
                TraversalKind::Direct,
                dig_gossip::ObservedSession::new(responder.closed_handle(), never_superseded()),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("inbound peer {i} is within the cap: {e:?}"));
        held.push((responder, initiator));
    }
    assert_eq!(
        handle.peer_count().await,
        cap,
        "the cap is reached, not the pool"
    );

    let (extra_responder, extra_id, _extra_initiator) =
        authenticated_inbound_connection([70; 32], [71; 32]).await;
    let err = handle
        .adopt_direct_inbound_handle(
            extra_id,
            inbound_source_in_group(90),
            TraversalKind::Direct,
            dig_gossip::ObservedSession::new(extra_responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect_err("the accepted-direct cap refuses the next inbound peer");
    assert!(
        matches!(err, dig_gossip::GossipError::ConnectionFiltered(_)),
        "refused as filtered, got {err:?}"
    );

    // The reserved room is real: a peer THIS node dials is still admitted at the same moment.
    let (dialed, _s) = loopback_nat_conn(
        [72; 32],
        addr("[2001:db8:2::7]:9445"),
        TraversalKind::Direct,
    );
    handle
        .adopt_nat_connection(dialed)
        .await
        .expect("the quarter reserved for outbound dialing is still free");

    svc.stop().await.expect("stop");
}

/// **The two inbound caps must COMPOSE — the regression this fixture exists to hold down.**
///
/// `max_direct_inbound` and `max_relayed_inbound` were each a reserved quarter of `max_connections`
/// and were counted SEPARATELY, so they bounded each tier's size and neither tier's share of the sum:
/// at `max_connections = 8` that is `6 + 2 = 8`, and the eighth adoption failed with
/// `MaxConnectionsReached` having left this node no slot at all to dial with. That is strictly worse
/// than before the direct tier existed, when the relayed cap alone held inbound to 6 of 8.
///
/// The fixture fills BOTH tiers, which is the only arrangement that can see the defect: a fixture
/// holding one tier is bounded by that tier's own cap and passes either way — which is exactly why
/// the suite could not see this.
#[tokio::test]
async fn the_two_inbound_tiers_cannot_pool_their_budgets() {
    let (svc, handle, _dir) = running_handle().await;
    let mut held = Vec::new();

    // Five accepted DIRECT peers — the direct tier at its own cap.
    for i in 0..5usize {
        let (responder, peer_id, initiator) =
            authenticated_inbound_connection([100 + i as u8; 32], [140 + i as u8; 32]).await;
        handle
            .adopt_direct_inbound_handle(
                peer_id,
                inbound_source_in_group(i as u16 + 1),
                TraversalKind::Direct,
                dig_gossip::ObservedSession::new(responder.closed_handle(), never_superseded()),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("direct inbound {i} is within the direct cap: {e:?}"));
        held.push((responder, initiator));
    }

    // One accepted RELAYED circuit — well inside the relayed tier's own cap of 6, and the sixth and
    // last slot of the shared inbound budget.
    let (relay_responder, relay_id, _r) = authenticated_inbound_connection([120; 32], [121; 32]).await;
    handle
        .adopt_relayed_inbound_handle(
            relay_id,
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
            dig_gossip::ObservedSession::new(relay_responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect("the relayed tier is far from its own cap");
    assert_eq!(handle.peer_count().await, 6, "six accepted peers are held");

    // A SEVENTH accepted peer of either tier is refused by the shared budget, and — the whole point —
    // refused as FILTERED rather than by running the pool out of slots.
    let (next_responder, next_id, _n) = authenticated_inbound_connection([122; 32], [123; 32]).await;
    let err = handle
        .adopt_relayed_inbound_handle(
            next_id,
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
            dig_gossip::ObservedSession::new(next_responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect_err("the shared inbound budget refuses a seventh accepted peer");
    assert!(
        matches!(err, dig_gossip::GossipError::ConnectionFiltered(_)),
        "refused by a BUDGET, not by MaxConnectionsReached — got {err:?}"
    );

    // The reserve the caps exist to protect is measurably still there: TWO slots for peers this node
    // chooses. Asserting both is what distinguishes "a bound fired" from "a bound fired in the right
    // place" — one free slot would satisfy a fixture that only dialed once.
    for (i, seed) in [130u8, 131].into_iter().enumerate() {
        let (dialed, _s) = loopback_nat_conn(
            [seed; 32],
            // DISTINCT /16 groups: two dialed peers in one group would be refused by INT-006, and
            // the fixture would read that as "the reserve is not there".
            addr(&format!("[2001:a{}::7]:9445", i + 1)),
            TraversalKind::Direct,
        );
        handle
            .adopt_nat_connection(dialed)
            .await
            .unwrap_or_else(|e| panic!("reserved outbound slot {i} is free: {e:?}"));
    }
    assert_eq!(
        handle.peer_count().await,
        8,
        "the pool is full only once THIS node has used its reserve"
    );

    svc.stop().await.expect("stop");
}

/// **One host must not be able to take the accepted-direct tier by minting identities.**
///
/// Certificates are free here — `dig-nat` mints CA-signed leaves locally — so a pool-wide count alone
/// bounds "how many strangers", never "how many strangers from ONE place". Without a per-source bound
/// a single machine presents one identity per slot and occupies the whole accepted tier, which is the
/// eclipse INT-006 bounds outbound, reachable inbound without dialing anything.
///
/// The control is the load-bearing half: a peer from a DIFFERENT `/16` is admitted at the very moment
/// the crowded group is refused, so the refusal is measurably keyed on the SOURCE GROUP and not on the
/// pool-wide count that the previous fixture already covers.
#[tokio::test]
async fn one_source_group_cannot_take_the_accepted_direct_tier() {
    let (svc, handle, _dir) = running_handle().await;
    // max_direct_inbound(8) == 5 → a quarter, at least two, is 2 per /16.
    let group_cap = 2usize;
    let crowded = 7u16;
    let mut held = Vec::new();

    for i in 0..group_cap {
        let (responder, peer_id, initiator) =
            authenticated_inbound_connection([150 + i as u8; 32], [170 + i as u8; 32]).await;
        handle
            .adopt_direct_inbound_handle(
                peer_id,
                // Same /16 group, DIFFERENT address within it: a bound keyed on the full address
                // rather than on the group would pass this fixture while a /16 flood walked through.
                addr(&format!("[2001:{crowded:x}::{}]:54321", i + 1)),
                TraversalKind::Direct,
                dig_gossip::ObservedSession::new(responder.closed_handle(), never_superseded()),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("peer {i} is within the per-group cap: {e:?}"));
        held.push((responder, initiator));
    }

    let (crowd_responder, crowd_id, _c) = authenticated_inbound_connection([160; 32], [161; 32]).await;
    let err = handle
        .adopt_direct_inbound_handle(
            crowd_id,
            addr(&format!("[2001:{crowded:x}::9]:54321")),
            TraversalKind::Direct,
            dig_gossip::ObservedSession::new(crowd_responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect_err("a third peer from one /16 is refused");
    assert!(
        matches!(err, dig_gossip::GossipError::ConnectionFiltered(_)),
        "refused as filtered, got {err:?}"
    );

    // CONTROL — the pool is nowhere near its pool-wide cap of 5, so a peer from ANOTHER group is
    // admitted at the same moment. Without this the refusal above is indistinguishable from "the pool
    // is full".
    let (other_responder, other_id, _o) = authenticated_inbound_connection([162; 32], [163; 32]).await;
    handle
        .adopt_direct_inbound_handle(
            other_id,
            inbound_source_in_group(crowded + 1),
            TraversalKind::Direct,
            dig_gossip::ObservedSession::new(other_responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect("a peer from a different /16 is admitted while the crowded group is refused");

    svc.stop().await.expect("stop");
}

/// **An accepted connection never displaces a slot this node can DIAL** — the `:2028` branch, which
/// no earlier fixture reached because every one of them used a fresh identity holding no slot at all.
///
/// The control is a peer holding a NON-dialable slot, superseded successfully by the same call in the
/// same fixture. Without it the refusal reads as "a held identity is refused", which is a different
/// and much broader rule — and deleting the branch under test would still leave a green suite.
#[tokio::test]
async fn an_accepted_connection_never_supersedes_a_dialable_slot() {
    let (svc, handle, _dir) = running_handle().await;

    // The peer under test already holds a slot this node DIALED, at an address it answers on.
    let (responder, dialed_id, _i) = authenticated_inbound_connection([180; 32], [181; 32]).await;
    let dialed_at = addr("[2001:db8:3::11]:9445");
    let (outbound, _s) = loopback_nat_conn(dialed_id.to_bytes(), dialed_at, TraversalKind::Direct);
    handle
        .adopt_nat_connection(outbound)
        .await
        .expect("the dialed slot is adopted first");

    let err = handle
        .adopt_direct_inbound_handle(
            dialed_id,
            inbound_source_in_group(1),
            TraversalKind::Direct,
            dig_gossip::ObservedSession::new(responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect_err("an accepted connection does not demote a dialable peer");
    assert!(
        matches!(err, dig_gossip::GossipError::ConnectionFiltered(_)),
        "refused as filtered, got {err:?}"
    );

    // The refusal PRESERVED the dial address — the thing the branch protects. Asserting only the
    // error would pass against a version that refused after already replacing the slot.
    assert!(
        handle
            .connected_pool_peers_detailed()
            .iter()
            .any(|p| p.peer_id == dialed_id && p.dial_addr == Some(dialed_at)),
        "the dialable slot survives the refused adoption, still dialable at the address this node picked"
    );

    // CONTROL — a peer holding a NON-dialable (relayed, accepted) slot IS superseded by the same
    // call, so the refusal above is keyed on DIALABILITY and not on holding a slot.
    let (relay_responder, relay_id, _r) = authenticated_inbound_connection([182; 32], [183; 32]).await;
    handle
        .adopt_relayed_inbound_handle(
            relay_id,
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
            dig_gossip::ObservedSession::new(relay_responder.closed_handle(), || {}),
            None,
        )
        .await
        .expect("relayed inbound adopted");
    let (upgrade_responder, _u_id, _u) = authenticated_inbound_connection([184; 32], [185; 32]).await;
    handle
        .adopt_direct_inbound_handle(
            relay_id,
            inbound_source_in_group(2),
            TraversalKind::Direct,
            dig_gossip::ObservedSession::new(upgrade_responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect("an undialable held slot is superseded, so the refusal above is not 'held'");
    assert_eq!(
        handle
            .connected_pool_peers_detailed()
            .iter()
            .find(|p| p.peer_id == relay_id)
            .map(|p| p.via),
        Some(dig_gossip::nat::peer_record::Via::Direct),
        "the superseded peer is now typed direct"
    );

    svc.stop().await.expect("stop");
}

/// **Holding a slot exempts an adoption only from a budget it ALREADY occupies** — the `:2045` branch.
///
/// Replacing that predicate with a blanket `held.is_some()` is the bypass the sibling relayed path
/// warns about in the same words: any peer admitted by another route could then convert into an
/// accepted direct one for nothing, and the cap becomes a formality. No earlier fixture could tell the
/// two apart, because none ever offered an identity that already held a slot.
///
/// Both directions are asserted in one fixture, because either alone is satisfied by a wrong version:
/// the re-adoption alone passes under a blanket exemption, and the conversion alone passes under no
/// exemption at all.
#[tokio::test]
async fn converting_a_held_slot_is_charged_but_re_adopting_the_same_tier_is_free() {
    let (svc, handle, _dir) = running_handle().await;
    let mut held = Vec::new();

    // One accepted RELAYED circuit, adopted FIRST so it is inside the shared inbound budget.
    let (relay_responder, relay_id, _r) = authenticated_inbound_connection([190; 32], [191; 32]).await;
    handle
        .adopt_relayed_inbound_handle(
            relay_id,
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
            dig_gossip::ObservedSession::new(relay_responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect("relayed inbound adopted");

    // Fill the accepted-DIRECT tier to its cap of 5.
    let mut direct_ids = Vec::new();
    for i in 0..5usize {
        let (responder, peer_id, initiator) =
            authenticated_inbound_connection([200 + i as u8; 32], [210 + i as u8; 32]).await;
        handle
            .adopt_direct_inbound_handle(
                peer_id,
                inbound_source_in_group(i as u16 + 1),
                TraversalKind::Direct,
                dig_gossip::ObservedSession::new(responder.closed_handle(), || {}),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("direct inbound {i} is within the direct cap: {e:?}"));
        direct_ids.push(peer_id);
        held.push((responder, initiator));
    }

    // CHARGED — the relayed peer holds a slot, but NOT one in the direct tier's budget, so converting
    // it is net-new occupancy on a tier that is full. A blanket exemption admits this.
    let (convert_responder, _c_id, _c) = authenticated_inbound_connection([220; 32], [221; 32]).await;
    let err = handle
        .adopt_direct_inbound_handle(
            relay_id,
            inbound_source_in_group(60),
            TraversalKind::Direct,
            dig_gossip::ObservedSession::new(convert_responder.closed_handle(), || {}),
            None,
        )
        .await
        .expect_err("converting a relayed slot into an accepted direct one is charged the direct cap");
    assert!(
        matches!(err, dig_gossip::GossipError::ConnectionFiltered(_)),
        "refused as filtered, got {err:?}"
    );
    assert_eq!(
        handle
            .connected_pool_peers_detailed()
            .iter()
            .find(|p| p.peer_id == relay_id)
            .map(|p| p.via),
        Some(dig_gossip::nat::peer_record::Via::Relay),
        "the refused conversion left the relayed slot exactly as it was"
    );

    // FREE — an identity that ALREADY occupies the direct tier re-adopts at the same full cap, in the
    // same group it already holds. Removing the exemption entirely breaks this.
    let readopted = direct_ids[0];
    let (again_responder, _a_id, _a) = authenticated_inbound_connection([222; 32], [223; 32]).await;
    handle
        .adopt_direct_inbound_handle(
            readopted,
            inbound_source_in_group(1),
            TraversalKind::Direct,
            dig_gossip::ObservedSession::new(again_responder.closed_handle(), || {}),
            None,
        )
        .await
        .expect("re-adopting a peer already in the direct tier is free");
    assert_eq!(
        handle.peer_count().await,
        6,
        "newest-wins replaced the slot rather than adding one"
    );

    svc.stop().await.expect("stop");
}

/// **An accepted direct peer must be CYCLABLE — the admission ledger, not the announcement.**
///
/// `PeerPool::publish(PeerAdded)` is the only production path that creates a peer's activity record
/// (`record_admission`); `begin_activity` refuses to create one and `activity_of` silently drops a
/// recordless peer. A slot admitted without it counts toward `connected` and appears in `cyclable`
/// while being structurally incapable of being displaced — so every eviction lands on a peer this node
/// chose, and the only un-cyclable slots in the pool are the ones a stranger opened.
///
/// The record is observed through `tracked_peer_count`, with a peer admitted by a SIBLING path held
/// beside it so the count cannot pass by being "all peers" or "none".
#[tokio::test]
async fn an_accepted_direct_peer_is_recorded_as_admitted_and_can_be_displaced() {
    let (svc, handle, _dir) = running_handle().await;
    assert_eq!(
        handle.__tracked_pool_activity_count_for_tests(),
        0,
        "control: no peer is tracked before any adoption, so a later 1 is a measured change"
    );

    let (responder, peer_id, _i) = authenticated_inbound_connection([230; 32], [231; 32]).await;
    handle
        .adopt_direct_inbound_handle(
            peer_id,
            inbound_source_in_group(1),
            TraversalKind::Direct,
            dig_gossip::ObservedSession::new(responder.closed_handle(), never_superseded()),
            None,
        )
        .await
        .expect("direct inbound adopted");
    assert_eq!(
        handle.__tracked_pool_activity_count_for_tests(),
        1,
        "the accepted peer holds an activity record, so displacement can see it at all"
    );

    // The record is what makes the peer BUSYABLE, and therefore weighable against other candidates:
    // `begin_activity` returns false for a peer with no record, which is the observable form of "this
    // slot can never be the victim".
    assert!(
        handle.__begin_pool_activity_for_tests(peer_id, 1_700_000_000),
        "work over an accepted peer is stamped; a recordless slot would silently refuse and sort as \
         permanently un-displaceable"
    );

    svc.stop().await.expect("stop");
}
