//! Regression tests for **dig-gossip#71 — a superseded by-handle slot must not leave its session
//! ownerless and un-notified.**
//!
//! ## The defect
//!
//! `adopt_relayed_inbound_handle` (#1871) registers a relayed peer by liveness observer, so the CALLER
//! keeps and serves the session. Newest-wins supersede then had an asymmetry: dropping a displaced
//! `Owned` slot closes its mux (#1717), while dropping a displaced `Observed` slot closes NOTHING. The
//! displaced session kept running — still served by the caller, no longer counted by the pool — and no
//! signal reached its owner. PR #70 documented that as a caller MUST, which nothing enforced and
//! nothing could detect.
//!
//! ## The fix under test
//!
//! An observed session is registered as an [`ObservedSession`]: the liveness observer AND the notice
//! that reaches the session's owner, which cannot be registered apart. When the pool RETIRES the slot
//! — superseded by a newer session for the same identity, or displaced to admit a discovered holder —
//! it fires that notice.
//!
//! ## Why each fixture is shaped the way it is
//!
//! "The notice fired" on its own is satisfied by an implementation that fires on ANY slot removal, or
//! on every adoption, or that fires the wrong session's notice. So the fixtures vary ONE actor and
//! keep truthful controls: two sessions for the SAME identity (only the displaced one's notice may
//! fire), a second identity adopted alongside (its notice must stay silent), and a `disconnect` —
//! which RELINQUISHES rather than retires, and whose silence is #1871's tested contract.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dig_gossip::{GossipHandle, GossipService, ObservedSession, PeerPoolConfig};
use dig_tls::BindingPolicy;

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
/// `peer_id` its certificate proved.
///
/// The initiator is passed as an already-minted [`dig_tls::NodeCert`] rather than a seed, because
/// `peer_id = SHA-256(TLS SPKI DER)` and `NodeCert::generate_signed` mints a FRESH TLS keypair every
/// call — two certs from the same BLS seed prove two DIFFERENT identities. Reusing one cert across two
/// handshakes is therefore the only way to produce two distinct sessions for one identity, which is
/// exactly the reconnect the supersede path exists for.
///
/// The initiator side is returned so the caller can hold it: dropping it would close the circuit and
/// make the responder's liveness observer report a departed peer, which these fixtures must not
/// confuse with a retirement.
async fn authenticated_relayed_circuit(
    responder: [u8; 32],
    initiator: &Arc<dig_tls::NodeCert>,
) -> (
    dig_nat::PeerSession,
    dig_gossip::PeerId,
    dig_nat::PeerSession,
) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_node = node_cert(responder);
    let client_node = Arc::clone(initiator);

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

/// A counter a fixture registers as the session's owner, so "the owner was told" is observable.
#[derive(Clone, Default)]
struct NoticeCounter(Arc<AtomicUsize>);

impl NoticeCounter {
    fn fires(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    /// Build the notice this owner registers with its session.
    fn notice(&self) -> impl FnOnce() + Send + 'static {
        let seen = Arc::clone(&self.0);
        move || {
            seen.fetch_add(1, Ordering::SeqCst);
        }
    }
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

/// **#71, the whole point:** the session a supersede DISPLACES gets its owner told — and it is the
/// only notice that fires.
///
/// The second adoption is a genuine second mTLS session for the SAME certificate, which is the
/// reconnect shape the newest-wins rule exists for. Two live notices are registered so an
/// implementation that fires "the notice of whatever was just adopted", or fires every notice it can
/// reach, is distinguishable from one that fires the DISPLACED session's notice.
#[tokio::test]
async fn superseding_an_observed_session_tells_that_session_owner_and_no_other() {
    let (svc, handle, _dir) = running_handle().await;
    // ONE certificate, TWO handshakes: same proven identity, two live sessions.
    let peer_cert = node_cert([32; 32]);
    let (first_session, peer_id, _first_peer) =
        authenticated_relayed_circuit([31; 32], &peer_cert).await;
    let (second_session, same_peer_id, _second_peer) =
        authenticated_relayed_circuit([33; 32], &peer_cert).await;
    assert_eq!(
        peer_id, same_peer_id,
        "both circuits must prove the SAME identity, or this is not a supersede at all"
    );

    let displaced = NoticeCounter::default();
    let successor = NoticeCounter::default();

    handle
        .adopt_relayed_inbound_handle(
            peer_id,
            accepted_relayed_remote(),
            ObservedSession::new(first_session.closed_handle(), displaced.notice()),
            None,
        )
        .await
        .expect("the first circuit is adopted");
    assert_eq!(displaced.fires(), 0, "adopting a session must not retire it");

    handle
        .adopt_relayed_inbound_handle(
            peer_id,
            accepted_relayed_remote(),
            ObservedSession::new(second_session.closed_handle(), successor.notice()),
            None,
        )
        .await
        .expect("a newer circuit for the same identity supersedes the first");

    assert_eq!(
        displaced.fires(),
        1,
        "the DISPLACED session's owner must be told exactly once, or it serves a peer nobody counts"
    );
    assert_eq!(
        successor.fires(),
        0,
        "the session that WON the slot is live — telling its owner would close the peer's only link"
    );
    assert_eq!(
        handle.peer_count().await,
        1,
        "supersede replaces the slot rather than growing the map"
    );

    svc.stop().await.expect("stop");
}

/// **The identity control.** Adopting a DIFFERENT peer displaces nothing, so no notice fires. Without
/// this, an implementation that retired some arbitrary observed slot on every adoption would pass the
/// fixture above.
#[tokio::test]
async fn adopting_a_different_peer_retires_nobody() {
    let (svc, handle, _dir) = running_handle().await;
    let (held_session, held_id, _held_peer) = authenticated_relayed_circuit([34; 32], &node_cert([35; 32])).await;
    let (other_session, other_id, _other_peer) =
        authenticated_relayed_circuit([36; 32], &node_cert([37; 32])).await;
    assert_ne!(held_id, other_id, "the fixture needs two distinct peers");

    let held = NoticeCounter::default();
    let other = NoticeCounter::default();

    handle
        .adopt_relayed_inbound_handle(
            held_id,
            accepted_relayed_remote(),
            ObservedSession::new(held_session.closed_handle(), held.notice()),
            None,
        )
        .await
        .expect("the held peer is adopted");
    handle
        .adopt_relayed_inbound_handle(
            other_id,
            accepted_relayed_remote(),
            ObservedSession::new(other_session.closed_handle(), other.notice()),
            None,
        )
        .await
        .expect("a second, different peer is adopted");

    assert_eq!(
        held.fires(),
        0,
        "a peer that kept its slot must not be told its session was retired"
    );
    assert_eq!(other.fires(), 0, "nor may the newcomer");
    assert_eq!(handle.peer_count().await, 2, "two distinct peers, two slots");

    svc.stop().await.expect("stop");
}

/// **Retire is not relinquish (#1871's contract, kept).** `disconnect` stops ACCOUNTING for a peer; the
/// caller may still be mid-conversation on the session, so the pool must not tell its owner the
/// session is obsolete. This control is what stops the fix degenerating into "fire on any removal",
/// which would hang up on a peer the node is actively serving — the defect #1871 was opened to remove.
#[tokio::test]
async fn disconnect_relinquishes_the_slot_without_retiring_the_session() {
    let (svc, handle, _dir) = running_handle().await;
    let (session, peer_id, _peer) = authenticated_relayed_circuit([38; 32], &node_cert([39; 32])).await;
    let owner = NoticeCounter::default();

    handle
        .adopt_relayed_inbound_handle(
            peer_id,
            accepted_relayed_remote(),
            ObservedSession::new(session.closed_handle(), owner.notice()),
            None,
        )
        .await
        .expect("adopted by handle");
    handle.disconnect(&peer_id).await.expect("leave the pool");

    assert!(
        !handle.is_pool_peer(&peer_id),
        "the slot is gone from the pool"
    );
    assert_eq!(
        owner.fires(),
        0,
        "leaving the pool is not the session ending — the caller may still be serving this peer"
    );

    svc.stop().await.expect("stop");
}
