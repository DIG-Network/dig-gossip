//! Regression test for **dig_ecosystem#3063 — the broadcast return value counted peers that were
//! sent nothing.**
//!
//! ## The defect
//!
//! `broadcast` returned `stub + eager + lazy_pids.len()` while the send loop covered stub + eager
//! only, and skipped [`PeerSlot::Nat`] peers entirely (#3062). A node with one NAT-adopted peer
//! therefore logged `announced_to_peers: 1` while that peer received nothing — the inflated count is
//! what made the two real defects invisible during live testing.
//!
//! ## What is under test
//!
//! The value `broadcast` / `broadcast_local` returns is a DELIVERY count: it counts a peer only when
//! this call actually put the frame on that peer's transport. A peer this crate cannot reach — a NAT
//! peer, whose gossip message loop over the `dig-nat` mux is not wired here — is excluded, so the
//! caller's log tells the truth about the silence rather than hiding it.
//!
//! The fixture pairs ONE reachable stub peer with ONE unreachable NAT peer: an implementation that
//! counted intent rather than delivery returns 2, one that counts delivery returns 1. A NAT-only
//! fixture could not tell those apart from a broadcast that simply failed.

mod common;

use std::net::SocketAddr;

use dig_gossip::{DigMessage, GossipHandle, GossipService, NodeType};

async fn running_handle() -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 32;
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    (svc, handle, dir)
}

/// A `NatPeerConnection` over a loopback duplex — a real mux session, no network. The server half is
/// returned so the caller can keep the session open.
fn loopback_nat_conn(
    peer_id_bytes: [u8; 32],
    remote: SocketAddr,
) -> (dig_gossip::NatPeerConnection, dig_nat::PeerSession) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let inner = dig_nat::PeerConnection {
        peer_id: dig_nat::PeerId::from_bytes(peer_id_bytes),
        method: dig_nat::TraversalKind::Relayed,
        remote_addr: remote,
        peer_bls_pub: None,
        session: dig_nat::PeerSession::client(client_io),
    };
    let server = dig_nat::PeerSession::server(server_io);
    (dig_gossip::NatPeerConnection::new(inner), server)
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// **#3063 core regression.** One reachable stub peer + one unreachable NAT peer: the returned count
/// is 1 (what was delivered), not 2 (what was merely present).
#[tokio::test]
async fn broadcast_counts_only_peers_it_actually_sent_to() {
    let (_svc, handle, _dir) = running_handle().await;

    handle
        .__connect_stub_peer_with_direction(addr("127.0.0.1:19101"), NodeType::FullNode, true)
        .await
        .unwrap();

    let (nat, _server) = loopback_nat_conn([0x5a; 32], addr("198.51.100.7:9445"));
    handle.adopt_nat_connection(nat).await.unwrap();

    assert_eq!(
        handle.peer_count().await,
        2,
        "both peers are connected — the count under test is about DELIVERY, not membership"
    );

    let delivered = handle
        .broadcast(DigMessage::new(223, None, vec![3u8; 32].into()), None)
        .await
        .unwrap();

    assert_eq!(
        delivered, 1,
        "the return value must count only the peer the frame was actually sent to; \
         a NAT peer has no wired gossip transport in this crate and receives nothing"
    );
}

/// The count reported by `unreachable_peer_count` names the silence the delivery count hides: a
/// caller can tell "nobody is connected" apart from "the connected peer cannot be reached".
#[tokio::test]
async fn unreachable_nat_peers_are_reported_separately() {
    let (_svc, handle, _dir) = running_handle().await;

    assert_eq!(handle.unreachable_peer_count(), 0, "no peers at all");

    let (nat, _server) = loopback_nat_conn([0x5b; 32], addr("198.51.100.8:9445"));
    handle.adopt_nat_connection(nat).await.unwrap();

    assert_eq!(
        handle.unreachable_peer_count(),
        1,
        "a NAT-adopted peer is connected but unreachable by broadcast — say so explicitly"
    );
}
