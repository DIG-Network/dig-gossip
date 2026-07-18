//! #924 WU4 — B1 (dialable-peer fold + self-filter) + B2 (count/route a relay-transport peer as
//! connected).
//!
//! **B1** turns a relay-DISCOVERED peer that now carries a relay-resolved dialable candidate
//! (`RelayPeerInfo.addresses`, filled by dig-nat/dig-relay's address-carrying reservation) into a
//! DIALABLE [`PeerRecord`] that SURVIVES the dialable-only address-book merge — so the pool
//! direct-dials it over the existing mTLS path and it lands in `connected_peers`. A legacy peer with
//! no candidate keeps today's identity-only `Via::Relay` behavior. The self-filter is hardened so a
//! relay echoing this node's own id in a different spelling (a `0x` prefix / uppercase) no longer
//! inflates `relay_peer_count`.
//!
//! **B2** treats a peer reached over dig-nat's relayed transport ([`TraversalKind::Relayed`] — the
//! traversal ladder's last tier, tunnelled through the relay's RLY-002 forwarder) as a CONNECTED pool
//! peer: it is counted in `connected_peers`, tallied distinctly in `relay_transport_peer_count`, and
//! reported [`Via::Relay`]. Per **NC-1** the relay only ever forwards opaque bytes — the RLY-002
//! payload is a `Vec<u8>` the relay cannot interpret — so no plaintext-to-relay path is introduced.

mod common;

use std::net::SocketAddr;

use dig_gossip::nat::{AddressKind, PeerRecord, Via};
use dig_gossip::relay::relay_client::RelayClient;
use dig_gossip::{GossipHandle, GossipService, PeerPoolConfig, RelayMessage};
use dig_nat::wire::RelayPeerInfo;

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

/// A relay-discovered peer carrying relay-resolved dialable candidate address(es) (#924 B1).
fn relay_peer_with_addrs(peer_id: &str, addrs: Vec<SocketAddr>) -> RelayPeerInfo {
    let mut rpi = RelayPeerInfo::new(peer_id.to_string(), "DIG_MAINNET".to_string(), 1);
    rpi.addresses = addrs;
    rpi
}

/// A legacy relay-discovered peer, addressed by `peer_id` only (no dialable candidate).
fn relay_peer(peer_id: &str) -> RelayPeerInfo {
    RelayPeerInfo::new(peer_id.to_string(), "DIG_MAINNET".to_string(), 1)
}

/// Build a `NatPeerConnection` over a loopback duplex with a chosen peer_id, remote, and traversal
/// tier, so a relay-transport peer can be adopted into the pool WITHOUT a real relay. Returns the
/// connection and the server half of the duplex (kept alive by the caller so the session stays open).
fn loopback_nat_conn(
    peer_id_bytes: [u8; 32],
    remote: SocketAddr,
    method: dig_nat::TraversalKind,
) -> (dig_gossip::NatPeerConnection, dig_nat::PeerSession) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let inner = dig_nat::PeerConnection {
        peer_id: dig_nat::PeerId::from_bytes(peer_id_bytes),
        method,
        remote_addr: remote,
        session: dig_nat::PeerSession::client(client_io),
    };
    let server = dig_nat::PeerSession::server(server_io);
    (dig_gossip::NatPeerConnection::new(inner), server)
}

async fn running_handle(
    min: usize,
    target: usize,
    max: usize,
) -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = max + 8;
    cfg.peer_pool = Some(PeerPoolConfig {
        min_peers: min,
        target_peers: target,
        max_peers: max,
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

// -------------------------------------------------------------------------------------------------
// B1 — dialable fold + self-filter
// -------------------------------------------------------------------------------------------------

/// (a) A relay peer with dialable candidate(s) folds into a DIALABLE `Via::Direct` record whose
/// candidates are `Direct` and IPv6-first, so it survives the dialable-only merge
/// (`to_timestamped_peer_info` is `Some`).
#[test]
fn dialable_candidates_fold_into_a_direct_record_ipv6_first() {
    // Deliberately list IPv4 before IPv6 to prove the fold reorders IPv6-first (§5.2).
    let v4 = addr("203.0.113.5:9445");
    let v6 = addr("[2001:db8::1]:9445");
    let rpi = relay_peer_with_addrs(&"cd".repeat(32), vec![v4, v6]);

    let record = PeerRecord::from_nat_relay_peer_info(&rpi);

    assert_eq!(
        record.via,
        Via::Direct,
        "a dialable relay peer is Via::Direct"
    );
    assert_eq!(record.addresses.len(), 2);
    assert!(
        record
            .addresses
            .iter()
            .all(|a| a.kind == AddressKind::Direct),
        "relay-resolved candidates are dialable Direct addresses"
    );
    assert_eq!(
        record.addresses[0].host, "2001:db8::1",
        "IPv6 candidate is surfaced first (§5.2 happy-eyeballs)"
    );
    assert_eq!(record.addresses[1].host, "203.0.113.5");
    assert!(
        record.best_address().is_some(),
        "the record has a dialable address"
    );
    assert!(
        record.to_timestamped_peer_info().is_some(),
        "a dialable record SURVIVES the dialable-only address-book merge"
    );
}

/// (a) After folding a dialable relay peer, it enters the by-address book (so the pool can dial it).
#[tokio::test]
async fn a_dialable_relay_peer_enters_the_address_book_on_fold() {
    let (svc, handle, _dir) = running_handle(1, 4, 8).await;

    handle.fold_relay_known_peers(&[relay_peer_with_addrs(
        &"11".repeat(32),
        vec![addr("198.51.100.7:9445")],
    )]);

    let stats = handle.stats().await;
    assert_eq!(
        stats.known_addresses, 1,
        "the relay-resolved dialable candidate enters the by-address book for the pool to dial"
    );
    assert_eq!(
        stats.relay_peer_count, 1,
        "the peer is also still counted as relay-reachable (no regression)"
    );

    svc.stop().await.expect("stop");
}

/// (b) A legacy relay peer with NO candidate keeps today's identity-only `Via::Relay` behavior — no
/// dialable address, never placed in the by-address book.
#[test]
fn empty_candidates_preserve_identity_only_relay_behavior() {
    let rpi = relay_peer(&"ab".repeat(32));
    let record = PeerRecord::from_nat_relay_peer_info(&rpi);

    assert_eq!(record.via, Via::Relay);
    assert!(record.addresses.is_empty());
    assert!(record.best_address().is_none());
    assert!(record.to_timestamped_peer_info().is_none());
}

/// (c) The self-filter excludes this node even when the relay echoes its id in a DIFFERENT spelling
/// (a `0x` prefix + uppercase). A byte-exact compare missed the match and inflated `relay_peer_count`
/// by one (round-3 finding 4); normalizing both sides fixes it.
#[tokio::test]
async fn self_is_excluded_despite_a_differently_spelled_echo() {
    let (svc, handle, _dir) = running_handle(1, 4, 8).await;
    let self_hex = handle.local_peer_id().expect("peer id").to_string();
    let echoed_self = format!("0x{}", self_hex.to_uppercase());

    handle.fold_relay_known_peers(&[relay_peer(&echoed_self), relay_peer(&"33".repeat(32))]);

    assert_eq!(
        handle.stats().await.relay_peer_count,
        1,
        "self is excluded regardless of 0x-prefix/case; only the genuine peer counts"
    );

    svc.stop().await.expect("stop");
}

// -------------------------------------------------------------------------------------------------
// B2 — count + route a relay-transport peer as connected (NC-1 sealed)
// -------------------------------------------------------------------------------------------------

/// (d) A peer reached over the relayed transport is COUNTED as connected: it lands in
/// `connected_peers` AND is tallied distinctly in `relay_transport_peer_count`. This is what moves
/// `connected_peers` off 0 for a NAT-blocked pair with no direct dialability.
#[tokio::test]
async fn a_relay_transport_peer_is_counted_as_connected() {
    let (svc, handle, _dir) = running_handle(1, 4, 8).await;

    let (direct, s1) = loopback_nat_conn(
        [1; 32],
        addr("203.0.113.1:9445"),
        dig_nat::TraversalKind::Direct,
    );
    let (relayed, s2) = loopback_nat_conn(
        [2; 32],
        addr("203.0.113.9:9450"),
        dig_nat::TraversalKind::Relayed,
    );
    handle
        .adopt_nat_connection(direct)
        .await
        .expect("adopt direct");
    handle
        .adopt_nat_connection(relayed)
        .await
        .expect("adopt relayed");

    let stats = handle.stats().await;
    assert_eq!(stats.connected_peers, 2, "both peers count as connected");
    assert_eq!(
        stats.relay_transport_peer_count, 1,
        "exactly the relayed-transport peer is tallied as relay-transport"
    );

    let _ = (s1, s2);
    svc.stop().await.expect("stop");
}

/// (e) A relay-transport peer's route is CLASSIFIED `Via::Relay` (its gossip rides dig-nat's relayed
/// transport = the relay's RLY-002 forwarder), while a directly-reached peer is `Via::Direct`. This is
/// the relay-transport peer-kind reported alongside the direct-TLS peer.
#[tokio::test]
async fn a_relay_transport_peer_is_reported_via_relay() {
    let (svc, handle, _dir) = running_handle(1, 4, 8).await;

    let (direct, s1) = loopback_nat_conn(
        [3; 32],
        addr("203.0.113.3:9445"),
        dig_nat::TraversalKind::Direct,
    );
    let (relayed, s2) = loopback_nat_conn(
        [4; 32],
        addr("203.0.113.9:9450"),
        dig_nat::TraversalKind::Relayed,
    );
    let direct_pid = handle
        .adopt_nat_connection(direct)
        .await
        .expect("adopt direct");
    let relayed_pid = handle
        .adopt_nat_connection(relayed)
        .await
        .expect("adopt relayed");

    let via: std::collections::HashMap<_, _> =
        handle.connected_pool_peers_with_via().into_iter().collect();
    assert_eq!(
        via.get(&relayed_pid),
        Some(&Via::Relay),
        "relayed peer routes via the relay"
    );
    assert_eq!(
        via.get(&direct_pid),
        Some(&Via::Direct),
        "direct peer routes peer-to-peer"
    );

    let _ = (s1, s2);
    svc.stop().await.expect("stop");
}

/// (f) NC-1: the relay only ever forwards OPAQUE bytes. An already-sealed (ciphertext) payload handed
/// to the RLY-002 forwarding builder is placed VERBATIM in the `Vec<u8>` payload and appears on the
/// wire unchanged — the relay sees only ciphertext, never structured plaintext. dig-gossip has no path
/// that turns a gossip message into relay plaintext, so no plaintext-to-relay path is introduced.
#[test]
fn nc1_rly002_forwards_only_opaque_ciphertext_bytes() {
    let mut client = RelayClient::new("me".to_string(), "DIG_MAINNET".to_string(), 1);
    // Stand in for a frame already sealed to the recipient's key — bytes the relay cannot interpret.
    let sealed: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22];

    let msg = client.build_send_to_peer("peer_b", sealed.clone());

    match &msg {
        RelayMessage::RelayGossipMessage { payload, .. } => {
            assert_eq!(
                payload, &sealed,
                "the RLY-002 payload carries the sealed bytes verbatim — no plaintext transform"
            );
        }
        other => panic!("expected RelayGossipMessage, got {other:?}"),
    }

    // The serialized wire the relay sees carries exactly those opaque bytes (a JSON u8 array), and
    // never the recipient's cleartext — the relay is an untrusted byte forwarder (NC-1).
    let wire = serde_json::to_string(&msg).expect("serialize");
    assert!(
        wire.contains("[222,173,190,239,0,17,34]"),
        "wire carries the opaque byte payload, not interpretable plaintext: {wire}"
    );
}
