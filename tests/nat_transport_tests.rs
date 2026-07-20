//! INT-017 — the `dig-nat`-backed peer transport + the peer-RPC `PeerRecord` shapes.
//!
//! `dig-gossip` routes its peer connections + discovery through `dig-nat` (the unified L7
//! `connect(peer)` NAT-traversal ladder + yamux-multiplexed transport) instead of a bespoke dialer.
//! This suite covers the ADAPTER layer that wires the two together — with NO real network:
//!
//! - **identity** — the node mints a CA-signed `dig-tls` `NodeCert` (the #1268/#1280 self-signed→
//!   CA-signed cutover) whose `peer_id = SHA-256(SPKI DER)` is derived identically by the gossip layer.
//! - **`PeerTarget` construction** — a gossip `PeerId` + address becomes a `dig-nat` `PeerTarget`.
//! - **`PeerRecord` wire shape** — the spec's `dig.getPeers` record
//!   (`{peer_id, addresses:[{host,port,kind}], network_id, last_seen, via}`) round-trips through JSON
//!   with the exact field names + `kind`/`via` enum spellings the L7 spec freezes, and converts
//!   to/from the Chia-streamable `TimestampedPeerInfo` peer-exchange + the relay `RelayPeerInfo`.
//! - **mux transport over a loopback mTLS-shaped stream** — a gossip channel opens a logical stream
//!   over a `dig-nat` `PeerSession` and control/data round-trips (the transport dig-gossip layers its
//!   gossip algorithms on top of).

use dig_gossip::nat::{peer_target_for, AddressKind, PeerAddress, PeerRecord, Via};
use dig_gossip::PeerId;

// -----------------------------------------------------------------------------------------------
// Identity: a CA-signed dig-tls NodeCert whose peer_id the gossip layer derives identically
// -----------------------------------------------------------------------------------------------

#[test]
fn nat_node_cert_peer_id_matches_gossip_spki_derivation() {
    // Mint the node's CA-signed dig-tls NodeCert (the #1268/#1280 cutover) from an ephemeral BLS key,
    // exactly as the service does on first use of the dig-nat transport.
    let bls_sk = dig_tls::bls::SecretKey::from_seed(&[7u8; 32]);
    let node = dig_tls::NodeCert::generate_signed(&bls_sk).expect("mint a CA-signed NodeCert");

    // The gossip layer, given the SAME leaf certificate's SPKI DER, derives the SAME peer_id
    // (peer_id = SHA-256(TLS SPKI DER) — the frozen contract across dig-gossip / dig-nat / dig-tls).
    let (_, x509) = x509_parser::parse_x509_certificate(node.cert_der())
        .expect("parse the CA-signed leaf cert");
    let gossip_id = dig_gossip::peer_id_from_tls_spki_der(x509.tbs_certificate.subject_pki.raw);

    assert_eq!(
        node.peer_id().as_bytes(),
        gossip_id.as_ref(),
        "the NodeCert's peer_id must equal the gossip-layer SPKI derivation from the same cert"
    );
}

// -----------------------------------------------------------------------------------------------
// PeerTarget construction for dig-nat's connect()
// -----------------------------------------------------------------------------------------------

#[test]
fn peer_target_carries_peer_id_addr_and_network() {
    let peer_id = PeerId::from([7u8; 32]);
    let addr = "203.0.113.7:9444".parse().unwrap();
    let target = peer_target_for(peer_id, Some(addr), "DIG_MAINNET");

    assert_eq!(target.peer_id.as_bytes(), &[7u8; 32]);
    assert_eq!(target.direct_addr(), Some(addr));
    assert_eq!(target.network_id, "DIG_MAINNET");
}

#[test]
fn peer_target_without_addr_is_relay_only() {
    let peer_id = PeerId::from([9u8; 32]);
    let target = peer_target_for(peer_id, None, "DIG_MAINNET");
    assert_eq!(target.direct_addr(), None);
    assert_eq!(target.peer_id.as_bytes(), &[9u8; 32]);
}

// -----------------------------------------------------------------------------------------------
// PeerRecord — the dig.getPeers wire shape (L7 spec §7 / §11 Conformance)
// -----------------------------------------------------------------------------------------------

#[test]
fn peer_record_json_matches_the_spec_shape() {
    let rec = PeerRecord {
        peer_id: "aa".repeat(32),
        addresses: vec![PeerAddress {
            host: "203.0.113.7".into(),
            port: 9444,
            kind: AddressKind::Direct,
        }],
        network_id: "DIG_MAINNET".into(),
        last_seen: 1_719_763_200,
        via: Via::Direct,
    };
    let v: serde_json::Value = serde_json::to_value(&rec).unwrap();

    // Exact field names + kind/via spellings the spec freezes.
    assert_eq!(v["peer_id"], "aa".repeat(32));
    assert_eq!(v["addresses"][0]["host"], "203.0.113.7");
    assert_eq!(v["addresses"][0]["port"], 9444);
    assert_eq!(v["addresses"][0]["kind"], "direct");
    assert_eq!(v["network_id"], "DIG_MAINNET");
    assert_eq!(v["last_seen"], 1_719_763_200u64);
    assert_eq!(v["via"], "direct");

    // Round-trips.
    let back: PeerRecord = serde_json::from_value(v).unwrap();
    assert_eq!(back, rec);
}

#[test]
fn address_kind_and_via_spellings_are_the_frozen_lowercase_tokens() {
    for (k, s) in [
        (AddressKind::Direct, "direct"),
        (AddressKind::Reflexive, "reflexive"),
        (AddressKind::Mapped, "mapped"),
        (AddressKind::Relay, "relay"),
    ] {
        assert_eq!(serde_json::to_value(k).unwrap(), serde_json::json!(s));
    }
    for (v, s) in [(Via::Direct, "direct"), (Via::Relay, "relay")] {
        assert_eq!(serde_json::to_value(v).unwrap(), serde_json::json!(s));
    }
}

#[test]
fn peer_record_converts_to_timestamped_peer_info_for_gossip_exchange() {
    // A PeerRecord's most-direct address becomes a Chia-streamable TimestampedPeerInfo row for the
    // §4b RequestPeers/RespondPeers exchange + the address manager.
    let rec = PeerRecord {
        peer_id: "bb".repeat(32),
        addresses: vec![
            PeerAddress {
                host: "198.51.100.4".into(),
                port: 9444,
                kind: AddressKind::Mapped,
            },
            PeerAddress {
                host: "203.0.113.9".into(),
                port: 9444,
                kind: AddressKind::Direct,
            },
        ],
        network_id: "DIG_MAINNET".into(),
        last_seen: 1_719_763_200,
        via: Via::Direct,
    };
    let tpi = rec
        .to_timestamped_peer_info()
        .expect("a record with a dialable address yields a TimestampedPeerInfo");
    // Direct is most-direct (rank 0) so it is chosen over the mapped address.
    assert_eq!(tpi.host, "203.0.113.9");
    assert_eq!(tpi.port, 9444);
    assert_eq!(tpi.timestamp, 1_719_763_200);
}

#[test]
fn peer_record_from_relay_peer_info_has_no_dialable_address() {
    // The relay introducer returns identity-only RelayPeerInfo (no IP:port) — the record marks the
    // peer as relay-reachable so the caller knows to reach it via the relay / a hole punch.
    let rpi = dig_gossip::RelayPeerInfo {
        peer_id: "cc".repeat(32),
        network_id: "DIG_MAINNET".into(),
        protocol_version: 1,
        connected_at: 100,
        last_seen: 200,
        addresses: Vec::new(),
    };
    let rec = PeerRecord::from_relay_peer_info(&rpi);
    assert_eq!(rec.peer_id, "cc".repeat(32));
    assert_eq!(rec.network_id, "DIG_MAINNET");
    assert_eq!(rec.last_seen, 200);
    assert_eq!(rec.via, Via::Relay);
    assert!(
        rec.addresses.is_empty(),
        "a relay-introduced peer has no direct candidate address until discovered"
    );
    assert!(rec.to_timestamped_peer_info().is_none());
}

// -----------------------------------------------------------------------------------------------
// Mux transport — a gossip channel over a dig-nat PeerSession (loopback, no real network)
// -----------------------------------------------------------------------------------------------

#[tokio::test]
async fn gossip_channel_round_trips_over_a_nat_mux_stream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A loopback duplex stands in for the mTLS byte stream dig-nat establishes; the mux transport is
    // identical regardless of which traversal tier produced the stream (the point of the abstraction).
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let mut client = dig_nat::PeerSession::client(client_io);
    let mut server = dig_nat::PeerSession::server(server_io);

    // Server accepts one logical stream (a gossip channel) and echoes a framed reply.
    let server_task = tokio::spawn(async move {
        let mut s = server
            .accept_stream()
            .await
            .expect("inbound gossip channel");
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"BLOCK");
        s.write_all(b"ACKED").await.unwrap();
        s.flush().await.unwrap();
    });

    // Client opens a gossip channel over the same connection dig-gossip would layer Plumtree on.
    let mut ch = client.open_stream().await.expect("open gossip channel");
    ch.write_all(b"BLOCK").await.unwrap();
    ch.flush().await.unwrap();
    let mut reply = [0u8; 5];
    ch.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ACKED");

    server_task.await.unwrap();
}

// -----------------------------------------------------------------------------------------------
// NatPeerConnection — the gossip-facing wrapper over a dig-nat PeerConnection
// -----------------------------------------------------------------------------------------------

/// Build a [`dig_gossip::NatPeerConnection`] over a loopback stream so its accessors + channel/range/
/// availability methods are exercised WITHOUT a real network. `remote` mirrors what a real dial would
/// carry; `session` is the client side of a loopback duplex (a real yamux session, just not over TLS).
fn loopback_nat_connection(
    peer_id_bytes: [u8; 32],
    remote: std::net::SocketAddr,
) -> (
    dig_gossip::NatPeerConnection,
    dig_nat::PeerSession, // the server side, kept alive by the caller
) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let inner = dig_nat::PeerConnection {
        peer_id: dig_nat::PeerId::from_bytes(peer_id_bytes),
        method: dig_nat::TraversalKind::Direct,
        remote_addr: remote,
        // No BLS binding over a loopback duplex (#1204 field on dig-nat's PeerConnection).
        peer_bls_pub: None,
        session: dig_nat::PeerSession::client(client_io),
    };
    let server = dig_nat::PeerSession::server(server_io);
    (dig_gossip::NatPeerConnection::new(inner), server)
}

#[tokio::test]
async fn nat_peer_connection_reports_verified_identity_and_tier() {
    let addr: std::net::SocketAddr = "203.0.113.7:9444".parse().unwrap();
    let (conn, _server) = loopback_nat_connection([0x5a; 32], addr);

    // The verified remote identity is bridged back to a gossip PeerId (Bytes32) byte-for-byte.
    assert_eq!(conn.peer_id().as_ref(), &[0x5a; 32]);
    // Which traversal tier established it — observability.
    assert_eq!(conn.method(), dig_nat::TraversalKind::Direct);
    assert_eq!(conn.remote_addr(), addr);
    // Debug does not leak the session internals.
    let dbg = format!("{conn:?}");
    assert!(dbg.contains("NatPeerConnection"));
    assert!(dbg.contains("Direct"));
}

#[tokio::test]
async fn nat_peer_connection_opens_channels_range_and_availability() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr: std::net::SocketAddr = "198.51.100.9:9444".parse().unwrap();
    let (mut conn, mut server) = loopback_nat_connection([0x01; 32], addr);

    // Serving side: accept three inbound logical streams (a gossip channel, a range stream, an
    // availability control call) and respond appropriately.
    let server_task = tokio::spawn(async move {
        // 1) plain gossip channel
        let mut ch = server.accept_stream().await.expect("gossip channel");
        let mut b = [0u8; 3];
        ch.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"HI!");

        // 2) range stream — read the RangeRequest preamble, stream one final frame back
        let mut rs = server.accept_stream().await.expect("range stream");
        let req = dig_nat::RangeRequest::decode(&mut rs).await.unwrap();
        assert_eq!(req.store_id, "aa".repeat(32));
        assert_eq!(req.offset, 0);
        let frame = dig_nat::RangeFrame {
            offset: 0,
            length: 4,
            bytes: b"data".to_vec(),
            complete: true,
            total_length: Some(4),
            chunk_lens: Some(vec![4]),
            chunk_index: Some(0),
            inclusion_proof: None,
            root: Some("bb".repeat(32)),
        };
        rs.write_all(&frame.encode()).await.unwrap();
        rs.flush().await.unwrap();

        // 3) availability control call — read the request, answer one item available
        let mut av = server.accept_stream().await.expect("availability stream");
        let areq = dig_nat::AvailabilityRequest::decode(&mut av).await.unwrap();
        assert_eq!(areq.items.len(), 1);
        let aresp = dig_nat::AvailabilityResponse {
            items: vec![dig_nat::AvailabilityAnswer {
                available: true,
                roots: None,
                total_length: Some(4),
                chunk_count: Some(1),
                complete: Some(true),
            }],
        };
        av.write_all(&aresp.encode()).await.unwrap();
        av.flush().await.unwrap();
    });

    // 1) open_channel
    let mut ch = conn.open_channel().await.expect("open gossip channel");
    ch.write_all(b"HI!").await.unwrap();
    ch.flush().await.unwrap();

    // 2) open_range_stream + read the frame back
    let req = dig_nat::RangeRequest::resource("aa".repeat(32), "cc".repeat(32), 0, 4);
    let mut rs = conn
        .open_range_stream(&req)
        .await
        .expect("open range stream");
    let frame = dig_nat::RangeFrame::decode(&mut rs)
        .await
        .unwrap()
        .expect("one frame");
    assert_eq!(frame.bytes, b"data");
    assert!(frame.complete);
    assert_eq!(frame.total_length, Some(4));

    // 3) query_availability
    let items = vec![dig_nat::AvailabilityItem {
        store_id: "aa".repeat(32),
        root: Some("bb".repeat(32)),
        retrieval_key: None,
    }];
    let resp = conn
        .query_availability(items)
        .await
        .expect("availability answered");
    assert_eq!(resp.items.len(), 1);
    assert!(resp.items[0].available);

    server_task.await.unwrap();

    // into_inner hands back the raw dig-nat connection for callers that need it (e.g. dig-node).
    let raw = conn.into_inner();
    assert_eq!(raw.peer_id.as_bytes(), &[0x01; 32]);
    assert_eq!(raw.method, dig_nat::TraversalKind::Direct);
}

// -----------------------------------------------------------------------------------------------
// PeerRecord — the peer-exchange (§4b) source + best-address selection
// -----------------------------------------------------------------------------------------------

#[test]
fn peer_record_from_timestamped_peer_info_is_a_direct_candidate() {
    let tpi = dig_protocol::TimestampedPeerInfo::new("203.0.113.50".to_string(), 9444, 12_345);
    let rec = PeerRecord::from_timestamped_peer_info(&tpi, "DIG_MAINNET");
    assert_eq!(rec.addresses.len(), 1);
    assert_eq!(rec.addresses[0].kind, AddressKind::Direct);
    assert_eq!(rec.addresses[0].host, "203.0.113.50");
    assert_eq!(rec.via, Via::Direct);
    assert_eq!(rec.network_id, "DIG_MAINNET");
    // Round-trips back to a dialable TimestampedPeerInfo.
    let back = rec.to_timestamped_peer_info().expect("dialable");
    assert_eq!(back.host, "203.0.113.50");
    assert_eq!(back.port, 9444);
    assert_eq!(back.timestamp, 12_345);
}

#[test]
fn best_address_prefers_most_direct_and_ignores_relay_only() {
    // A relay-only address is not dialable — best_address returns None; to_timestamped is None too.
    let relay_only = PeerRecord {
        peer_id: "dd".repeat(32),
        addresses: vec![PeerAddress {
            host: "0.0.0.0".into(),
            port: 0,
            kind: AddressKind::Relay,
        }],
        network_id: "DIG_MAINNET".into(),
        last_seen: 1,
        via: Via::Relay,
    };
    assert!(relay_only.best_address().is_none());
    assert!(relay_only.to_timestamped_peer_info().is_none());

    // Reflexive beats mapped? No — mapped (rank 1) is more direct than reflexive (rank 2).
    let mixed = PeerRecord {
        peer_id: String::new(),
        addresses: vec![
            PeerAddress {
                host: "a".into(),
                port: 1,
                kind: AddressKind::Reflexive,
            },
            PeerAddress {
                host: "b".into(),
                port: 2,
                kind: AddressKind::Mapped,
            },
        ],
        network_id: "n".into(),
        last_seen: 1,
        via: Via::Direct,
    };
    assert_eq!(mixed.best_address().unwrap().kind, AddressKind::Mapped);
}

#[test]
fn address_kind_dialability_matches_the_ladder() {
    assert!(AddressKind::Direct.is_dialable());
    assert!(AddressKind::Mapped.is_dialable());
    assert!(AddressKind::Reflexive.is_dialable());
    assert!(!AddressKind::Relay.is_dialable());
    // rank ordering is direct < mapped < reflexive < relay
    assert!(AddressKind::Direct.rank() < AddressKind::Mapped.rank());
    assert!(AddressKind::Mapped.rank() < AddressKind::Reflexive.rank());
    assert!(AddressKind::Reflexive.rank() < AddressKind::Relay.rank());
}
