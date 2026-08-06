//! Integration tests for the **advertised software version** on the Chia handshake
//! (dig_ecosystem#2215).
//!
//! ## What is under test
//!
//! [`GossipConfig::software_version`] is the ONE value this node advertises to peers, in BOTH
//! directions — on the hello we send when we dial ([`connect_outbound_peer`]) and on the reply we
//! send when we accept (the listener). Before #2215 the two directions disagreed: the dial path
//! sent the literal `"0.0.0"` and the accept path sent `dig-gossip/<CARGO_PKG_VERSION>`, so what a
//! peer learned about us depended on who dialled whom, and neither string was the *application's*
//! version.
//!
//! ## Fixture design
//!
//! Every test gives the two nodes **distinct** advertised strings, neither of which is `"0.0.0"`
//! nor the dig-gossip crate version. That is what makes the assertions load-bearing:
//!
//! - Distinct values distinguish "each node reports the *other's* string" from "each node reports
//!   its own" — a shared value could not tell those apart.
//! - Values unlike the two former literals mean a surviving hardcode fails the test rather than
//!   coincidentally matching it.
//!
//! [`GossipConfig::software_version`]: dig_gossip::GossipConfig::software_version
//! [`connect_outbound_peer`]: dig_gossip::connection::outbound

mod common;

use std::net::SocketAddr;

use dig_gossip::{GossipHandle, GossipService, PeerId};

/// The value node A advertises. Deliberately unlike `"0.0.0"` and unlike `dig-gossip/<version>`.
const A_SOFTWARE: &str = "dig-node/1.2.3";
/// The value node B advertises. Distinct from [`A_SOFTWARE`] so a mixed-up reading is visible.
const B_SOFTWARE: &str = "dig-node/9.8.7";

/// Start a running [`GossipService`] advertising `software_version`, and return its handle plus
/// the address it is listening on.
///
/// The [`tempfile::TempDir`] owns the TLS material and must outlive the test.
async fn node_advertising(
    software_version: &str,
) -> (tempfile::TempDir, GossipService, GossipHandle, SocketAddr) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.software_version = software_version.to_string();
    let svc = GossipService::new(cfg).expect("GossipService::new");
    let handle = svc.start().await.expect("start");
    let bound = handle
        .__listen_bound_addr_for_tests()
        .expect("listen addr after start");
    (dir, svc, handle, bound)
}

/// The software version `handle` has recorded for its one and only connected peer.
///
/// Panics unless exactly one peer is connected, so a test can never silently assert against a
/// peer that is not the one it just connected.
fn sole_peer_software(handle: &GossipHandle) -> String {
    let mut peers: Vec<(PeerId, String)> = handle.connected_pool_peers_with_software();
    assert_eq!(peers.len(), 1, "expected exactly one connected peer");
    peers.remove(0).1
}

/// A node advertises the SAME configured string whether it dialled or was dialled, and the peer on
/// the other end READS it — proven for all four send paths across two nodes.
///
/// Connection 1 (A dials B) exercises A's dial path and B's accept path. Connection 2 (B dials A)
/// exercises B's dial path and A's accept path. Asserting the same expected string on both
/// connections is the regression guard against the direction-dependent split returning: if the
/// dial and accept paths ever advertise different values again, one of the four assertions fails.
#[tokio::test]
async fn peer_reads_our_configured_software_version_in_both_directions() {
    // --- Connection 1: A dials B ---
    let (_da, _sa, a, _a_addr) = node_advertising(A_SOFTWARE).await;
    let (_db, _sb, b, b_addr) = node_advertising(B_SOFTWARE).await;
    a.connect_to(b_addr).await.expect("A dials B");

    assert_eq!(
        sole_peer_software(&a),
        B_SOFTWARE,
        "the dialling node must read the accepting peer's configured software version"
    );
    assert_eq!(
        sole_peer_software(&b),
        A_SOFTWARE,
        "the accepting node must read the dialling peer's configured software version"
    );

    // --- Connection 2: the reverse direction, on a fresh pair so each pool holds one peer ---
    let (_dc, _sc, c, c_addr) = node_advertising(A_SOFTWARE).await;
    let (_dd, _sd, d, _d_addr) = node_advertising(B_SOFTWARE).await;
    d.connect_to(c_addr).await.expect("D dials C");

    assert_eq!(
        sole_peer_software(&d),
        A_SOFTWARE,
        "a node advertises the same string when it ACCEPTS as when it DIALS"
    );
    assert_eq!(
        sole_peer_software(&c),
        B_SOFTWARE,
        "a node advertises the same string when it DIALS as when it ACCEPTS"
    );
}

/// The `off` coarsening setting — an empty advertised string — is indistinguishable to a peer from
/// a build that predates the field, and does not prevent the connection.
///
/// This is the back-compat evidence: `Handshake.software_version` is a non-optional `String`, so a
/// peer that never learned to set it sends `""`. A node advertising `""` must therefore connect
/// exactly as any other peer does, and the far end must observe `""` — which the control boundary
/// maps to `PeerSoftware::Unknown`.
#[tokio::test]
async fn empty_advertised_version_connects_and_is_read_as_empty() {
    let (_ds, _ss, server, bound) = node_advertising("").await;
    let (_dc, _sc, client, _c_addr) = node_advertising(B_SOFTWARE).await;

    client
        .connect_to(bound)
        .await
        .expect("connect with off mode");

    assert_eq!(
        sole_peer_software(&client),
        "",
        "a peer advertising nothing must be observed as an empty string, not a fabricated version"
    );
    assert_eq!(
        sole_peer_software(&server),
        B_SOFTWARE,
        "advertising nothing must not affect what this node READS from its peer"
    );
}

/// The legacy `"0.0.0"` sentinel — what every peer built before #2215 advertises — still connects,
/// and is carried through verbatim rather than being rewritten or rejected by the transport.
///
/// dig-gossip is a dumb carrier: interpreting `"0.0.0"` as "unknown" is the control boundary's job
/// (`PeerSoftware`), not the transport's. This test pins that division so a well-meaning
/// normalisation is not added here, where it would hide the raw wire value from every reader.
#[tokio::test]
async fn legacy_zero_sentinel_connects_and_is_carried_verbatim() {
    let (_ds, _ss, server, bound) = node_advertising("0.0.0").await;
    let (_dc, _sc, client, _c_addr) = node_advertising(A_SOFTWARE).await;

    client
        .connect_to(bound)
        .await
        .expect("legacy peer connects");

    assert_eq!(
        sole_peer_software(&client),
        "0.0.0",
        "the transport must carry the legacy sentinel verbatim, not reinterpret it"
    );
    assert_eq!(
        sole_peer_software(&server),
        A_SOFTWARE,
        "a legacy peer must still READ its peer's build correctly"
    );
}

/// The default advertised value names dig-gossip, never the bare `"0.0.0"` that the dial path used
/// to send — an application that forgets to set the field is identifiable, not anonymous-looking.
#[test]
fn default_software_version_names_the_crate_and_is_not_the_legacy_sentinel() {
    let default = dig_gossip::GossipConfig::default().software_version;
    assert!(
        default.starts_with("dig-gossip/"),
        "default must be UA-shaped and name this crate, got {default:?}"
    );
    assert_ne!(
        default, "0.0.0",
        "the legacy sentinel must never be a default"
    );
}
