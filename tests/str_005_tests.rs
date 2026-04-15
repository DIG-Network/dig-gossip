//! Integration tests for **STR-005: Test infrastructure** (`tests/common` helpers).
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`STR-005.md`](../docs/requirements/domains/crate_structure/specs/STR-005.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/crate_structure/NORMATIVE.md)
//! - **Implementation order:** [`IMPLEMENTATION_ORDER.md`](../docs/requirements/IMPLEMENTATION_ORDER.md) Phase 0
//!
//! ## What this proves
//!
//! Each test maps to a row in STR-005’s verification matrix. Helpers live in [`common`] so future
//! domains (CON-*, API-*) can reuse the same harness without copy-pasting setup.

mod common;

use std::time::{Duration, Instant};

use dig_gossip::load_ssl_cert;

/// **Acceptance:** unique [`PeerId`] per call — STR-005 §`random_peer_id`.
///
/// SPEC §2.2 — PeerId is a type alias for Bytes32 (SHA256 of TLS public key);
/// two random draws from 256 bits must not collide.
#[test]
fn test_random_peer_id_unique() {
    // Two draws from 256 bits should collide with negligible probability; this guards accidental
    // constant / zeroed implementations.
    let a = common::random_peer_id();
    let b = common::random_peer_id();
    assert_ne!(a, b, "random_peer_id must not return a fixed value");
}

/// **Acceptance:** `PeerId` is 32 bytes on the wire (Chia `Bytes32`).
///
/// SPEC §2.2 — `pub type PeerId = Bytes32` from chia-protocol.
#[test]
fn test_random_peer_id_is_32_bytes() {
    let id = common::random_peer_id();
    assert_eq!(id.to_bytes().len(), 32);
}

/// **Acceptance:** outbound mock sets `is_outbound` and metadata fields — STR-005 `mock_peer_connection`.
///
/// SPEC §2.4 — PeerConnection wraps chia-sdk-client::Peer with is_outbound, node_type,
/// protocol_version, software_version, bytes_read, bytes_written fields.
#[tokio::test]
async fn test_mock_peer_connection_outbound() {
    let conn = common::mock_peer_connection(true).await;
    assert!(conn.is_outbound);
    assert_eq!(conn.node_type, dig_gossip::NodeType::FullNode);
    assert_eq!(conn.protocol_version, "0.0.35");
    assert!(!conn.software_version.is_empty());
    assert_eq!(conn.bytes_read, 0);
    assert_eq!(conn.bytes_written, 0);
}

/// **Acceptance:** inbound mock mirrors outbound with `is_outbound == false`.
///
/// SPEC §2.4 — PeerConnection.is_outbound distinguishes inbound vs outbound direction.
#[tokio::test]
async fn test_mock_peer_connection_inbound() {
    let conn = common::mock_peer_connection(false).await;
    assert!(!conn.is_outbound);
    assert_eq!(conn.node_type, dig_gossip::NodeType::FullNode);
}

/// **Acceptance:** temp directory exists before drop — STR-005 `test_temp_dir`.
#[test]
fn test_temp_dir_created() {
    let dir = common::test_temp_dir();
    assert!(
        dir.path().exists(),
        "temp dir should exist while TempDir guard is alive"
    );
}

/// **Acceptance:** `TempDir` removes the tree on drop — no leaks of peers.dat / certs.
#[test]
fn test_temp_dir_cleanup() {
    let path = {
        let d = common::test_temp_dir();
        let p = d.path().to_path_buf();
        assert!(p.exists());
        p
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    while path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !path.exists(),
        "temp dir should be removed after drop (Windows may need a short spin)"
    );
}

/// **Acceptance:** localhost listener `:0` and STR-005 example limits (`2`, `10`).
///
/// SPEC §2.10 — GossipConfig fields: listen_addr, target_outbound_count, max_connections.
/// SPEC §11.1 — test infrastructure provides harness configs for integration tests.
#[test]
fn test_gossip_config_defaults() {
    let dir = common::test_temp_dir();
    let cfg = common::test_gossip_config(dir.path());
    assert!(cfg.listen_addr.ip().is_loopback());
    assert_eq!(cfg.listen_addr.port(), 0);
    assert_eq!(cfg.target_outbound_count, 2);
    assert_eq!(cfg.max_connections, 10);
}

/// **Acceptance:** TLS and persistence paths stay under the harness temp dir (portable paths).
///
/// SPEC §2.10 — GossipConfig.cert_path, key_path, peers_file_path fields.
/// SPEC §10.1 — test layout uses temp dirs to isolate TLS and address manager state.
#[test]
fn test_gossip_config_uses_temp_dir() {
    let dir = common::test_temp_dir();
    let root = dir.path();
    let cfg = common::test_gossip_config(root);
    assert!(std::path::Path::new(&cfg.cert_path).starts_with(root));
    assert!(std::path::Path::new(&cfg.key_path).starts_with(root));
    assert!(cfg.peers_file_path.starts_with(root));
}

/// **Acceptance:** PEM files exist after generation — STR-005 `generate_test_certs`.
///
/// SPEC §5.3 — mTLS via chia-ssl: ChiaCertificate::generate() creates PEM cert+key.
#[test]
fn test_generate_certs() {
    let dir = common::test_temp_dir();
    let (c, k) = common::generate_test_certs(dir.path());
    assert!(std::path::Path::new(&c).exists());
    assert!(std::path::Path::new(&k).exists());
}

/// **Acceptance:** chia-sdk-client can load generated material (`load_ssl_cert`).
///
/// SPEC §1.2 — chia-ssl for TLS certificates; SPEC §5.3 — load_ssl_cert() loads existing certs.
#[test]
fn test_generate_certs_valid() {
    let dir = common::test_temp_dir();
    let (c, k) = common::generate_test_certs(dir.path());
    let loaded = load_ssl_cert(&c, &k).expect("load_ssl_cert on generated PEM");
    drop(loaded);
}

/// **Acceptance:** [`common::connected_test_pair`] composes harness pieces and returns distinct bind addresses.
///
/// SPEC §11.2 — integration tests: connect two nodes using connect_peer(), verify handshake.
///
/// **Deferred detail:** “each handle reports one connected peer” needs API-002 + CON-001; see
/// `common` module docs and the ignored tests below.
#[tokio::test]
async fn test_connected_pair() {
    let (_ha, _hb, a, b) = common::connected_test_pair().await;
    assert_ne!(
        a, b,
        "OS should assign different ephemeral ports for two :0 binds"
    );
    assert!(a.ip().is_loopback());
    assert!(b.ip().is_loopback());
}

/// **Future:** bidirectional gossip once `GossipService` / `GossipHandle` expose messaging.
#[tokio::test]
#[ignore = "requires API-001/002 and CON-001 for real cross-service gossip links"]
async fn test_connected_pair_bidirectional() {
    // Placeholder: when GossipHandle::send / inbound channels exist, send a wire message both
    // ways and assert delivery (STR-005 integration row).
    unimplemented!("wired after service + connection domains");
}
