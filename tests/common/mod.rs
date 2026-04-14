#![allow(dead_code)]
// ^ Each integration test binary (`str_005_tests`, `api_001_tests`, …) uses a different subset of
// helpers; unused items in this module are expected when compiling a single test crate.

//! Shared integration-test helpers for **STR-005: Test infrastructure**.
//!
//! ## Traceability
//!
//! - **Spec:** [`STR-005.md`](../../docs/requirements/domains/crate_structure/specs/STR-005.md)
//! - **Normative:** [`NORMATIVE.md`](../../docs/requirements/domains/crate_structure/NORMATIVE.md)
//! - **Master SPEC:** [`SPEC.md`](../../docs/resources/SPEC.md) Section 11 (testing strategy)
//!
//! ## Design notes
//!
//! - **Import surface:** Integration tests are separate crates; they depend only on the public
//!   `dig_gossip` API plus this module. Helpers intentionally live under `tests/common/` (not
//!   `#[cfg(test)]` in `src/`) so they stay available to **integration** tests — library unit
//!   tests cannot share `tests/common` without duplication (Cargo limitation).
//! - **Mock [`Peer`](chia_sdk_client::Peer):** `chia-sdk-client` exposes peers only after a
//!   WebSocket exists (`Peer::connect`, `Peer::from_websocket`). For [`mock_peer_connection`]
//!   we open a **plain** `ws://` loopback pair (no TLS) so [`Peer::from_websocket`] can hash a
//!   socket address for peer id plumbing. This is **not** a production handshake path (CON-001
//!   uses `wss://` + mutual TLS); it exists solely to obtain a well-formed [`PeerConnection`]
//!   for structure tests until CON-* lands.
//! - **[`connected_test_pair`]:** Full “two [`dig_gossip::GossipService`] instances wired
//!   together” requires API-001 / API-002 / CON-001. The function below composes temp dirs,
//!   certs, configs, and proves two independent listeners can bind — the handles remain
//!   placeholders until the service constructor exists.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use dig_gossip::{
    Bytes32, ChiaCertificate, GossipConfig, GossipHandle, GossipService, Network, NodeType, Peer,
    PeerConnection, PeerId, PeerOptions, PeerReputation,
};
use rand::Rng;
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, connect_async, MaybeTlsStream};

/// SHA256(`b"dig_testnet"`) — stable fake network id for harnesses (STR-005 sample).
///
/// Computed offline; documented here so tests do not pull a `sha2` dev-dependency solely for
/// this constant. See also API-003 (`network_id` field).
const DIG_TESTNET_NETWORK_ID: [u8; 32] = [
    0xa5, 0x92, 0xcc, 0x41, 0x7c, 0x04, 0xc7, 0x9e, 0x07, 0x51, 0x17, 0xec, 0xd5, 0x73, 0xce, 0x7c,
    0x27, 0x59, 0x55, 0xd8, 0x7e, 0xb5, 0xe2, 0x0f, 0x04, 0xb9, 0xbf, 0x5c, 0x23, 0x8f, 0x04, 0xae,
];

/// Unix timestamp in seconds (DIG metadata fields use wall-clock seconds — SPEC §2.4).
fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_secs()
}

/// Generate a random [`PeerId`] (`Bytes32`).
///
/// **Acceptance:** STR-005 — each call draws 32 random bytes (`rand::thread_rng`), so collisions
/// are cryptographically negligible for test uniqueness assertions.
pub fn random_peer_id() -> PeerId {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    PeerId::from(bytes)
}

/// Build a [`PeerConnection`] for tests by opening a loopback WebSocket and wrapping the chosen
/// side with gossip metadata.
///
/// `is_outbound == true` selects the **client** side of the connection (we initiated `ws://`);
/// `false` selects the **accepted** server side. Both sides hold a valid [`Peer`]; the discarded
/// side is dropped when this function returns (closing that half — sufficient for metadata-only
/// tests).
///
/// ## Async
///
/// STR-005’s prose shows a synchronous signature; real I/O needs an executor. Callers should
/// use `#[tokio::test]` (see `tests/str_005_tests.rs`).
pub async fn mock_peer_connection(is_outbound: bool) -> PeerConnection {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback for mock peer");
    let addr = listener.local_addr().expect("local_addr after bind");

    let server = async {
        let (tcp, _) = listener.accept().await.expect("accept mock websocket tcp");
        // `Peer::from_websocket` is typed for `MaybeTlsStream<TcpStream>` (same as `connect_async`).
        let ws = accept_async(MaybeTlsStream::Plain(tcp))
            .await
            .expect("websocket accept");
        Peer::from_websocket(ws, PeerOptions::default()).expect("server Peer::from_websocket")
    };

    let client = async {
        let url = format!("ws://127.0.0.1:{}/", addr.port());
        let (ws, _) = connect_async(url.as_str())
            .await
            .expect("client websocket connect");
        Peer::from_websocket(ws, PeerOptions::default()).expect("client Peer::from_websocket")
    };

    let (server_res, client_res) = tokio::join!(server, client);
    let (server_peer, server_rx) = server_res;
    let (client_peer, client_rx) = client_res;

    let (peer, inbound_rx) = if is_outbound {
        // Drop server half — we model the outbound-initiator (`ws` client) side.
        drop((server_peer, server_rx));
        (client_peer, client_rx)
    } else {
        drop((client_peer, client_rx));
        (server_peer, server_rx)
    };

    let address = peer.socket_addr();
    PeerConnection {
        peer,
        peer_id: random_peer_id(),
        address,
        is_outbound,
        node_type: NodeType::FullNode,
        protocol_version: "0.0.35".to_string(),
        software_version: "dig-gossip/0.1.0".to_string(),
        peer_server_port: address.port(),
        capabilities: Vec::new(),
        creation_time: unix_secs(),
        bytes_read: 0,
        bytes_written: 0,
        last_message_time: unix_secs(),
        reputation: PeerReputation::default(),
        inbound_rx,
    }
}

/// Temporary directory for certs, peer files, etc. — cleans up on drop (`tempfile` crate).
pub fn test_temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempfile::tempdir for STR-005 harness")
}

/// Fixed test [`Bytes32`] used as `network_id` in [`test_gossip_config`].
pub fn test_network_id() -> Bytes32 {
    Bytes32::from(DIG_TESTNET_NETWORK_ID)
}

/// [`Network`] with **empty** DNS introducers so unit tests never hit the public internet (DSC-003).
///
/// Genesis / port values follow testnet11 as a convenient Chia baseline; only `dns_introducers`
/// is cleared per STR-005 “disabled for tests”.
pub fn test_network() -> Network {
    let mut n = Network::default_testnet11();
    n.dns_introducers.clear();
    n
}

/// [`GossipConfig`] tuned for local integration tests (localhost, small limits, paths under `temp_dir`).
///
/// **STR-005 alignment:** `listen_addr` uses port `0` for OS assignment; `target_outbound_count`
/// and `max_connections` match the STR-005 example (`2` / `10`). [`PeerOptions`] uses defaults
/// from `chia-sdk-client`.
pub fn test_gossip_config(temp_dir: &Path) -> GossipConfig {
    GossipConfig {
        listen_addr: "127.0.0.1:0".parse().expect("parse 127.0.0.1:0"),
        peer_id: random_peer_id(),
        network_id: test_network_id(),
        network: test_network(),
        target_outbound_count: 2,
        max_connections: 10,
        bootstrap_peers: Vec::new(),
        introducer: None,
        relay: None,
        cert_path: temp_dir.join("test.crt").to_string_lossy().into_owned(),
        key_path: temp_dir.join("test.key").to_string_lossy().into_owned(),
        peer_connect_interval: 1,
        gossip_fanout: 3,
        max_seen_messages: 1000,
        peers_file_path: temp_dir.join("peers.dat"),
        peer_options: PeerOptions::default(),
    }
}

/// Write PEM TLS material via [`ChiaCertificate::generate`] (chia-ssl).
///
/// Returns `(cert_path, key_path)` as UTF-8 strings for [`load_ssl_cert`] and for
/// [`GossipConfig::cert_path`] / `key_path`.
pub fn generate_test_certs(dir: &Path) -> (String, String) {
    let cert = ChiaCertificate::generate().expect("ChiaCertificate::generate");
    let cert_path = dir.join("test.crt");
    let key_path = dir.join("test.key");
    std::fs::write(&cert_path, &cert.cert_pem).expect("write cert pem");
    std::fs::write(&key_path, &cert.key_pem).expect("write key pem");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

/// Compose two temp dirs + configs and return **placeholder** [`GossipHandle`]s with resolved
/// bind addresses.
///
/// **Gap (documented):** Full bidirectional gossip traffic still needs **CON-001**. After API-001,
/// this helper builds two real [`GossipService`] values, calls [`GossipService::start`], and
/// returns the handles plus ephemeral bind addresses used only to prove distinct OS ports.
pub async fn connected_test_pair() -> (GossipHandle, GossipHandle, SocketAddr, SocketAddr) {
    let dir_a = test_temp_dir();
    let dir_b = test_temp_dir();
    let _ = generate_test_certs(dir_a.path());
    let _ = generate_test_certs(dir_b.path());
    let cfg_a = test_gossip_config(dir_a.path());
    let cfg_b = test_gossip_config(dir_b.path());

    let la = TcpListener::bind(cfg_a.listen_addr)
        .await
        .expect("listener a");
    let lb = TcpListener::bind(cfg_b.listen_addr)
        .await
        .expect("listener b");
    let addr_a = la.local_addr().expect("local addr a");
    let addr_b = lb.local_addr().expect("local addr b");
    drop(la);
    drop(lb);

    let sa = GossipService::new(cfg_a).expect("GossipService::new a");
    let sb = GossipService::new(cfg_b).expect("GossipService::new b");
    let ha = sa.start().await.expect("start a");
    let hb = sb.start().await.expect("start b");
    drop(sa);
    drop(sb);

    (ha, hb, addr_a, addr_b)
}
