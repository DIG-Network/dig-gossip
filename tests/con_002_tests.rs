//! Integration tests for **CON-002: inbound connection listener**.
//!
//! ## Traceability
//!
//! - **Spec + matrix:** [`CON-002.md`](../docs/requirements/domains/connection/specs/CON-002.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/connection/NORMATIVE.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §5.2
//!
//! ## Proof strategy
//!
//! Each test name maps to a **Test Plan** row in CON-002. We start a real [`GossipService`] (TLS from
//! [`dig_gossip::load_ssl_cert`]), call [`GossipService::start`] so [`TcpListener`] binds and
//! [`dig_gossip::connection::listener::accept_loop`] runs, then drive one or more outbound
//! [`GossipHandle::connect_to`] (or a raw WSS client where we must send invalid handshake bytes).
//!
//! **Hooks:** [`GossipHandle::__listen_bound_addr_for_tests`], [`GossipHandle::__con002_live_peer_meta_for_tests`],
//! [`GossipHandle::__con001_last_address_batch_for_tests`] map to observable CON-002 side effects.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use chia_traits::Streamable;
use dig_gossip::{
    create_native_tls_connector, load_ssl_cert, Bytes32, GossipHandle, GossipService, Handshake,
    Message, NodeType, PeerId, ProtocolMessageTypes, RespondPeers,
};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMsg;

#[cfg(not(target_os = "windows"))]
use dig_gossip::peer_id_from_tls_spki_der;
#[cfg(not(target_os = "windows"))]
use dig_gossip::{ChiaCertificate, GossipConfig};
#[cfg(not(target_os = "windows"))]
use x509_parser::pem::Pem;

/// Decode the first X.509 certificate in a PEM bundle and derive the gossip [`PeerId`]
/// using the same SPKI-hash rule that the live TLS path uses (API-005).
///
/// This is used by `test_inbound_self_connection_reject` to manufacture a server whose
/// `peer_id` matches the connecting client's TLS certificate, simulating a self-connection
/// at the identity level.
#[cfg(not(target_os = "windows"))]
fn peer_id_from_chia_cert(cert: &ChiaCertificate) -> PeerId {
    let pem = Pem::iter_from_buffer(cert.cert_pem.as_bytes())
        .next()
        .expect("at least one PEM block")
        .expect("parse pem");
    let (_, x509) = x509_parser::parse_x509_certificate(&pem.contents).expect("parse x509");
    peer_id_from_tls_spki_der(x509.tbs_certificate.subject_pki.raw)
}

/// Build a [`GossipConfig`] with a specific `peer_id` override. Used by
/// `test_inbound_self_connection_reject` to force the server's identity to match the
/// client's TLS cert.
#[cfg(not(target_os = "windows"))]
fn server_config_with_peer_id(temp_dir: &std::path::Path, peer_id: PeerId) -> GossipConfig {
    let mut cfg = common::test_gossip_config(temp_dir);
    cfg.peer_id = peer_id;
    cfg
}

/// Start a full [`GossipService`] (TLS listener, accept loop) and return handles plus the
/// actual bound address.
///
/// Returns `(temp_dir, service, handle, bound_addr)`. The temp dir owns the TLS cert
/// files and must be kept alive for the duration of the test. Used by every CON-002 test
/// as the "server" side.
async fn running_server() -> (tempfile::TempDir, GossipService, GossipHandle, SocketAddr) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("GossipService::new");
    let h = svc.start().await.expect("start");
    let bound = h
        .__listen_bound_addr_for_tests()
        .expect("listen addr after start");
    (dir, svc, h, bound)
}

/// Start a separate [`GossipService`] that acts as the "client" / outbound peer. It has
/// its own TLS identity (different cert/key) so the server sees it as a distinct peer.
///
/// Returns `(temp_dir, handle)`. Used by tests that need a real outbound `connect_to`
/// against the server started by [`running_server`].
async fn outbound_client_handle() -> (tempfile::TempDir, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("client new");
    let h = svc.start().await.expect("client start");
    (dir, h)
}

/// **Row:** `test_inbound_listener_bind` — the `TcpListener` binds to the configured
/// address and the OS assigns a non-zero ephemeral port (SPEC Section 5.2, acceptance:
/// "`TcpListener` binds to `config.listen_addr`").
///
/// **How the test simulates the inbound flow:** We start the server via `running_server()`,
/// which calls `GossipService::start()`. The accept loop internally calls
/// `TcpListener::bind("127.0.0.1:0")`.
/// **Assertion 1:** `bound.port() != 0` — the OS replaced port 0 with a real ephemeral port.
/// **Assertion 2:** `bound.ip() == "127.0.0.1"` — the listener is on localhost only.
/// **Security property:** Binding to `127.0.0.1` (not `0.0.0.0`) ensures test listeners
/// are not externally reachable. The non-zero port confirms the bind succeeded (a port-0
/// return would mean the listener never actually bound).
#[tokio::test]
async fn test_inbound_listener_bind() {
    let (_d, _svc, _h, bound) = running_server().await;
    // OS must have assigned a real ephemeral port (not 0).
    assert_ne!(
        bound.port(),
        0,
        "binding to 127.0.0.1:0 must yield ephemeral port"
    );
    // Must be localhost — test listeners should not be externally reachable.
    assert_eq!(bound.ip().to_string(), "127.0.0.1");
}

/// **Row:** `test_inbound_tls_handshake` + `test_inbound_websocket_upgrade` +
/// `test_inbound_handshake_exchange` — a single end-to-end test that verifies the full
/// inbound connection pipeline: TCP accept, TLS handshake, WebSocket upgrade, and
/// bidirectional Chia `Handshake` exchange (SPEC Section 5.2 steps 1-7).
///
/// **How the mock client simulates a real peer:** `outbound_client_handle()` creates a
/// second `GossipService` with its own TLS identity, then calls `connect_to(bound)` which
/// performs real TLS + WSS + Chia handshake against the server's listener.
///
/// **Note:** `connect_to` returns the *remote* peer's `PeerId` (the server's TLS id).
/// The *server's* peer map is keyed by the *inbound client's* id — we query it via
/// `__peer_ids_for_tests()`.
///
/// **Assertions:**
/// - `remote_pid != PeerId::default()`: the client received a valid server identity.
/// - `keys.len() == 1`: the server registered exactly one inbound peer.
/// - `meta.0.ip() == bound.ip()`: the registered address matches the listener.
/// - `meta.1 == false` (`is_outbound`): the server correctly tagged the connection as
///   inbound.
/// **Security property:** The bidirectional handshake ensures both sides exchanged their
/// `network_id`, `protocol_version`, and `node_type` before the peer is registered.
#[tokio::test]
async fn test_inbound_tls_websocket_and_handshake() {
    let (_ds, _svc, server_h, bound) = running_server().await;
    let (_dc, client_h) = outbound_client_handle().await;
    // Full pipeline: TCP -> TLS -> WSS -> Chia Handshake.
    let remote_pid = client_h
        .connect_to(bound)
        .await
        .expect("inbound full flow accepts outbound peer");
    // Client must have received a valid server PeerId (derived from TLS SPKI).
    assert_ne!(remote_pid, PeerId::default());
    // Server's peer map should contain exactly one inbound peer.
    let keys = server_h.__peer_ids_for_tests();
    assert_eq!(
        keys.len(),
        1,
        "server should register exactly one inbound peer"
    );
    let meta = server_h
        .__con002_live_peer_meta_for_tests(keys[0])
        .expect("server registered live slot");
    // The registered IP must match the listener's bind address.
    assert_eq!(meta.0.ip(), bound.ip());
    // CON-002 Step 7: inbound connections must have is_outbound = false.
    assert!(!meta.1, "inbound slot must set is_outbound = false");
}

/// **Row:** `test_inbound_network_id_reject` — the server closes the session when the
/// connecting peer's `Handshake.network_id` does not match the server's configured
/// `network_id` (SPEC Section 5.2 step 5, acceptance: "`network_id` is validated
/// against the local config (rejects mismatch)").
///
/// **How the mock client simulates a real peer:** We bypass `GossipHandle::connect_to`
/// and instead open a raw `wss://` connection using `tokio_tungstenite`, then manually
/// send a `Handshake` message with a fabricated `network_id` (`[0x42; 32]`). This
/// isolates the server's network-id validation from any client-side logic.
///
/// **What security property the assertion proves:** Cross-network isolation. If a mainnet
/// node accepted a testnet peer's handshake, gossip messages from different networks
/// would mix, causing chain-split confusion. The `peer_count() == 0` assertion proves
/// the server rejected the peer entirely (it is not registered in the peer map).
///
/// **Why the test waits for `ws.next()`:** The server may send a close frame or simply
/// drop the socket; either way, the 2-second timeout ensures we do not hang.
#[tokio::test]
async fn test_inbound_network_id_reject() {
    let (_ds, _svc, server_h, bound) = running_server().await;
    let client_dir = common::test_temp_dir();
    let (c, k) = common::generate_test_certs(client_dir.path());
    let client_tls = load_ssl_cert(&c, &k).expect("client tls");
    let connector = create_native_tls_connector(&client_tls).expect("connector");
    let uri = format!("wss://{bound}/ws");
    // Step 1-3: TCP + TLS + WebSocket — these succeed (the reject happens at Step 5).
    let (mut ws, _) = tokio_tungstenite::connect_async_tls_with_config(
        uri.as_str(),
        None,
        false,
        Some(connector),
    )
    .await
    .expect("tls + ws connect");

    // Craft a Handshake with a WRONG network_id (0x42 repeated, not the server's id).
    let bad_net = Bytes32::from([0x42u8; 32]).to_string();
    let hs = Handshake {
        network_id: bad_net.clone(),
        protocol_version: "0.0.37".to_string(),
        software_version: "test/1".to_string(),
        server_port: 0,
        node_type: NodeType::FullNode,
        capabilities: vec![],
    };
    let wire = Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: hs.to_bytes().expect("hs").into(),
    };
    ws.send(WsMsg::Binary(wire.to_bytes().expect("msg")))
        .await
        .ok();

    // Wait for the server to process and reject (close frame or socket drop).
    let _ = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .ok();

    // The server must NOT register this peer — wrong network_id means full rejection.
    assert_eq!(
        server_h.peer_count().await,
        0,
        "server must not register peer after WrongNetwork"
    );
}

/// **Row:** `test_inbound_peer_connection_wrapping` — inbound peers are wrapped with
/// `is_outbound = false` metadata (SPEC Section 5.2 step 7, acceptance: "The connection
/// is wrapped in `PeerConnection` with `is_outbound: false`").
///
/// **How the mock client simulates a real peer:** `outbound_client_handle().connect_to(bound)`
/// completes a full TLS + WSS + Handshake flow against the server.
/// **What security property the assertion proves:** Direction correctness. If inbound peers
/// were tagged as outbound, the node would over-count its outbound capacity, potentially
/// refusing to initiate needed outbound connections. The `is_outbound = false` tag also
/// controls whether the peer's address is shared via `RespondPeers` (only outbound peers'
/// self-reported `server_port` is trusted).
#[tokio::test]
async fn test_inbound_peer_connection_wrapping() {
    let (_ds, _svc, server_h, bound) = running_server().await;
    let (_dc, client_h) = outbound_client_handle().await;
    client_h.connect_to(bound).await.expect("connect");
    let keys = server_h.__peer_ids_for_tests();
    let (_, is_out) = server_h
        .__con002_live_peer_meta_for_tests(keys[0])
        .expect("wrapped peer");
    // Inbound connections MUST be tagged is_outbound=false for correct direction accounting.
    assert!(
        !is_out,
        "CON-002 requires PeerConnection-style metadata with is_outbound=false for inbound"
    );
}

/// **Row:** `test_inbound_address_manager_add` — when an inbound peer completes the
/// handshake, the server adds the peer's address to the address manager's "new" table
/// (SPEC Section 5.2 step 8, acceptance: "Peer is added to address manager 'new' table",
/// mirrors `node_discovery.py:120-125`).
///
/// **How the mock client simulates a real peer:** `outbound_client_handle().connect_to(bound)`
/// completes the full inbound flow on the server.
/// **What the assertion proves:**
/// - `src.host == bound.ip()` and `src.port == bound.port()`: the source peer info
///   (our own listener address) is correctly passed to `add_to_new_table`, which uses
///   it for source-group bucketing (preventing Sybil attacks from a single source).
/// - `batch.len() == 1`: exactly one peer address is added per inbound connection.
/// - `batch[0].host == "127.0.0.1"`: the inbound peer's IP is correctly extracted
///   from the TCP socket address.
/// **Security property:** Address manager integration ensures the gossip network learns
/// about new peers organically through inbound connections, not just through explicit
/// `RequestPeers` exchanges.
#[tokio::test]
async fn test_inbound_address_manager_add() {
    let (_ds, _svc, server_h, bound) = running_server().await;
    let (_dc, client_h) = outbound_client_handle().await;
    client_h.connect_to(bound).await.expect("connect");

    let (batch, src) = server_h
        .__con001_last_address_batch_for_tests()
        .expect("inbound should call add_to_new_table");

    // Source peer info = our own listener address (used for source-group bucketing).
    assert_eq!(src.host, bound.ip().to_string());
    assert_eq!(src.port, bound.port());
    // Exactly one new address added per inbound connection.
    assert_eq!(batch.len(), 1);
    // The new peer's IP comes from the TCP socket, which is localhost in tests.
    assert_eq!(batch[0].host, "127.0.0.1");
}

/// **Row:** `test_inbound_peer_info_relay` — when a second peer connects, the server relays
/// the newcomer's address to the first peer via `RespondPeers` (SPEC Section 5.2 step 9,
/// acceptance: "Peer info is relayed to other connected peers", mirrors
/// `node_discovery.py:126-127`).
///
/// **How the mock clients simulate real peers:**
/// 1. `hb` connects first and subscribes to the server's inbound broadcast hub.
/// 2. `hc` connects second — this triggers the server to relay `hc`'s address to `hb`.
///
/// **What the assertion proves:** The first peer (`hb`) receives a `RespondPeers` message
/// containing exactly one entry with `host == "127.0.0.1"` — the second peer's address.
/// This proves the server's `relay_peer_info` logic fires on every new inbound connection.
///
/// **Security property:** Peer-info relay is how the gossip network propagates address
/// knowledge. Without it, nodes would only learn about peers they directly connect to
/// or discover via the introducer.
///
/// **Why the 10-second deadline:** The relay is asynchronous (spawned task); we poll the
/// subscription channel with a generous timeout to avoid flaky failures on slow CI.
#[tokio::test]
async fn test_inbound_peer_info_relay() {
    let (_ds, _svc, _server_h, bound) = running_server().await;
    // First peer connects and subscribes to inbound messages.
    let (_db, hb) = outbound_client_handle().await;
    hb.connect_to(bound).await.expect("first peer");

    let mut sub = hb.inbound_receiver().expect("subscribe");

    // Second peer connects — this should trigger relay to the first peer.
    let (_dc, hc) = outbound_client_handle().await;
    hc.connect_to(bound).await.expect("second peer");

    // Poll the subscription for the relayed RespondPeers message.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut saw_relay = false;
    while tokio::time::Instant::now() < deadline {
        let Ok((_sender, msg)) = sub.recv().await else {
            break;
        };
        if msg.msg_type == ProtocolMessageTypes::RespondPeers {
            let body = RespondPeers::from_bytes(&msg.data).expect("RespondPeers");
            // The relay should contain exactly the second peer's address.
            if body.peer_list.len() == 1 && body.peer_list[0].host == "127.0.0.1" {
                saw_relay = true;
                break;
            }
        }
    }
    assert!(
        saw_relay,
        "first peer should receive RespondPeers relay per CON-002 Peer Info Relay"
    );
}

/// **Row:** `test_inbound_max_connections` — when the server is at capacity
/// (`max_connections = 1`), further inbound attempts do not increase `peer_count`
/// (SPEC Section 5.2, acceptance: "Max connections: reject inbound connections when
/// `max_connections` is reached").
///
/// **How the mock clients simulate real peers:**
/// 1. `h1` connects first and fills the single slot (`peer_count == 1`).
/// 2. `h2` attempts to connect but the server is at capacity.
///
/// **What the assertion proves:** `server_h.peer_count() <= 1` — the server did not
/// register a second peer. The inequality (`<= 1` rather than `== 1`) accounts for
/// the race: the server may drop the TCP accept before TLS, or reject after TLS but
/// before handshake, both of which are valid rejection points.
///
/// **Security property:** The max-connections cap prevents resource exhaustion attacks.
/// Without it, an attacker could open unlimited inbound connections to consume file
/// descriptors and memory.
#[tokio::test]
async fn test_inbound_max_connections() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 1; // artificially low for test
    cfg.target_outbound_count = 1;
    let svc = GossipService::new(cfg).expect("new");
    let server_h = svc.start().await.expect("start");
    let bound = server_h.__listen_bound_addr_for_tests().unwrap();

    // First connection fills the single slot.
    let (_d1, h1) = outbound_client_handle().await;
    h1.connect_to(bound).await.expect("first allowed");
    assert_eq!(server_h.peer_count().await, 1);

    // Second connection must be rejected (server at capacity).
    let (_d2, h2) = outbound_client_handle().await;
    let _ = h2.connect_to(bound).await;
    // Server drops excess before or after TLS; client may see ClientError or I/O failure.
    assert!(
        server_h.peer_count().await <= 1,
        "server must not exceed max_connections"
    );
}

/// **Row:** `test_inbound_self_connection_reject` — the server rejects an inbound
/// connection whose TLS `PeerId` matches the server's own `peer_id` (SPEC Section 5.2,
/// acceptance: "Self-connection detection: reject if peer_id matches our own").
///
/// **Platform:** Skipped on Windows — SChannel does not expose remote leaf certs without
/// client-auth negotiation; see listener module docs and CON-009.
///
/// **How the test creates the precondition:** We generate a *separate* client TLS cert,
/// derive its `PeerId` via `peer_id_from_chia_cert`, then configure the *server* with
/// that same `peer_id`. This makes the server think the connecting client has the same
/// identity as itself, even though they have different cert/key material.
///
/// **What security property the assertion proves:** Self-connection prevention at the TLS
/// identity level. In production, a node might discover its own address via the
/// introducer or peer exchange. Without this guard, it would waste a connection slot
/// talking to itself in a no-op loop. The `peer_count() == 0` assertion proves the
/// connection was fully rejected (not just logged as suspicious).
///
/// **Why the test checks both `res.is_err()` and `res.unwrap().is_err()`:** The rejection
/// may happen at the TLS level (connection refused) or after the WebSocket upgrade
/// (server closes the socket during handshake validation). Either failure mode is
/// acceptable.
#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn test_inbound_self_connection_reject() {
    let server_dir = common::test_temp_dir();
    let (sc, sk) = common::generate_test_certs(server_dir.path());
    let client_dir = common::test_temp_dir();
    let (cc, ck) = common::generate_test_certs(client_dir.path());
    let client_tls = load_ssl_cert(&cc, &ck).expect("client tls");
    // Derive the client's PeerId from its TLS cert.
    let client_derived_id = peer_id_from_chia_cert(&client_tls);

    // Configure the server to use the CLIENT's PeerId as its own identity.
    let mut cfg = server_config_with_peer_id(server_dir.path(), client_derived_id);
    cfg.cert_path = sc;
    cfg.key_path = sk;

    let svc = GossipService::new(cfg).expect("new");
    let server_h = svc.start().await.expect("start");
    let bound = server_h.__listen_bound_addr_for_tests().unwrap();

    // Connect with the client cert whose PeerId matches the server's configured peer_id.
    let connector = create_native_tls_connector(&client_tls).expect("connector");
    let uri = format!("wss://{bound}/ws");
    let connect = tokio_tungstenite::connect_async_tls_with_config(
        uri.as_str(),
        None,
        false,
        Some(connector),
    );
    let res = tokio::time::timeout(Duration::from_secs(5), connect).await;
    // Rejection may happen at TLS or handshake level — either is acceptable.
    assert!(
        res.is_err() || res.unwrap().is_err(),
        "self-id inbound must fail TLS or handshake path"
    );
    // The server must not have registered this self-connection.
    assert_eq!(server_h.peer_count().await, 0);
}
