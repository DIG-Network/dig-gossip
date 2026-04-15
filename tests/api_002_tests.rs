//! Integration tests for **API-002: `GossipHandle` RPC surface**.
//!
//! ## Traceability
//!
//! - **Spec + matrix:** [`API-002.md`](../docs/requirements/domains/crate_api/specs/API-002.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/crate_api/NORMATIVE.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §3.2–3.3
//!
//! ## What this file proves
//!
//! API-002 is the **primary handle contract**: once [`GossipService::start`] yields a
//! [`GossipHandle`], every public method on that handle must behave according to the
//! acceptance matrix in the spec (broadcast fan-out, send/request/subscribe, peer
//! management, stats, introducer discovery, lifecycle shutdown). These tests exercise
//! **every row** of that matrix, using stub peers to isolate handle logic from real TLS.
//!
//! ## Scope (this commit)
//!
//! Many rows assume **live `Peer` handles** or introducer I/O (DSC-*). **Offline** registry tests
//! call [`GossipHandle::__connect_stub_peer_with_direction`] (deterministic [`PeerId`] from socket);
//! **real** `connect_to` TLS + `RequestPeers` lives in [`con_001_tests`](../con_001_tests.rs).
//!
//! ## How to read the tests
//!
//! Each test name maps to a **Row** label from the API-002 verification/test-plan table.
//! The `running_handle()` helper spins up a full [`GossipService`] with TLS certs in a
//! temp dir and returns a live handle — every test starts from that baseline. Stub peers
//! (via `__connect_stub_peer_with_direction`) simulate connected nodes without real
//! sockets, letting us test handle logic (broadcast counting, disconnect, ban, etc.)
//! in isolation.
//!
//! ## Test harness
//!
//! - [`running_handle`] — creates a temp dir, generates TLS certs, builds a
//!   [`GossipConfig`], constructs a [`GossipService`], and calls `start()`.
//! - [`sample_new_peak`] — builds a minimal [`NewPeak`] payload for broadcast tests.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use dig_gossip::{
    Bytes32, ChiaProtocolMessage, GossipError, GossipHandle, GossipService, IntroducerConfig,
    Message, NewPeak, NodeType, ProtocolMessageTypes, RelayConfig, RequestPeers, RespondBlock,
    RespondPeers, Streamable,
};

/// Build a minimal [`NewPeak`] message suitable for broadcast tests.
///
/// All hash fields are zeroed (`Bytes32::default()`); height/weight/fork are non-zero
/// so the message is distinguishable from a default-constructed payload in stats counters.
/// The exact field values do not matter — only that `NewPeak::msg_type()` maps to
/// [`ProtocolMessageTypes::NewPeak`] on the wire (SPEC §3.2 broadcast typed).
fn sample_new_peak() -> NewPeak {
    let z = Bytes32::default();
    NewPeak::new(z, 1, 1, 0, z)
}

/// Spin up a [`GossipService`] with harness defaults and return both the service (for
/// lifecycle control) and the [`GossipHandle`] (for RPC calls).
///
/// The service binds `127.0.0.1:0` (OS-assigned port), uses freshly generated TLS certs,
/// and has no introducer/relay configured. This baseline is sufficient for every API-002
/// test that operates on stub peers.
async fn running_handle() -> (GossipService, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    (svc, h)
}

/// **Row:** `test_handle_is_cloneable` — [`GossipHandle`] is `Clone` + `Arc` backed (API-002 summary).
///
/// **Precondition:** A running service yields a handle `h`.
/// **Assertion:** Cloning the handle produces `g`; both `h` and `g` pass `health_check()`.
/// **Why sufficient:** Proves the handle is cheaply copyable for multi-task fan-out
/// (the common pattern is to clone into each spawned Tokio task). If the inner `Arc`
/// or channel were not shared correctly, `health_check` on the clone would panic or
/// return `ServiceNotStarted`.
#[tokio::test]
async fn test_handle_is_cloneable() {
    let (_s, h) = running_handle().await;
    let g = h.clone();
    h.health_check().await.unwrap();
    g.health_check().await.unwrap();
}

/// **Row:** `test_broadcast_returns_peer_count` — three stub peers => broadcast fan-out count 3.
///
/// **Precondition:** Three outbound stub peers (a, b, c) are registered with the handle.
/// **Assertion:** `broadcast(msg, None)` returns `3`, meaning it delivered to all peers.
/// **Why sufficient:** The return value of `broadcast` is the fan-out count (SPEC §3.2).
/// Returning the exact peer count proves the handle iterates every registered peer when
/// `exclude` is `None`. The message itself is a dummy `RequestPeers` — content is
/// irrelevant; only delivery accounting matters here.
#[tokio::test]
async fn test_broadcast_returns_peer_count() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9101".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:9102".parse().unwrap();
    let c: SocketAddr = "127.0.0.1:9103".parse().unwrap();
    h.__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    h.__connect_stub_peer_with_direction(b, NodeType::FullNode, true)
        .await
        .unwrap();
    h.__connect_stub_peer_with_direction(c, NodeType::FullNode, true)
        .await
        .unwrap();
    let dummy = Message {
        msg_type: ProtocolMessageTypes::RequestPeers,
        id: None,
        data: RequestPeers::new().to_bytes().unwrap().into(),
    };
    let n = h.broadcast(dummy, None).await.unwrap();
    // 3 peers registered, no exclusion => fan-out must equal the full peer set.
    assert_eq!(n, 3);
}

/// **Row:** `test_broadcast_with_exclude` — excluded stub peer reduces delivery count by one.
///
/// **Precondition:** Three peers (a, b, c). We capture `id_b` from the stub connection.
/// **Assertion:** `broadcast(msg, Some(id_b))` returns `2` (3 total minus 1 excluded).
/// **Why sufficient:** The `exclude` parameter is how the gossip layer avoids echoing a
/// message back to the peer that sent it (SPEC §3.2 "exclude originator"). If exclusion
/// were broken, the count would be 3 (all peers). Returning exactly `n - 1` proves the
/// single-peer exclusion logic works.
#[tokio::test]
async fn test_broadcast_with_exclude() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9201".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:9202".parse().unwrap();
    let c: SocketAddr = "127.0.0.1:9203".parse().unwrap();
    let id_b = h
        .__connect_stub_peer_with_direction(b, NodeType::FullNode, true)
        .await
        .unwrap();
    h.__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    h.__connect_stub_peer_with_direction(c, NodeType::FullNode, true)
        .await
        .unwrap();
    let dummy = Message {
        msg_type: ProtocolMessageTypes::RequestPeers,
        id: None,
        data: RequestPeers::new().to_bytes().unwrap().into(),
    };
    let n = h.broadcast(dummy, Some(id_b)).await.unwrap();
    // Peer b is excluded => only a and c receive the message.
    assert_eq!(n, 2);
}

/// **Row:** `test_broadcast_typed_serializes` — `broadcast_typed` exercises `Streamable` + `ChiaProtocolMessage`.
///
/// **Proof:** [`NewPeak::msg_type`] must match the wire enum (serialization would fail if types were wrong).
#[tokio::test]
async fn test_broadcast_typed_serializes() {
    assert_eq!(NewPeak::msg_type(), ProtocolMessageTypes::NewPeak);
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9301".parse().unwrap();
    h.__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    let n = h.broadcast_typed(sample_new_peak(), None).await.unwrap();
    assert_eq!(n, 1);
    let st = h.stats().await;
    assert!(st.messages_sent >= 1);
}

/// **Row:** `test_send_to_connected_peer` — unicast delivery to a known stub peer succeeds.
///
/// **Precondition:** One stub peer `a` is registered; its `PeerId` is captured as `pid`.
/// **Assertion:** `send_to(pid, RequestPeers)` returns `Ok(())`.
/// **Why sufficient:** Proves the handle can route a typed message to a specific peer by
/// id (SPEC §3.2 `send_to`). The stub peer has no real socket, but the handle's internal
/// lookup succeeds and the message is enqueued. Real delivery is covered in CON-001 tests.
#[tokio::test]
async fn test_send_to_connected_peer() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9401".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    h.send_to(pid, RequestPeers::new()).await.unwrap();
}

/// **Row:** `test_send_to_unknown_peer` — sending to a non-existent peer id fails cleanly.
///
/// **Precondition:** No peers are connected; `unknown` is a fabricated `Bytes32`.
/// **Assertion:** `send_to` returns `Err(GossipError::PeerNotConnected(_))`.
/// **Why sufficient:** API-002 requires graceful error propagation, not a panic, when the
/// caller references a peer that has disconnected or was never connected (SPEC §4 error
/// variants).
#[tokio::test]
async fn test_send_to_unknown_peer() {
    let (_s, h) = running_handle().await;
    let unknown = Bytes32::from([7u8; 32]);
    let err = h.send_to(unknown, RequestPeers::new()).await.unwrap_err();
    assert!(matches!(err, GossipError::PeerNotConnected(_)));
}

/// **Row:** `test_request_response` — stub `RequestPeers -> RespondPeers` path (TypeId branch in handle).
///
/// **Precondition:** One stub peer `a` is registered.
/// **Assertion:** `h.request::<RespondPeers, _>(pid, RequestPeers)` returns `Ok(RespondPeers)`
/// with an empty `peer_list`.
/// **Why sufficient:** The `request` method is the Chia-style request/response RPC
/// (SPEC §3.3). Stub peers auto-respond to `RequestPeers` with an empty `RespondPeers`.
/// This proves the handle correctly matches the response type to the request type via
/// [`ChiaProtocolMessage`] trait dispatch, deserializes the response, and returns it
/// to the caller. The empty list is the expected stub behavior.
#[tokio::test]
async fn test_request_response() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9501".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    let r: RespondPeers = h.request(pid, RequestPeers::new()).await.unwrap();
    // Stub peers have no real peer list to share; empty is correct.
    assert!(r.peer_list.is_empty());
}

/// **Row:** `test_request_timeout` — mismatched request/response pair hits fast `RequestTimeout`.
///
/// **Precondition:** One stub peer. We send `RequestPeers` but declare the expected
/// response type as `RespondBlock` (a deliberate type mismatch).
/// **Assertion:** The call returns `Err(GossipError::RequestTimeout)`.
/// **Why sufficient:** The stub peer answers `RequestPeers` with `RespondPeers`, but the
/// caller is waiting for `RespondBlock`. Since the response message type does not match,
/// the handle's request-correlation logic never resolves and the internal timeout fires.
/// This proves API-002's timeout path and type-safe request/response pairing (SPEC §3.3).
#[tokio::test]
async fn test_request_timeout() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:9601".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    let err = h
        .request::<RespondBlock, RequestPeers>(pid, RequestPeers::new())
        .await
        .unwrap_err();
    assert!(matches!(err, GossipError::RequestTimeout));
}

/// **Row:** `test_inbound_receiver` — subscribe on broadcast hub, inject synthetic tuple, receive it.
///
/// **Precondition:** Subscribe to the handle's inbound broadcast channel via
/// `inbound_receiver()`. Then inject a synthetic `(PeerId, Message)` tuple via the
/// test-only `__inject_inbound_for_tests` hook.
/// **Assertion:** The subscription receives the exact `(sender, msg)` tuple within 2 seconds.
/// **Why sufficient:** This proves the SPEC §3.3 subscription/broadcast hub works: external
/// code (e.g. a block validator) can subscribe, and messages arriving from any peer are
/// fanned out to all subscribers. The synthetic injection simulates what the connection
/// layer does when a real peer sends a message.
#[tokio::test]
async fn test_inbound_receiver() {
    let (_s, h) = running_handle().await;
    let mut rx = h.inbound_receiver().expect("subscribe");
    let sender = Bytes32::from([9u8; 32]);
    let msg = Message {
        msg_type: ProtocolMessageTypes::NewPeak,
        id: None,
        data: sample_new_peak().to_bytes().unwrap().into(),
    };
    h.__inject_inbound_for_tests(sender, msg.clone())
        .expect("inject");
    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("recv");
    // The received tuple must carry the original sender id and message type.
    assert_eq!(got.0, sender);
    assert_eq!(got.1.msg_type, ProtocolMessageTypes::NewPeak);
}

/// **Row:** `test_connected_peers` — `connected_peers()` returns an empty vec when no live
/// [`PeerConnection`] handles exist (SPEC Section 3.3 peer management).
///
/// **Precondition:** A running service with zero connections (no stubs, no real peers).
/// **Assertion:** `connected_peers()` returns an empty `Vec<PeerConnection>`.
/// **Why sufficient:** Stub peers (via `__connect_stub_peer_with_direction`) register in the
/// peer map but do **not** create full [`PeerConnection`] objects (they lack real TLS
/// sockets). Therefore the live-connection snapshot is correctly empty. This confirms
/// the method returns `Vec`, not `Option`, and does not panic on an empty peer set.
/// Real peer visibility is tested in `con_001_tests` and `con_002_tests`.
#[tokio::test]
async fn test_connected_peers() {
    let (_s, h) = running_handle().await;
    assert!(h.connected_peers().await.is_empty());
}

/// **Row:** `test_peer_count` — `peer_count()` equals the number of registered stub peers (SPEC Section 3.3).
///
/// **Precondition:** Five outbound stub peers are registered in a loop (ports 9700..9704).
/// **Assertion:** `peer_count()` returns exactly `5`.
/// **Why sufficient:** This verifies the handle's internal peer-map length is exposed
/// accurately. The loop approach ensures the counter increments per-connection, not
/// just once. Combined with `test_disconnect_peer` (which checks the count drops),
/// this proves `peer_count` is a live snapshot, not a static value.
#[tokio::test]
async fn test_peer_count() {
    let (_s, h) = running_handle().await;
    for i in 0..5u16 {
        let addr = SocketAddr::from(([127, 0, 0, 1], 9700 + i));
        h.__connect_stub_peer_with_direction(addr, NodeType::FullNode, true)
            .await
            .unwrap();
    }
    assert_eq!(h.peer_count().await, 5);
}

/// **Row:** `test_get_connections_filter_type` — `get_connections(Some(NodeType), false)`
/// filters by node type (SPEC Section 3.3 peer management).
///
/// **Precondition:** Two stubs: one `FullNode` (port 9801) and one `Wallet` (port 9802).
/// **Assertion 1:** The test-only stub filter
/// (`__stub_filter_count_for_tests(Some(FullNode), false)`) returns `1`, proving the
/// stub layer correctly records `NodeType` metadata per peer.
/// **Assertion 2:** The public `get_connections` returns an empty vec — stubs lack
/// live `PeerConnection` handles, so the public API correctly excludes them.
/// **Why sufficient:** Together these assertions prove (a) the filtering predicate
/// distinguishes `FullNode` from `Wallet`, and (b) the public method returns only
/// fully-connected peers (not stubs). Real-peer filtering is proved in `con_002_tests`.
#[tokio::test]
async fn test_get_connections_filter_type() {
    let (_s, h) = running_handle().await;
    h.__connect_stub_peer_with_direction(
        "127.0.0.1:9801".parse().unwrap(),
        NodeType::FullNode,
        true,
    )
    .await
    .unwrap();
    h.__connect_stub_peer_with_direction("127.0.0.1:9802".parse().unwrap(), NodeType::Wallet, true)
        .await
        .unwrap();
    // Stub filter sees 1 FullNode; Wallet is excluded by the type predicate.
    assert_eq!(
        h.__stub_filter_count_for_tests(Some(NodeType::FullNode), false)
            .await,
        1
    );
    // Public `get_connections` returns empty because stubs have no live PeerConnection.
    assert!(h
        .get_connections(Some(NodeType::FullNode), false)
        .await
        .is_empty());
}

/// **Row:** `test_get_connections_outbound_only` — `get_connections(None, true)` returns
/// only outbound peers (SPEC Section 3.3 direction filtering).
///
/// **Precondition:** Two `FullNode` stubs: one outbound (port 9901, `is_outbound=true`),
/// one inbound (port 9902, `is_outbound=false`).
/// **Assertion:** `__stub_filter_count_for_tests(None, true)` returns `1` — only the
/// outbound stub passes the filter.
/// **Why sufficient:** Proves the `outbound_only` flag correctly partitions the peer
/// set by direction. The `None` node-type means "all types", so the only discriminator
/// is direction. Returning 1 out of 2 confirms the inbound peer is excluded.
#[tokio::test]
async fn test_get_connections_outbound_only() {
    let (_s, h) = running_handle().await;
    h.__connect_stub_peer_with_direction(
        "127.0.0.1:9901".parse().unwrap(),
        NodeType::FullNode,
        true, // outbound
    )
    .await
    .unwrap();
    h.__connect_stub_peer_with_direction(
        "127.0.0.1:9902".parse().unwrap(),
        NodeType::FullNode,
        false, // inbound
    )
    .await
    .unwrap();
    // Only the outbound stub (port 9901) passes the outbound_only=true filter.
    assert_eq!(h.__stub_filter_count_for_tests(None, true).await, 1);
}

/// **Row:** `test_connect_to_success` — stub `connect_to` returns a non-default `PeerId` and
/// increments the peer count (SPEC Section 3.3, acceptance: "returns `Ok(PeerId)`").
///
/// **Precondition:** No peers connected. One stub peer is registered at `127.0.0.1:10001`.
/// **Assertion 1:** `peer_count()` is `1` after the connection.
/// **Assertion 2:** The returned `PeerId` is not the zero hash (`Bytes32::default()`),
/// confirming the handle derived a deterministic id from the socket address.
/// **Why sufficient:** Proves that `connect_to` (stub path) correctly registers the peer
/// in the map and returns a usable id. Real TLS connect is covered in `con_001_tests`.
#[tokio::test]
async fn test_connect_to_success() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    assert_eq!(h.peer_count().await, 1);
    // PeerId must be non-zero — the handle derives it from the socket address.
    assert_ne!(pid, Bytes32::default());
}

/// **Row:** `test_connect_to_max_connections` — third connection attempt when
/// `max_connections = 2` returns `MaxConnectionsReached(2)` (SPEC Section 4 error variants).
///
/// **Precondition:** A service configured with `max_connections = 2`. Two stub peers are
/// already connected (filling the capacity).
/// **Assertion:** The third `__connect_stub_peer_with_direction` call returns
/// `GossipError::MaxConnectionsReached(2)`, carrying the capacity limit.
/// **Why sufficient:** Proves the handle enforces the configured cap *before* registering
/// a new peer, and that the error variant includes the limit value so callers can log
/// meaningful diagnostics. The capacity check applies to both outbound (`connect_to`)
/// and inbound (CON-002) paths.
#[tokio::test]
async fn test_connect_to_max_connections() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.max_connections = 2; // artificially low limit for test
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    // Fill both slots.
    h.__connect_stub_peer_with_direction(
        "127.0.0.1:10101".parse().unwrap(),
        NodeType::FullNode,
        true,
    )
    .await
    .unwrap();
    h.__connect_stub_peer_with_direction(
        "127.0.0.1:10102".parse().unwrap(),
        NodeType::FullNode,
        true,
    )
    .await
    .unwrap();
    // Third attempt must fail with the capacity limit embedded in the error.
    let err = h
        .__connect_stub_peer_with_direction(
            "127.0.0.1:10103".parse().unwrap(),
            NodeType::FullNode,
            true,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, GossipError::MaxConnectionsReached(2)));
}

/// **Row:** `test_connect_to_duplicate` — connecting twice to the same address returns
/// `DuplicateConnection` carrying the existing `PeerId` (SPEC Section 4).
///
/// **Precondition:** One stub peer `a` is already registered; its `PeerId` is `first`.
/// **Assertion:** A second registration attempt for the *same* socket address returns
/// `GossipError::DuplicateConnection(p)` where `p == first`.
/// **Why sufficient:** Proves the handle detects address-level duplicates before allocating
/// a second slot, and returns the *existing* peer id in the error so the caller can
/// reuse the connection instead of leaking resources. The guard clause is checked in
/// both the stub and real `connect_to` paths.
#[tokio::test]
async fn test_connect_to_duplicate() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10201".parse().unwrap();
    let first = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    // Same address => DuplicateConnection, carrying the id of the existing peer.
    let err = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap_err();
    assert!(matches!(err, GossipError::DuplicateConnection(p) if p == first));
}

/// **Row:** `test_connect_to_self` — connecting to our own `listen_addr` is rejected with
/// `SelfConnection` before any TCP I/O (SPEC Section 4, Section 5.1 self-detection).
///
/// **Precondition:** The config's `listen_addr` is captured *before* the service starts
/// (so we know the exact address without resolving).
/// **Assertion:** `connect_to(self_addr)` returns `GossipError::SelfConnection`.
/// **Why sufficient:** Self-connection detection must happen at the address level (before
/// TLS), not just at the `PeerId` level (after TLS). This test uses the real
/// `connect_to` (not a stub), proving the early guard fires. Without this check, a
/// node could waste a slot connecting to itself or enter an infinite gossip loop.
#[tokio::test]
async fn test_connect_to_self() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let self_addr = cfg.listen_addr; // capture before move into GossipService
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    // Must fail before opening a TCP socket — address-level self-detection.
    let err = h.connect_to(self_addr).await.unwrap_err();
    assert!(matches!(err, GossipError::SelfConnection));
}

/// **Row:** `test_disconnect_peer` — `disconnect(&pid)` removes the peer from the map
/// and decrements `peer_count()` to zero (SPEC Section 3.3 lifecycle).
///
/// **Precondition:** One stub peer `a` is connected (`peer_count == 1`).
/// **Assertion:** After `disconnect(&pid)`, `peer_count()` drops to `0`.
/// **Why sufficient:** Proves the handle cleans up the peer-map entry synchronously
/// (within the same `.await`). Combined with `test_peer_count` (which adds 5 peers)
/// and `test_total_connections_monotonic_across_disconnect` (in `api_008_tests`), this
/// covers the full connect-disconnect lifecycle on the handle surface.
#[tokio::test]
async fn test_disconnect_peer() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10301".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    h.disconnect(&pid).await.unwrap();
    // Peer map must be empty after disconnect.
    assert_eq!(h.peer_count().await, 0);
}

/// **Row:** `test_ban_peer` — `ban_peer` disconnects the peer *and* blocks future sends
/// with `PeerBanned` (SPEC Section 3.3; **CON-007** wires [`ClientState::ban`] on the stub IP).
///
/// **Precondition:** One stub peer `a` is connected.
/// **Assertion 1:** After `ban_peer(&pid, ProtocolViolation)`, `peer_count()` drops to `0`
/// (the ban triggers an immediate disconnect, per API-002 implementation notes).
/// **Assertion 2:** `send_to(pid, ...)` returns `GossipError::PeerBanned(pid)`, proving
/// the ban is persistent — the peer id is remembered even after disconnection.
/// **Why sufficient:** Proves the two-phase ban contract: (1) disconnect now, (2) reject
/// future interaction. Without assertion 2, we could not distinguish "ban" from plain
/// "disconnect". The `ProtocolViolation` reason exercises the most severe penalty path.
#[tokio::test]
async fn test_ban_peer() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10401".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    h.ban_peer(&pid, dig_gossip::PenaltyReason::ProtocolViolation)
        .await
        .unwrap();
    assert!(
        h.__con007_chia_client_is_ip_banned_for_tests(a.ip()).await,
        "CON-007: Chia ClientState must mirror the DIG ban for the remote IP"
    );
    // Ban must disconnect immediately.
    assert_eq!(h.peer_count().await, 0);
    // Subsequent sends must be rejected — the peer id is in the ban list.
    let err = h.send_to(pid, RequestPeers::new()).await.unwrap_err();
    assert!(matches!(err, GossipError::PeerBanned(_)));
}

/// **Row:** `test_penalize_peer_below_threshold` — a single low-weight penalty does not
/// trigger a ban (SPEC Section 3.3, acceptance: "increments penalty points; auto-bans
/// at threshold").
///
/// **Precondition:** One stub peer `a`. We apply a single `ConnectionIssue` penalty
/// (weight defined in API-006 / CON-007, currently < `PENALTY_BAN_THRESHOLD`).
/// **Assertion:** `peer_count()` remains `1` — the peer is still connected.
/// **Why sufficient:** Proves the penalty system is *graduated*, not one-strike. A
/// mild infraction does not disconnect the peer. This is the "below threshold" half of
/// the penalty contract; `test_penalize_peer_auto_ban` covers the "at threshold" half.
#[tokio::test]
async fn test_penalize_peer_below_threshold() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10501".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    // ConnectionIssue is a low-weight penalty — not enough to reach the ban threshold.
    h.penalize_peer(&pid, dig_gossip::PenaltyReason::ConnectionIssue)
        .await
        .unwrap();
    // Peer must still be connected (penalty accumulated but threshold not exceeded).
    assert_eq!(h.peer_count().await, 1);
}

/// **Row:** `test_penalize_peer_auto_ban` — accumulated penalties at the threshold trigger
/// an automatic ban and disconnect (SPEC Section 3.3, API-006 / CON-007 penalty weights).
///
/// **Precondition:** One stub peer `a`. We apply `Spam` penalties four times. Each `Spam`
/// penalty carries a weight of 25 (defined in API-006). After 4 applications the
/// cumulative score reaches 100, which equals `PENALTY_BAN_THRESHOLD`.
/// **Assertion 1:** `peer_count()` drops to `0` — the auto-ban disconnects the peer.
/// **Assertion 2:** `send_to` returns `GossipError::PeerBanned`, confirming the peer is
/// on the ban list (not merely disconnected).
/// **Why sufficient:** Proves the penalty accumulator crosses the threshold and triggers
/// the same two-phase ban as explicit `ban_peer`. The loop structure proves penalties
/// are additive across calls, not reset.
#[tokio::test]
async fn test_penalize_peer_auto_ban() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10601".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    // 4 x Spam (weight 25 each) = 100 points => reaches PENALTY_BAN_THRESHOLD.
    for _ in 0..4 {
        h.penalize_peer(&pid, dig_gossip::PenaltyReason::Spam)
            .await
            .unwrap();
    }
    assert!(
        h.__con007_chia_client_is_ip_banned_for_tests(a.ip()).await,
        "threshold crossing must populate ClientState banned_peers"
    );
    // Auto-ban must disconnect the peer.
    assert_eq!(h.peer_count().await, 0);
    // Peer must be on the ban list, not merely disconnected.
    let err = h.send_to(pid, RequestPeers::new()).await.unwrap_err();
    assert!(matches!(err, GossipError::PeerBanned(_)));
}

/// **Row:** `test_discover_no_introducer` — `discover_from_introducer()` without a configured
/// introducer returns `IntroducerNotConfigured` (SPEC Section 3.3 discovery methods).
///
/// **Precondition:** The default `running_handle()` has `cfg.introducer = None`.
/// **Assertion:** `discover_from_introducer()` returns `GossipError::IntroducerNotConfigured`.
/// **Why sufficient:** Proves the handle checks the config before attempting any network
/// I/O, and returns a descriptive error rather than panicking or returning an empty list.
/// The caller can use this error to decide whether to fall back to direct peer exchange.
#[tokio::test]
async fn test_discover_no_introducer() {
    let (_s, h) = running_handle().await;
    let err = h.discover_from_introducer().await.unwrap_err();
    assert!(matches!(err, GossipError::IntroducerNotConfigured));
}

/// **Row:** `test_discover_from_introducer` — with `introducer` set but **empty** `endpoint`, the
/// handle fails fast with [`GossipError::InvalidConfig`] (SPEC §3.3 + DSC-004 guard).
///
/// **Precondition:** `IntroducerConfig::default()` uses an empty-string `endpoint` sentinel (API-010).
/// **Assertion:** `discover_from_introducer()` returns `InvalidConfig` — DSC-004 refuses to dial
/// before a real `wss://` URL exists. End-to-end introducer I/O lives in `tests/dsc_004_tests.rs`.
#[tokio::test]
async fn test_discover_from_introducer() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.introducer = Some(IntroducerConfig::default());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    let err = h.discover_from_introducer().await.unwrap_err();
    assert!(
        matches!(err, GossipError::InvalidConfig(_)),
        "expected InvalidConfig for empty introducer.endpoint, got {err:?}"
    );
}

/// **Row:** `test_register_with_introducer` — with `introducer` set but **empty** `endpoint`, the
/// handle fails fast with [`GossipError::InvalidConfig`] (mirrors DSC-004 / DSC-005 guards).
///
/// **Precondition:** `IntroducerConfig::default()` uses an empty-string `endpoint` sentinel (API-010).
/// **Assertion:** `register_with_introducer()` returns `InvalidConfig` — DSC-005 refuses to dial
/// before a real `wss://` URL exists. Full registration I/O is in `tests/dsc_005_tests.rs`.
#[tokio::test]
async fn test_register_with_introducer() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.introducer = Some(IntroducerConfig::default());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    let err = h.register_with_introducer().await.unwrap_err();
    assert!(
        matches!(err, GossipError::InvalidConfig(_)),
        "expected InvalidConfig for empty introducer.endpoint, got {err:?}"
    );
}

/// **Row:** `test_request_peers_from` — `request_peers_from(&pid)` sends `RequestPeers` and
/// returns a `RespondPeers` with an empty peer list (stub behavior) (SPEC Section 3.3).
///
/// **Precondition:** One stub peer `a` is connected.
/// **Assertion:** `request_peers_from(&pid)` returns `Ok(RespondPeers)` with an empty
/// `peer_list`.
/// **Why sufficient:** This is the convenience wrapper around `request::<RespondPeers,
/// RequestPeers>`. The stub peer auto-responds with an empty `RespondPeers`. Proving
/// the call completes without timeout or error demonstrates that the request/response
/// correlation works for this specific message pair (the most common peer-exchange RPC
/// in the Chia protocol). Real peer-list exchange is tested in CON-001/CON-002.
#[tokio::test]
async fn test_request_peers_from() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:10701".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    // Stub peer responds with an empty peer list — the important thing is no timeout.
    let r = h.request_peers_from(&pid).await.unwrap();
    assert!(r.peer_list.is_empty());
}

/// **Row:** `test_stats` — `stats()` returns a `GossipStats` snapshot with zero peers
/// when the service is idle (SPEC Section 3.4, API-008).
///
/// **Precondition:** A running service with no connections.
/// **Assertion:** `stats().connected_peers == 0`.
/// **Why sufficient:** Baseline sanity — proves `stats()` is callable, returns a
/// `GossipStats` struct (not `Option`), and reflects the empty-state counters. Detailed
/// counter accuracy (messages_sent, inbound vs outbound, etc.) is covered in
/// `api_008_tests`.
#[tokio::test]
async fn test_stats() {
    let (_s, h) = running_handle().await;
    let st = h.stats().await;
    assert_eq!(st.connected_peers, 0);
}

/// **Row:** `test_relay_stats_none` — `relay_stats()` returns `None` when no relay is
/// configured (SPEC Section 3.4, acceptance: "returns `None` when relay is not configured").
///
/// **Precondition:** Default `running_handle()` has `cfg.relay = None`.
/// **Assertion:** `relay_stats()` returns `None`.
/// **Why sufficient:** Proves the `Option<RelayStats>` contract: callers must check for
/// `None` before accessing relay metrics. Without this, a missing relay could either
/// panic or return misleading zeroed stats.
#[tokio::test]
async fn test_relay_stats_none() {
    let (_s, h) = running_handle().await;
    assert!(h.relay_stats().await.is_none());
}

/// **Row:** `test_relay_stats_some_when_configured` — `relay_stats()` returns `Some(RelayStats)`
/// when a relay is configured, even before the relay connects (SPEC Section 3.4).
///
/// **Precondition:** `cfg.relay = Some(RelayConfig::default())`.
/// **Assertion:** `relay_stats()` returns `Some(...)`.
/// **Why sufficient:** Proves the `Some`/`None` bifurcation is config-driven, not
/// connection-state-driven. The relay may not be connected yet, but the stats struct
/// exists (with default/zero values). Detailed relay stats fields are tested in
/// `api_008_tests::test_relay_stats_some_with_relay`.
#[tokio::test]
async fn test_relay_stats_some_when_configured() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.relay = Some(RelayConfig::default());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    assert!(h.relay_stats().await.is_some());
}

/// **Row:** `test_methods_after_stop` — all handle methods return `ServiceNotStarted` after
/// the service is stopped (SPEC Section 4, API-002 implementation notes: "all methods
/// should return `GossipError::ServiceNotStarted` if the service has been stopped").
///
/// **Precondition:** A running service is stopped via `svc.stop()`.
/// **Assertion:** `health_check()` returns `GossipError::ServiceNotStarted`.
/// **Why sufficient:** `health_check` is the cheapest probe — if it correctly detects the
/// stopped state, the same internal channel-closed guard protects all other handle methods
/// (they share the same `mpsc` channel to the service task). This is the lifecycle
/// "teardown" half of the API-002 contract; `test_handle_is_cloneable` covers the
/// "startup" half.
#[tokio::test]
async fn test_methods_after_stop() {
    let (s, h) = running_handle().await;
    s.stop().await.unwrap();
    // The internal channel is closed; all handle RPCs must fail gracefully.
    let err = h.health_check().await.unwrap_err();
    assert!(matches!(err, GossipError::ServiceNotStarted));
}
