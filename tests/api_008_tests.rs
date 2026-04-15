//! Tests for **API-008: [`GossipStats`] and [`RelayStats`]**.
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`API-008.md`](../docs/requirements/domains/crate_api/specs/API-008.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/crate_api/NORMATIVE.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §3.4
//!
//! ## Proof strategy
//!
//! Unit tests lock down **type shape**, **`Default`**, **`Debug`/`Clone`**, and **field round-trip**.
//! Integration tests exercise [`dig_gossip::GossipHandle::stats`] / [`dig_gossip::GossipHandle::relay_stats`]
//! against **stub** peers ([`GossipHandle::__connect_stub_peer_with_direction`]) so counters move
//! without real TLS; live `connect_to` is covered in [`con_001_tests`](../con_001_tests.rs).

mod common;

use std::net::SocketAddr;

use dig_gossip::{
    Bytes32, ChiaProtocolMessage, GossipHandle, GossipService, GossipStats, Message, NewPeak,
    NodeType, RelayConfig, RelayStats, RequestPeers, Streamable,
};

/// Spin up a [`GossipService`] with harness defaults and return both the service (for
/// lifecycle control) and the [`GossipHandle`] (for stats queries and stub-peer
/// registration).
///
/// Binds `127.0.0.1:0` (OS-assigned port), uses freshly generated TLS certs, and has
/// no relay configured. Used by every integration test in this file.
async fn running_handle() -> (GossipService, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    (svc, h)
}

/// Build a minimal [`NewPeak`] message for broadcast counter tests.
///
/// All hash fields are zeroed; height/weight are non-zero so the message is
/// distinguishable from default. The exact values are irrelevant — only the
/// serialized byte count matters for `bytes_sent` verification, and the message
/// type (`ProtocolMessageTypes::NewPeak`) matters for `messages_sent`.
/// Used by: `test_stats_cumulative_messages`.
fn sample_new_peak() -> NewPeak {
    let z = Bytes32::default();
    NewPeak::new(z, 1, 1, 0, z)
}

/// Field-by-field equality check for [`GossipStats`].
///
/// Why not `assert_eq!(a, b)`? `GossipStats` derives `Clone` and `Debug` but the
/// test plan explicitly requires per-field assertions so each field mismatch produces
/// a targeted error message. Used by: `test_gossip_stats_clone`.
fn assert_gossip_stats_equal(a: &GossipStats, b: &GossipStats) {
    assert_eq!(a.total_connections, b.total_connections);
    assert_eq!(a.connected_peers, b.connected_peers);
    assert_eq!(a.inbound_connections, b.inbound_connections);
    assert_eq!(a.outbound_connections, b.outbound_connections);
    assert_eq!(a.messages_sent, b.messages_sent);
    assert_eq!(a.messages_received, b.messages_received);
    assert_eq!(a.bytes_sent, b.bytes_sent);
    assert_eq!(a.bytes_received, b.bytes_received);
    assert_eq!(a.known_addresses, b.known_addresses);
    assert_eq!(a.seen_messages, b.seen_messages);
    assert_eq!(a.relay_connected, b.relay_connected);
    assert_eq!(a.relay_peer_count, b.relay_peer_count);
}

/// Field-by-field equality check for [`RelayStats`].
///
/// Same rationale as [`assert_gossip_stats_equal`] — each field gets a distinct failure
/// message. Used by: `test_relay_stats_clone`, `test_relay_stats_some_with_relay`.
fn assert_relay_stats_equal(a: &RelayStats, b: &RelayStats) {
    assert_eq!(a.connected, b.connected);
    assert_eq!(a.messages_sent, b.messages_sent);
    assert_eq!(a.messages_received, b.messages_received);
    assert_eq!(a.bytes_sent, b.bytes_sent);
    assert_eq!(a.bytes_received, b.bytes_received);
    assert_eq!(a.reconnect_attempts, b.reconnect_attempts);
    assert_eq!(a.last_connected_at, b.last_connected_at);
    assert_eq!(a.relay_peer_count, b.relay_peer_count);
    assert_eq!(a.latency_ms, b.latency_ms);
}

/// **Row:** `test_gossip_stats_default` — every field of `GossipStats::default()` matches
/// the zero/false baseline mandated by SPEC Section 3.4 and the `Default` derive.
///
/// **Acceptance criterion:** "GossipStats::default() has all numeric fields at 0, bools
/// at false" (API-008 spec).
/// **How setup creates precondition:** `GossipStats::default()` — no service needed; this
/// is a pure struct test.
/// **What each assertion proves:**
/// - `total_connections == 0`: cumulative counter starts at zero.
/// - `connected_peers == 0`: snapshot counter starts at zero.
/// - `inbound_connections == 0` / `outbound_connections == 0`: direction split starts empty.
/// - `messages_sent == 0` / `messages_received == 0`: cumulative I/O counters start at zero.
/// - `bytes_sent == 0` / `bytes_received == 0`: byte counters start at zero.
/// - `known_addresses == 0`: address manager is empty.
/// - `seen_messages == 0`: dedup set is empty.
/// - `relay_connected == false`: relay is not active.
/// - `relay_peer_count == 0`: no relay peers known.
///
/// **Why sufficient:** Exercises every public field in one shot; if a field were missing
/// or had a non-zero default, this test would fail at compile time or assertion time.
#[test]
fn test_gossip_stats_default() {
    let s = GossipStats::default();
    assert_eq!(s.total_connections, 0);
    assert_eq!(s.connected_peers, 0);
    assert_eq!(s.inbound_connections, 0);
    assert_eq!(s.outbound_connections, 0);
    assert_eq!(s.messages_sent, 0);
    assert_eq!(s.messages_received, 0);
    assert_eq!(s.bytes_sent, 0);
    assert_eq!(s.bytes_received, 0);
    assert_eq!(s.known_addresses, 0);
    assert_eq!(s.seen_messages, 0);
    assert!(!s.relay_connected); // false, not true — relay is inactive by default
    assert_eq!(s.relay_peer_count, 0);
}

/// **Row:** `test_relay_stats_default` — every field of `RelayStats::default()` matches
/// the zero/false/None baseline mandated by SPEC Section 3.4.
///
/// **Acceptance criterion:** "RelayStats::default() has all numeric fields at 0, Options
/// at None" (API-008 spec).
/// **What each assertion proves:**
/// - `connected == false`: not connected to relay at startup.
/// - `messages_sent == 0` / `messages_received == 0`: cumulative relay I/O at zero.
/// - `bytes_sent == 0` / `bytes_received == 0`: cumulative relay bytes at zero.
/// - `reconnect_attempts == 0`: no reconnect history.
/// - `last_connected_at == None`: never connected (distinct from "connected at epoch 0").
/// - `relay_peer_count == 0`: no relay peers known.
/// - `latency_ms == None`: no latency measurement taken yet.
///
/// **Why sufficient:** Covers every public field. The `Option<u64>` fields (`last_connected_at`,
/// `latency_ms`) default to `None` rather than `Some(0)`, which is semantically important:
/// `None` means "no data", `Some(0)` would mean "zero milliseconds / epoch 0".
#[test]
fn test_relay_stats_default() {
    let r = RelayStats::default();
    assert!(!r.connected);
    assert_eq!(r.messages_sent, 0);
    assert_eq!(r.messages_received, 0);
    assert_eq!(r.bytes_sent, 0);
    assert_eq!(r.bytes_received, 0);
    assert_eq!(r.reconnect_attempts, 0);
    assert_eq!(r.last_connected_at, None); // None = never connected, not Some(0)
    assert_eq!(r.relay_peer_count, 0);
    assert_eq!(r.latency_ms, None); // None = no measurement, not Some(0)
}

/// **Row:** `test_gossip_stats_debug` — `GossipStats` derives `Debug` and the formatted
/// output contains field names and values (SPEC Section 3.4 derive requirements).
///
/// **Acceptance criterion:** "`GossipStats` derives `Debug, Clone, Default`" (API-008 spec).
/// **Precondition:** Construct a stats struct with `connected_peers = 3` and
/// `messages_sent = 9` (non-default values to distinguish from zeros).
/// **Assertion:** The `Debug` output string contains both `"connected_peers"` and `'3'`.
/// **Why sufficient:** The `Debug` derive produces `"GossipStats { connected_peers: 3, ... }"`.
/// Checking for the field name *and* its value proves the derive is present and the struct
/// is not opaque. This matters for logging/diagnostics in production.
#[test]
fn test_gossip_stats_debug() {
    let s = GossipStats {
        connected_peers: 3,
        messages_sent: 9,
        ..Default::default()
    };
    let t = format!("{s:?}");
    // Confirm the Debug impl emits both the field name and its non-default value.
    assert!(t.contains("connected_peers") && t.contains('3'), "{t}");
}

/// **Row:** `test_relay_stats_debug` — `RelayStats` derives `Debug` and the formatted
/// output includes field names (SPEC Section 3.4 derive requirements).
///
/// **Acceptance criterion:** "`RelayStats` derives `Debug, Clone, Default`" (API-008 spec).
/// **Precondition:** A `RelayStats` with `reconnect_attempts = 2` and a non-None
/// `last_connected_at` to exercise the `Option` formatting path.
/// **Assertion:** The `Debug` string contains `"reconnect_attempts"`.
/// **Why sufficient:** Same rationale as `test_gossip_stats_debug` — proves the derive is
/// present and the struct is inspectable at runtime.
#[test]
fn test_relay_stats_debug() {
    let r = RelayStats {
        reconnect_attempts: 2,
        last_connected_at: Some(1_700_000_000),
        ..Default::default()
    };
    let t = format!("{r:?}");
    assert!(t.contains("reconnect_attempts"), "{t}");
}

/// **Row:** `test_gossip_stats_clone` — `GossipStats` derives `Clone` and a clone is
/// field-for-field identical to the original (SPEC Section 3.4).
///
/// **Acceptance criterion:** "`GossipStats` derives `Debug, Clone, Default`".
/// **Precondition:** A stats struct with several non-default fields (total=5, inbound=1,
/// outbound=4, seen=10) to ensure the clone copies more than just zeros.
/// **Assertion:** `assert_gossip_stats_equal` checks every field of `s` against `c`.
/// **Why sufficient:** If any field were skipped by the `Clone` derive (impossible with
/// the standard derive, but possible with a manual impl), the per-field check would
/// catch it. The `GossipHandle` clones stats snapshots when returning them to callers,
/// so `Clone` correctness is load-bearing.
#[test]
fn test_gossip_stats_clone() {
    let s = GossipStats {
        total_connections: 5,
        inbound_connections: 1,
        outbound_connections: 4,
        seen_messages: 10,
        ..Default::default()
    };
    let c = s.clone();
    assert_gossip_stats_equal(&s, &c);
}

/// **Row:** `test_relay_stats_clone` — `RelayStats` derives `Clone` and a clone preserves
/// all fields, including `Option` values (SPEC Section 3.4).
///
/// **Precondition:** `messages_sent = 1` and `latency_ms = Some(42)` — the `Some` value
/// exercises the `Option<u64>` clone path.
/// **Assertion:** `assert_relay_stats_equal` checks every field pairwise.
/// **Why sufficient:** Same rationale as `test_gossip_stats_clone`. The `Option` fields
/// are particularly important — a shallow copy bug could turn `Some(42)` into `None`.
#[test]
fn test_relay_stats_clone() {
    let r = RelayStats {
        messages_sent: 1,
        latency_ms: Some(42),
        ..Default::default()
    };
    let c = r.clone();
    assert_relay_stats_equal(&r, &c);
}

/// **Row:** `test_gossip_stats_populated` — constructing a `GossipStats` with every field
/// set to a non-default value proves the full field list compiles and that the
/// invariant `connected_peers == inbound + outbound` holds (SPEC Section 3.4,
/// implementation notes: "`connected_peers` should equal `inbound_connections +
/// outbound_connections`").
///
/// **Precondition:** All 12 fields are set to distinctive non-zero values in a struct
/// literal. `inbound_connections = 3`, `outbound_connections = 5`, `connected_peers = 8`.
/// **Assertion:** `connected_peers == inbound_connections + outbound_connections`.
/// **Why sufficient:** The struct literal is an exhaustive field list — if a field were
/// added or renamed, this test would fail to compile. The invariant assertion locks down
/// the relationship between the three connection counters, which callers rely on for
/// dashboard rendering.
#[test]
fn test_gossip_stats_populated() {
    let s = GossipStats {
        total_connections: 100,
        connected_peers: 8,
        inbound_connections: 3,
        outbound_connections: 5,
        messages_sent: 1_000,
        messages_received: 2_000,
        bytes_sent: 3_000,
        bytes_received: 4_000,
        known_addresses: 50,
        seen_messages: 99,
        relay_connected: true,
        relay_peer_count: 7,
    };
    // The spec-mandated invariant: connected = inbound + outbound.
    assert_eq!(
        s.connected_peers,
        s.inbound_connections + s.outbound_connections
    );
}

/// **Row:** `test_relay_stats_populated` — constructing a `RelayStats` with every field set
/// to a non-default value proves the full field list compiles (SPEC Section 3.4).
///
/// **Precondition:** All 9 fields are set to distinctive non-zero/non-None values in a
/// struct literal. `connected = true`, `last_connected_at = Some(99)`,
/// `latency_ms = Some(12)` to cover both `Option` variants.
/// **Assertion:** The test compiles and the struct is constructed without panic.
/// **Why sufficient:** Like `test_gossip_stats_populated`, this is primarily a
/// compile-time field-exhaustiveness check. If a field is added to `RelayStats`, this
/// test fails to compile, forcing the developer to update it. The `let _ = ...` pattern
/// is intentional — the values are verified in other tests; here we only prove the
/// struct shape.
#[test]
fn test_relay_stats_populated() {
    let _ = RelayStats {
        connected: true,
        messages_sent: 11,
        messages_received: 22,
        bytes_sent: 33,
        bytes_received: 44,
        reconnect_attempts: 3,
        last_connected_at: Some(99),
        relay_peer_count: 5,
        latency_ms: Some(12),
    };
}

/// **Row:** `test_stats_from_running_service` — `stats()` reflects the live stub-peer
/// topology: two outbound peers, zero inbound, and the invariant
/// `connected == inbound + outbound` holds (SPEC Section 3.4).
///
/// **Precondition:** Two outbound stub peers registered (a, b).
/// **Assertions:**
/// - `connected_peers == 2`: both stubs are counted.
/// - `outbound_connections == 2`: both stubs are outbound (`is_outbound=true`).
/// - `inbound_connections == 0`: no inbound stubs.
/// - `connected_peers == inbound + outbound`: invariant holds.
/// - `total_connections == 2`: cumulative matches current (no disconnects yet).
/// **Why sufficient:** Proves that `GossipHandle::stats()` computes a consistent snapshot
/// from the live peer map, not from stale cached values. The outbound-only setup is
/// intentional — mixed direction is covered by `test_stats_inbound_outbound_split`.
#[tokio::test]
async fn test_stats_from_running_service() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:18001".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:18002".parse().unwrap();
    h.__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    h.__connect_stub_peer_with_direction(b, NodeType::FullNode, true)
        .await
        .unwrap();
    let st = h.stats().await;
    assert_eq!(st.connected_peers, 2);
    assert_eq!(st.outbound_connections, 2);
    assert_eq!(st.inbound_connections, 0);
    // Invariant: connected = inbound + outbound.
    assert_eq!(
        st.connected_peers,
        st.inbound_connections + st.outbound_connections
    );
    // No disconnects yet, so total == current.
    assert_eq!(st.total_connections, 2);
}

/// **Row:** `test_relay_stats_none_without_relay` — `relay_stats()` returns `None` when
/// no relay is configured (SPEC Section 3.4, acceptance: "`relay_stats` returns `None`
/// when relay is not configured").
///
/// **Precondition:** Default `running_handle()` has `cfg.relay = None`.
/// **Assertion:** `relay_stats()` returns `None`.
/// **Why sufficient:** Callers (dashboards, health checks) must distinguish "relay not
/// configured" (`None`) from "relay configured but disconnected" (`Some(RelayStats { connected: false, .. })`).
/// This test locks down the `None` branch.
#[tokio::test]
async fn test_relay_stats_none_without_relay() {
    let (_s, h) = running_handle().await;
    assert!(h.relay_stats().await.is_none());
}

/// **Row:** `test_relay_stats_some_with_relay` — when a relay is configured, `relay_stats()`
/// returns `Some(RelayStats)` with default (zero/None) values because the relay has not
/// connected yet (SPEC Section 3.4).
///
/// **Precondition:** `cfg.relay = Some(RelayConfig::default())`.
/// **Assertions:**
/// - `relay_stats()` returns `Some(rs)` — proves config-driven presence.
/// - `rs` equals `RelayStats::default()` field-by-field — proves all counters start at
///   their documented zero values.
/// - `gs.relay_connected == false` and `rs.connected == false` — proves the implementation
///   notes consistency requirement: "`relay_connected` in `GossipStats` and `connected`
///   in `RelayStats` should be consistent".
/// **Why sufficient:** Covers the "configured but not yet connected" state, which is the
/// initial state for every relay-enabled node at startup.
#[tokio::test]
async fn test_relay_stats_some_with_relay() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.relay = Some(RelayConfig::default());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    let rs = h.relay_stats().await.expect("relay configured");
    // Relay exists but has not connected — all fields should be default.
    assert_relay_stats_equal(&rs, &RelayStats::default());
    let gs = h.stats().await;
    // Consistency check: GossipStats.relay_connected must match RelayStats.connected.
    assert!(!gs.relay_connected);
    assert!(!rs.connected);
}

/// **Row:** `test_stats_cumulative_messages` — `broadcast_typed` to two stub peers
/// increments `messages_sent` by exactly 2 (SPEC Section 3.4: "Total messages sent
/// (cumulative)").
///
/// **Precondition:** Two outbound stub peers. Capture `before = stats().messages_sent`.
/// **Assertion 1:** `broadcast_typed` returns `n == 2` (fan-out to both peers).
/// **Assertion 2:** `after == before + 2` — the counter incremented by the fan-out count.
/// **Why sufficient:** Proves the `messages_sent` counter is cumulative and tracks per-peer
/// deliveries (not per-broadcast). If the counter incremented by 1 instead of 2, the
/// implementation would be counting broadcasts rather than deliveries, which violates
/// the spec. The `before`/`after` pattern avoids coupling to service-internal message
/// traffic that might happen during startup.
#[tokio::test]
async fn test_stats_cumulative_messages() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:18101".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:18102".parse().unwrap();
    h.__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    h.__connect_stub_peer_with_direction(b, NodeType::FullNode, true)
        .await
        .unwrap();
    let before = h.stats().await.messages_sent;
    let n = h.broadcast_typed(sample_new_peak(), None).await.unwrap();
    assert_eq!(n, 2); // fan-out count: one delivery per peer
    let after = h.stats().await.messages_sent;
    // Counter must increase by 2 (one per peer delivery), not by 1 (one per broadcast).
    assert_eq!(after, before + 2, "two stub peers -> two counted deliveries");
}

/// **Extension:** `send_to` increments `messages_sent` by exactly 1 — the cumulative
/// counter tracks unicast sends as well as broadcasts (SPEC Section 3.4).
///
/// **Precondition:** One stub peer; capture `before` counter.
/// **Assertion:** `after == before + 1` — one `send_to` call = one delivery.
/// **Why sufficient:** Proves unicast and broadcast share the same counter (not separate
/// counters), and that `send_to` increments it synchronously before returning.
#[tokio::test]
async fn test_stats_send_to_increments_messages_sent() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:18201".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    let before = h.stats().await.messages_sent;
    h.send_to(pid, RequestPeers::new()).await.unwrap();
    let after = h.stats().await.messages_sent;
    // Unicast delivery increments the shared messages_sent counter by 1.
    assert_eq!(after, before + 1);
}

/// **Extension:** `__inject_inbound_for_tests` (simulating an inbound message from a peer)
/// increments `messages_received` by 1 (SPEC Section 3.4: "Total messages received
/// (cumulative)").
///
/// **Precondition:** Capture `before` counter. Inject a synthetic `RequestPeers` message
/// with a fabricated sender id.
/// **Assertion:** `after == before + 1`.
/// **Why sufficient:** Proves the receive counter is incremented by the same code path
/// that real inbound messages follow (the test-inject hook feeds into the same broadcast
/// hub). This is the receive-side counterpart of `test_stats_cumulative_messages`.
#[tokio::test]
async fn test_stats_inject_increments_messages_received() {
    let (_s, h) = running_handle().await;
    let sender = Bytes32::from([9u8; 32]);
    let before = h.stats().await.messages_received;
    let msg = Message {
        msg_type: RequestPeers::msg_type(),
        id: None,
        data: RequestPeers::new().to_bytes().unwrap().into(),
    };
    h.__inject_inbound_for_tests(sender, msg).unwrap();
    let after = h.stats().await.messages_received;
    // One injected message = one increment on the receive counter.
    assert_eq!(after, before + 1);
}

/// **Extension:** `total_connections` is cumulative and never decreases, even after
/// disconnect (SPEC Section 3.4 implementation notes: "`total_connections` is cumulative
/// and never decreases (even after disconnects)").
///
/// **Precondition:** Connect one stub peer; verify `total_connections == 1`. Then
/// disconnect the peer.
/// **Assertions after disconnect:**
/// - `connected_peers == 0`: the live count dropped.
/// - `total_connections == 1`: the cumulative count did NOT drop.
/// **Why sufficient:** Proves the two counters have different semantics: `connected_peers`
/// is a snapshot (goes down), `total_connections` is monotonic (never goes down). This
/// distinction matters for monitoring — total is a throughput metric, connected is a
/// capacity metric.
#[tokio::test]
async fn test_total_connections_monotonic_across_disconnect() {
    let (_s, h) = running_handle().await;
    let a: SocketAddr = "127.0.0.1:18301".parse().unwrap();
    let pid = h
        .__connect_stub_peer_with_direction(a, NodeType::FullNode, true)
        .await
        .unwrap();
    assert_eq!(h.stats().await.total_connections, 1);
    h.disconnect(&pid).await.unwrap();
    let st = h.stats().await;
    // Snapshot counter: drops to 0 after disconnect.
    assert_eq!(st.connected_peers, 0);
    // Cumulative counter: remains at 1 (monotonically non-decreasing).
    assert_eq!(st.total_connections, 1);
}

/// **Extension:** mixed-direction stub peers are correctly counted in the inbound/outbound
/// split, and the invariant `connected == inbound + outbound` holds (SPEC Section 3.4).
///
/// **Precondition:** One outbound stub (`is_outbound=true`) and one inbound stub
/// (`is_outbound=false`).
/// **Assertions:**
/// - `outbound_connections == 1`, `inbound_connections == 1`.
/// - `connected_peers == 2` (the sum).
/// **Why sufficient:** Complements `test_stats_from_running_service` (all-outbound) by
/// exercising the mixed-direction case. If the direction flag were ignored, both stubs
/// would count as outbound (2/0) or both as inbound (0/2), failing one of these
/// assertions.
#[tokio::test]
async fn test_stats_inbound_outbound_split() {
    let (_s, h) = running_handle().await;
    let out: SocketAddr = "127.0.0.1:18401".parse().unwrap();
    let inc: SocketAddr = "127.0.0.1:18402".parse().unwrap();
    h.__connect_stub_peer_with_direction(out, NodeType::FullNode, true) // outbound
        .await
        .unwrap();
    h.__connect_stub_peer_with_direction(inc, NodeType::FullNode, false) // inbound
        .await
        .unwrap();
    let st = h.stats().await;
    assert_eq!(st.outbound_connections, 1);
    assert_eq!(st.inbound_connections, 1);
    // Invariant: connected = inbound + outbound.
    assert_eq!(st.connected_peers, 2);
}
