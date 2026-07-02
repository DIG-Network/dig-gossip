//! Regression tests for **security audit #179 — dig-gossip findings**.
//!
//! ## Traceability
//!
//! - **Source:** `SECURITY_AUDIT_P2P.md` § "dig-gossip" (superproject root), 5 confirmed findings
//!   (2 HIGH, 2 MEDIUM, 1 LOW).
//! - **SPEC:** `docs/resources/SPEC.md` §6.3 / §6.5 / §6.6 — bounds documented per finding below.
//!
//! One module per finding, ordered HIGH -> MEDIUM -> LOW to match the fix/commit order.

mod common;

use dig_gossip::{AddressManager, PeerInfo, TimestampedPeerInfo};

/// Build `count` distinct dialable peers so each call to `add_to_new_table` is a genuine,
/// non-deduplicated merge (distinct `/16` groups so bucket placement doesn't collapse them).
fn fake_peers(count: usize, timestamp: u64) -> Vec<TimestampedPeerInfo> {
    (0..count)
        .map(|i| {
            let a = (i / 256) % 256;
            let b = i % 256;
            TimestampedPeerInfo::new(format!("10.{a}.{b}.1"), 9444, timestamp)
        })
        .collect()
}

// =========================================================================
// HIGH #1 — unbounded `new_table_log` Vec grows on every peer-exchange merge
// (src/discovery/address_manager.rs:902)
// =========================================================================
mod high_1_new_table_log_bounded {
    use super::*;

    /// **Regression for audit #179 HIGH finding 1.**
    ///
    /// `add_to_new_table` is called on every inbound peer-exchange merge (outbound connect,
    /// introducer discovery, relay merge). Before the fix, `Inner::new_table_log` pushed one
    /// owned clone of the batch + source PER CALL for the lifetime of the process, so N calls
    /// held O(N) batches in memory forever — unbounded growth from ordinary, even entirely
    /// honest, long-run operation.
    ///
    /// The only production consumer is `__last_new_table_batch_for_tests`, which reads only the
    /// MOST RECENT batch. This test proves the log stays bounded (does not grow per call) while
    /// still faithfully returning the last batch — i.e. the fix must not silently break the
    /// CON-001/CON-002 test hook.
    #[test]
    fn new_table_log_does_not_grow_unboundedly_across_many_merges() {
        let am = AddressManager::__with_key_and_seed_for_tests([7u8; 32], 42);

        // Simulate a long-running node observing many peer-exchange rounds. Before the fix this
        // pushed 500 owned (Vec<TimestampedPeerInfo>, PeerInfo) entries that were never freed.
        for round in 0..500u64 {
            let src = PeerInfo {
                host: format!("192.0.2.{}", round % 250),
                port: 9444,
            };
            let batch = fake_peers(4, 1_000 + round);
            am.add_to_new_table(&batch, &src, 0);
        }

        // The test hook must still see the LAST batch (round 499) — bounding the log must not
        // break the CON-001/CON-002 contract that reads the most recent merge.
        let (last_batch, last_src) = am
            .__last_new_table_batch_for_tests()
            .expect("last batch must be present after merges");
        assert_eq!(last_batch.len(), 4, "last batch content must be preserved");
        assert_eq!(last_src.host, "192.0.2.249");

        // The bounded-log memory-footprint contract: this call must not panic/OOM and the crate
        // must not expose any way to retrieve more than a small bounded number of retained
        // batches. `__new_table_log_len_for_tests` reports the CURRENT retained count, which
        // must stay small (<=1) regardless of how many merges have occurred.
        assert!(
            am.__new_table_log_len_for_tests() <= 1,
            "new_table_log must be bounded (<=1 retained batch), got {}",
            am.__new_table_log_len_for_tests()
        );
    }

    /// An empty batch (the outbound-connect path deliberately calls `add_to_new_table` with an
    /// empty list so the log records that the RequestPeers exchange occurred) must still update
    /// the hook without growing the retained log.
    #[test]
    fn new_table_log_records_empty_batches_without_growth() {
        let am = AddressManager::__with_key_and_seed_for_tests([9u8; 32], 1);
        let src = PeerInfo {
            host: "10.9.9.9".to_string(),
            port: 9444,
        };

        for _ in 0..50 {
            am.add_to_new_table(&[], &src, 0);
        }

        let (last_batch, _last_src) = am
            .__last_new_table_batch_for_tests()
            .expect("empty batches must still be recorded for the test hook");
        assert!(last_batch.is_empty());
        assert!(am.__new_table_log_len_for_tests() <= 1);
    }
}

// =========================================================================
// HIGH #2 — inbound accept loop has no cap on concurrent in-flight handshakes
// (src/connection/listener.rs:733)
// =========================================================================
#[cfg(any(feature = "native-tls", feature = "rustls"))]
mod high_2_inbound_handshake_semaphore {
    use std::time::Duration;

    use dig_gossip::GossipService;
    use tokio::net::TcpStream;

    /// **Regression for audit #179 HIGH finding 2.**
    ///
    /// Before the fix, the accept loop's ONLY admission gate was `state.peers.len() >=
    /// max_connections` — but a connection is not inserted into `state.peers` until AFTER TLS +
    /// the full Chia handshake completes. A connection that never completes the handshake
    /// (a raw TCP connect that sends nothing) is invisible to that gate and would previously
    /// spawn an unbounded `handle_inbound_native` task per accepted socket.
    ///
    /// This test opens `max_inflight_handshakes` raw TCP connections to the server (never
    /// completing TLS/handshake on any of them, so `max_connections` — set very high — never
    /// applies) and proves a REAL, well-formed client `connect_to` cannot complete while the
    /// budget is exhausted: the new semaphore admission gate must reject/drop it, because a
    /// slot is never freed by the registered-peer count.
    #[tokio::test]
    async fn accept_loop_caps_concurrent_inflight_handshakes_independent_of_max_connections() {
        let dir = super::common::test_temp_dir();
        let _ = super::common::generate_test_certs(dir.path());
        let mut cfg = super::common::test_gossip_config(dir.path());
        // max_connections deliberately high — this test proves the SEPARATE handshake-budget gate,
        // not the registered-peer gate already covered by `con_002_tests::test_inbound_max_connections`.
        cfg.max_connections = 1000;
        cfg.max_inflight_handshakes = 2;
        let svc = GossipService::new(cfg).expect("GossipService::new");
        let h = svc.start().await.expect("start");
        let bound = h
            .__listen_bound_addr_for_tests()
            .expect("listen addr after start");

        // Open exactly `max_inflight_handshakes` raw TCP connections and never send a single byte —
        // each should consume one permit and never be registered as a peer (no TLS, no handshake).
        let _stalled: Vec<TcpStream> = futures_util::future::join_all(
            (0..2)
                .map(|_| async move { TcpStream::connect(bound).await.expect("raw tcp connect") }),
        )
        .await;

        // Give the accept loop a moment to accept + spawn + acquire permits for the stalled sockets.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // A real, well-behaved client attempting a full connect must NOT succeed while the
        // in-flight handshake budget is exhausted — the accept loop must drop its socket outright
        // rather than spawn an unbounded 3rd handshake task.
        let client_dir = super::common::test_temp_dir();
        let _ = super::common::generate_test_certs(client_dir.path());
        let client_cfg = super::common::test_gossip_config(client_dir.path());
        let client_svc = GossipService::new(client_cfg).expect("client new");
        let client_h = client_svc.start().await.expect("client start");
        let connect_res =
            tokio::time::timeout(Duration::from_secs(5), client_h.connect_to(bound)).await;

        // Either the connect call errors out, or times out waiting on a socket the server never
        // completes the handshake on — either way it must NOT succeed while budget is exhausted.
        let connected_ok = matches!(connect_res, Ok(Ok(_)));
        assert!(
            !connected_ok,
            "client connect must not succeed while the server's inflight-handshake budget is exhausted"
        );

        // peer_count on the SERVER must stay at 0: the well-formed client's connection attempt was
        // refused at admission (no permit), so it never reaches the point of being registered.
        assert_eq!(
            h.peer_count().await,
            0,
            "server must not register any peer while the inflight-handshake budget is exhausted"
        );

        drop(client_h);
    }
}

// =========================================================================
// MEDIUM #3 — introducer discovery merge bypasses cap_received_peers
// (src/discovery/node_discovery.rs:721)
// =========================================================================
#[cfg(any(feature = "native-tls", feature = "rustls"))]
mod medium_3_introducer_cap {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use dig_gossip::{
        load_ssl_cert, run_discovery_loop, AddressManager, DiscoveryAction, GossipConfig,
        IntroducerConfig, TimestampedPeerInfo, MAX_PEERS_RECEIVED_PER_REQUEST,
    };
    use tokio_util::sync::CancellationToken;

    /// **Regression for audit #179 MEDIUM finding 3.**
    ///
    /// Before the fix, `try_introducer_query` folded the ENTIRE raw introducer response into the
    /// address manager via `add_to_new_table` with no cap — bypassing the `cap_received_peers`
    /// gate node peer-exchange applies. This test runs the real `run_discovery_loop` against a
    /// mock introducer (the same TLS/wire harness `dsc_004_tests.rs` uses) that returns an
    /// OVERSIZED peer list (2000, well above `MAX_PEERS_RECEIVED_PER_REQUEST` = 1000), with the
    /// SHARED `total_peers_received` counter pre-seeded to simulate a prior peer-exchange round
    /// having already consumed most of the global budget.
    ///
    /// It asserts:
    /// 1. The number of peers actually merged (`IntroducerQueried { count }`) is capped, not 2000.
    /// 2. The shared counter after the run does not exceed the global cap.
    #[tokio::test]
    async fn introducer_discovery_merge_is_capped_via_shared_counter() {
        let client_dir = super::common::test_temp_dir();
        let (cc, ck) = super::common::generate_test_certs(client_dir.path());
        let server_dir = super::common::test_temp_dir();
        let (sc, sk) = super::common::generate_test_certs(server_dir.path());
        let server_cert = load_ssl_cert(&sc, &sk).expect("server cert");
        let net = super::common::test_network_id().to_string();

        // A malicious/misconfigured introducer returns far more than the per-request cap.
        let oversized_list: Vec<TimestampedPeerInfo> = (0..2000)
            .map(|i| {
                let a = (i / 256) % 256;
                let b = i % 256;
                TimestampedPeerInfo::new(format!("203.0.{a}.{b}"), 9444, 1_700_000_000)
            })
            .collect();

        let (addr, _server_jh) = super::common::wss_full_node::spawn_one_shot_introducer(
            server_cert,
            net.clone(),
            net.clone(),
            oversized_list,
            false,
        )
        .await;

        let cfg = GossipConfig {
            cert_path: cc,
            key_path: ck,
            network_id: super::common::test_network_id(),
            // Empty DNS introducer list (unlike `GossipConfig::default()`'s real mainnet DNS
            // introducers) so DNS seeding always returns nothing and the loop reliably falls
            // through to the introducer path this test exercises.
            network: super::common::test_network(),
            dns_seed_timeout: Duration::from_millis(50),
            dns_seed_batch_size: 1,
            introducer: Some(IntroducerConfig {
                endpoint: format!("wss://127.0.0.1:{}/ws", addr.port()),
                connection_timeout_secs: 10,
                request_timeout_secs: 10,
                network_id: net,
            }),
            ..GossipConfig::default()
        };

        let am = Arc::new(AddressManager::new());
        let cancel = CancellationToken::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        // Simulate a prior peer-exchange round having already consumed most of the shared global
        // budget (2900 of 3000) — only 100 should remain for the introducer to fill.
        let shared_counter = Arc::new(AtomicU64::new(2900));

        let cancel_clone = cancel.clone();
        let counter_clone = shared_counter.clone();
        let handle = tokio::spawn(async move {
            run_discovery_loop(am, Arc::new(cfg), cancel_clone, Some(tx), counter_clone).await;
        });

        // Let the loop run its first cycle (DNS fails fast, then introducer is queried).
        // Keep polling on a per-message timeout until the deadline — do NOT bail out on an
        // individual `recv` timeout, only on the overall deadline or a closed channel.
        let mut queried_count = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
                Ok(Some(DiscoveryAction::IntroducerQueried { count })) => {
                    queried_count = Some(count);
                    break;
                }
                Ok(Some(_)) => continue,
                Ok(None) => break,  // channel closed — loop task exited
                Err(_) => continue, // per-message timeout — keep polling until the deadline
            }
        }
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;

        let queried_count =
            queried_count.expect("introducer query must complete and report a count");
        assert!(
            queried_count <= MAX_PEERS_RECEIVED_PER_REQUEST,
            "introducer batch must be capped at the per-request limit ({}), got {}",
            MAX_PEERS_RECEIVED_PER_REQUEST,
            queried_count
        );
        assert_eq!(
            queried_count, 100,
            "with 2900/3000 of the shared global budget already consumed, only the remaining \
             100 must be accepted from the introducer — proving it shares total_peers_received \
             with node peer-exchange rather than bypassing the cap"
        );
        assert_eq!(
            shared_counter.load(Ordering::Relaxed),
            3000,
            "shared counter must reach exactly the global cap, not be bypassed by the introducer path"
        );
    }
}

// =========================================================================
// MEDIUM #4 — relay-introducer trusts an unbounded frame stream + peer list
// (src/nat/discovery.rs:95)
// =========================================================================
#[cfg(feature = "relay")]
mod medium_4_relay_introducer_bounds {
    use std::time::Duration;

    use dig_gossip::nat::discovery::{relay_get_peers, MAX_RELAY_DISCOVERY_FRAMES};
    use dig_gossip::MAX_PEERS_RECEIVED_PER_REQUEST;
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;

    /// **Regression for audit #179 MEDIUM finding 4 (part A — frame count).**
    ///
    /// Before the fix, `relay_get_peers`'s read loop had no bound on the number of non-terminal
    /// frames it would read while waiting for a `peers`/`error` response — only the outer
    /// `timeout` bounded it. A hostile/compromised relay (or an on-path MITM of the relay
    /// WebSocket, which is explicitly documented as untrusted) could stream filler frames
    /// indefinitely, burning CPU/bandwidth for the whole timeout window on every discovery pass.
    ///
    /// This test spins up a mock relay that sends `MAX_RELAY_DISCOVERY_FRAMES + 10` unparsable
    /// filler frames (never a `peers`/`error` response) and asserts `relay_get_peers` gives up
    /// with an error WELL BEFORE the (long) outer timeout — proving the frame-count bound fires
    /// rather than relying solely on the timeout.
    #[tokio::test]
    async fn relay_get_peers_bounds_the_number_of_frames_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _register = ws.next().await.unwrap().unwrap();
            let _get_peers = ws.next().await.unwrap().unwrap();
            // Stream filler frames well past the expected budget — never send peers/error. Keep
            // going indefinitely (bounded only by a long sleep between sends) so a client WITHOUT
            // a frame-count bound would keep reading real frames until the outer timeout, not an
            // EOF/close — isolating the frame-count bound from a "server hung up" false pass.
            let mut i = 0usize;
            loop {
                let filler = serde_json::json!({ "type": "ping", "seq": i });
                if ws
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        filler.to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break; // client gave up and closed — expected once the bound fires
                }
                i += 1;
                if i > MAX_RELAY_DISCOVERY_FRAMES + 500 {
                    // Safety valve in case the bound never fires (test would fail on the
                    // elapsed-time assertion instead of hanging forever).
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // Keep the socket open a little longer so the client's bound (not a close) is what fires.
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let endpoint = format!("ws://{addr}");
        // Outer timeout is generous (10s) — the assertion is that we do NOT wait anywhere near
        // that long, because the frame-count bound fires first.
        let start = tokio::time::Instant::now();
        let result = relay_get_peers(
            &endpoint,
            "self".repeat(16),
            "DIG_MAINNET",
            Duration::from_secs(10),
        )
        .await;
        let elapsed = start.elapsed();
        let _ = server.await;

        assert!(
            result.is_err(),
            "an unbounded filler-frame stream must surface as an error, not succeed"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the frame-count bound must fire well before the 10s outer timeout, took {elapsed:?}"
        );
    }

    /// **Regression for audit #179 MEDIUM finding 4 (part B — peers-list length).**
    ///
    /// Before the fix, an oversized `RelayMessage::Peers` response was converted to `PeerRecord`s
    /// in full with no cap, independent of the per-request cap node peer-exchange applies to
    /// `RespondPeers`. This test has a mock relay return `MAX_PEERS_RECEIVED_PER_REQUEST + 500`
    /// peer entries and asserts the returned record count is capped, not the full oversized list.
    #[tokio::test]
    async fn relay_get_peers_caps_an_oversized_peers_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let oversized_count = MAX_PEERS_RECEIVED_PER_REQUEST + 500;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _register = ws.next().await.unwrap().unwrap();
            let _get_peers = ws.next().await.unwrap().unwrap();
            let peers: Vec<_> = (0..oversized_count)
                .map(|i| {
                    serde_json::json!({
                        "peer_id": format!("{i:064x}"),
                        "network_id": "DIG_MAINNET",
                        "protocol_version": 1,
                        "connected_at": 1,
                        "last_seen": i as u64,
                    })
                })
                .collect();
            let reply = serde_json::json!({ "type": "peers", "peers": peers });
            ws.send(tokio_tungstenite::tungstenite::Message::Text(
                reply.to_string(),
            ))
            .await
            .unwrap();
        });

        let endpoint = format!("ws://{addr}");
        let records = relay_get_peers(
            &endpoint,
            "self".repeat(16),
            "DIG_MAINNET",
            Duration::from_secs(10),
        )
        .await
        .expect("relay_get_peers succeeds even with an oversized response");
        server.await.unwrap();

        assert!(
            records.len() <= MAX_PEERS_RECEIVED_PER_REQUEST,
            "an oversized relay peers response ({oversized_count}) must be capped at the \
             per-request limit ({MAX_PEERS_RECEIVED_PER_REQUEST}), got {}",
            records.len()
        );
    }
}

// =========================================================================
// LOW #5 — broadcast() deep-clones per eager peer + holds two locks together
// (src/service/gossip_handle.rs:302)
// =========================================================================
#[cfg(any(feature = "native-tls", feature = "rustls"))]
mod low_5_broadcast_lock_scope {
    use std::net::SocketAddr;
    use std::time::Duration;

    use dig_gossip::{
        Bytes32, GossipHandle, GossipService, Message, NewPeak, ProtocolMessageTypes, Streamable,
    };

    async fn running_server() -> (tempfile::TempDir, GossipService, GossipHandle, SocketAddr) {
        let dir = super::common::test_temp_dir();
        let _ = super::common::generate_test_certs(dir.path());
        let cfg = super::common::test_gossip_config(dir.path());
        let svc = GossipService::new(cfg).expect("GossipService::new");
        let h = svc.start().await.expect("start");
        let bound = h
            .__listen_bound_addr_for_tests()
            .expect("listen addr after start");
        (dir, svc, h, bound)
    }

    async fn outbound_client_handle() -> (tempfile::TempDir, GossipHandle) {
        let dir = super::common::test_temp_dir();
        let _ = super::common::generate_test_certs(dir.path());
        let cfg = super::common::test_gossip_config(dir.path());
        let svc = GossipService::new(cfg).expect("client new");
        let h = svc.start().await.expect("client start");
        (dir, h)
    }

    /// **Regression for audit #179 LOW finding 5 (lock-scope half).**
    ///
    /// The audit flagged `broadcast()`'s eager-peer classification block for acquiring the
    /// `peers` + `plumtree` locks TOGETHER, then sending while (potentially) still holding them.
    /// `std::sync::MutexGuard` is `!Send`, so if EITHER guard were held across the
    /// `peer.send_protocol_message(...).await` point, the `broadcast()` future itself would
    /// become `!Send` — and `tokio::spawn` (which requires `F: Future + Send`) would fail to
    /// COMPILE. This test spawns `broadcast()` onto its own task via `tokio::spawn`: it is a
    /// compile-time proof, not a timing heuristic — if a future change re-introduces a
    /// `MutexGuard` held across the send await, this test file stops compiling with an
    /// `F: Send` trait-bound error (verified during development: reintroducing
    /// `self.inner.peers.lock()` held across the send loop reproduces exactly that compile
    /// error). A concurrent `peer_count()` call is raced alongside for a behavioral sanity check
    /// on top of the structural guarantee.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broadcast_future_is_send_and_peer_count_is_not_blocked_during_broadcast() {
        let (_server_dir, _server_svc, server_h, bound) = running_server().await;
        let (_client_dir, client_h) = outbound_client_handle().await;
        client_h.connect_to(bound).await.expect("connect_to");

        // Wait for the server to observe the inbound registration.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while server_h.peer_count().await == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            server_h.peer_count().await,
            1,
            "server must see the live peer"
        );

        let msg = {
            let z = Bytes32::default();
            let body = NewPeak::new(z, 1, 1, 0, z);
            Message {
                msg_type: ProtocolMessageTypes::NewPeak,
                id: None,
                data: body.to_bytes().unwrap().into(),
            }
        };

        // `tokio::spawn` requires `F: Future + Send` — this line alone is the structural proof
        // that no `!Send` MutexGuard is held across broadcast's internal send await.
        let count_handle = server_h.clone();
        let broadcast_task = tokio::spawn(async move { server_h.broadcast(msg, None).await });
        let count_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let start = tokio::time::Instant::now();
            let _ = count_handle.peer_count().await;
            start.elapsed()
        });

        let broadcast_res = broadcast_task.await.expect("broadcast task join");
        let count_elapsed = count_task.await.expect("count task join");

        broadcast_res.expect("broadcast succeeds");
        assert!(
            count_elapsed < Duration::from_millis(500),
            "peer_count() must not be blocked by broadcast's classification lock, took {count_elapsed:?}"
        );
    }
}
