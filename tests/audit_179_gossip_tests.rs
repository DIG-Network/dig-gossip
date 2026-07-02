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
