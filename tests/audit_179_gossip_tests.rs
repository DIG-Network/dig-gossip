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
