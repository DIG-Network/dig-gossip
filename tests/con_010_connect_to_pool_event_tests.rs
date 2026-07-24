//! Regression test for **#1581: `GossipHandle::connect_to` must publish `PoolEvent::PeerAdded`**.
//!
//! ## Traceability
//!
//! - **Bug:** #1581 — the direct-WSS dial ([`GossipHandle::connect_to`]) inserted the pool slot but
//!   never published [`PoolEvent::PeerAdded`], unlike [`GossipHandle::adopt_nat_connection`] (the
//!   relayed path) and the pool dial loop. So a directly-connected peer was invisible to every
//!   pool-event consumer — DHT routing (#1574's `spawn_dht_routing_feed`), the peer-selector, PEX —
//!   which made direct-path DISCOVER return zero providers while the relayed path worked.
//! - **SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §5.1 (outbound connection lifecycle) +
//!   the pool-event churn contract consumed via [`GossipHandle::subscribe_pool_events`].
//!
//! ## Proof strategy
//!
//! Spin up the local [`common::wss_full_node`] acceptor, subscribe to pool events, then
//! [`connect_to`] it and assert a [`PoolEvent::PeerAdded`] arrives carrying the same verified
//! `peer_id` the dial returned and the dialed remote `addr` — exactly the shape
//! `adopt_nat_connection` publishes on the relayed path. Without the fix no event is published and
//! the receive times out (RED).

mod common;

use std::time::Duration;

use dig_gossip::GossipService;
use dig_gossip::{load_ssl_cert, GossipHandle};

/// Spin up a running [`GossipService`] client — mirrors `con_001_tests::running_client`.
async fn running_client() -> (tempfile::TempDir, GossipService, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("GossipService::new");
    let h = svc.start().await.expect("start");
    (dir, svc, h)
}

/// **#1581** — a direct `connect_to` dial publishes `PoolEvent::PeerAdded` for the connected peer,
/// so DHT routing / selector / PEX see the directly-connected peer exactly like a relayed one.
#[tokio::test]
async fn connect_to_publishes_peer_added() {
    use dig_gossip::PoolEvent;

    let (_cdir, _svc, h) = running_client().await;
    let server_dir = common::test_temp_dir();
    let (sc, sk) = common::generate_test_certs(server_dir.path());
    let server_cert = load_ssl_cert(&sc, &sk).expect("server tls");
    let net = common::test_network_id().to_string();
    let (addr, jh) =
        common::wss_full_node::spawn_one_shot_full_node(server_cert, net, vec![]).await;

    // Subscribe BEFORE dialing so we cannot miss the event (broadcast delivers post-subscribe only).
    let mut events = h.subscribe_pool_events().expect("pool events subscription");

    let pid = h.connect_to(addr).await.expect("outbound connect");

    // The direct path MUST feed the pool-event stream just like the relayed path.
    let evt = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("PoolEvent::PeerAdded must be published on a direct connect_to (#1581)")
        .expect("pool event channel open");

    match evt {
        PoolEvent::PeerAdded {
            peer_id,
            addr: evt_addr,
        } => {
            assert_eq!(
                peer_id, pid,
                "PeerAdded must carry the verified dial peer_id"
            );
            assert_eq!(
                evt_addr, addr,
                "PeerAdded must carry the dialed remote addr"
            );
        }
        other => panic!("expected PoolEvent::PeerAdded, got {other:?}"),
    }

    jh.await.expect("join").expect("server task");
}
