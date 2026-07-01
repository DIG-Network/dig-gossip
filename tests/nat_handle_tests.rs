//! INT-019 — `GossipHandle` exposes the `dig-nat` transport.
//!
//! The gossip service's TLS identity + config drive `dig-nat` peer connections: the handle bridges
//! its own `ChiaCertificate` to a `dig-nat` identity and connects peers over the unified NAT-traversal
//! ladder. This suite proves the wiring WITHOUT a real network:
//!
//! - a running handle derives a `dig-nat` `LocalIdentity` whose `peer_id` matches the gossip layer's;
//! - `connect_via_nat` to an unreachable address fails cleanly (bounded, never hangs) rather than
//!   panicking — the graceful-fallback guarantee;
//! - after `stop()` the NAT methods are gated like every other handle method.

mod common;

use std::time::Duration;

use dig_gossip::{GossipHandle, GossipService, TraversalKind};

async fn running_handle() -> (GossipService, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    // Keep `dir` alive for the service's lifetime by leaking it into the returned tuple's scope:
    // the caller holds `svc`, and the certs are already loaded into memory by `new()`, so the temp
    // dir can drop safely here.
    (svc, handle)
}

#[tokio::test]
async fn handle_derives_a_nat_identity_matching_the_gossip_peer_id() {
    let (svc, handle) = running_handle().await;

    let identity = handle
        .nat_identity()
        .expect("a running handle bridges its TLS cert to a dig-nat identity");

    // The bridged identity's peer_id must equal the gossip-derived peer_id of the service's own cert.
    let expected = handle.local_peer_id().expect("local peer id");
    assert_eq!(
        identity.peer_id.as_bytes(),
        expected.as_ref(),
        "the NAT identity peer_id must equal the node's own gossip peer_id"
    );

    svc.stop().await.expect("stop");
}

#[tokio::test]
async fn connect_via_nat_to_a_dead_address_fails_cleanly() {
    let (svc, handle) = running_handle().await;

    // A peer_id we will never actually reach, at an address nothing listens on.
    let peer_id = dig_gossip::PeerId::from([0x11u8; 32]);
    // Port 1 on loopback: connection refused fast; the direct method fails and (with only Direct
    // enabled + a short timeout) connect returns AllMethodsFailed rather than hanging.
    let addr = "127.0.0.1:1".parse().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        handle.connect_via_nat(
            peer_id,
            Some(addr),
            &[TraversalKind::Direct],
            Duration::from_millis(500),
        ),
    )
    .await
    .expect("connect_via_nat must be bounded and never hang");

    assert!(
        result.is_err(),
        "connecting to a dead address must fail, not succeed"
    );

    svc.stop().await.expect("stop");
}

#[tokio::test]
async fn nat_methods_are_gated_after_stop() {
    let (svc, handle) = running_handle().await;
    svc.stop().await.expect("stop");

    assert!(
        handle.nat_identity().is_err(),
        "nat_identity must be gated after stop()"
    );
}
