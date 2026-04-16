//! Tests for **INT-015: End-to-end lifecycle integration test**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-015.md`
//! - **Master SPEC:** §3 (Public API)
//!
//! INT-015 proves the complete crate lifecycle works:
//! GossipConfig → GossipService::new() → start() → GossipHandle → stop()

/// Helper: create a valid GossipConfig for lifecycle tests.
///
/// Sets non-zero network_id and temp cert paths (GossipService::new generates
/// certs if files don't exist but paths must be non-empty).
fn lifecycle_config() -> dig_gossip::GossipConfig {
    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    let mut config = dig_gossip::GossipConfig::default();
    config.network_id = dig_gossip::Bytes32::from([1u8; 32]);
    config.cert_path = cert_path.to_string_lossy().to_string();
    config.key_path = key_path.to_string_lossy().to_string();
    // Use port 0 for ephemeral allocation (avoids conflicts).
    config.listen_addr = "127.0.0.1:0".parse().unwrap();
    config
}

/// **INT-015: full lifecycle — config → new → start → use handle → stop.**
///
/// Proves the public interface works as a complete unit. Every step must
/// succeed for the crate to function as designed (SPEC §3.1, §3.2, §3.3).
///
/// This is THE definitive test that the crate works end-to-end behind its
/// public API. If this passes, a downstream crate can use dig-gossip.
#[cfg(feature = "native-tls")]
#[tokio::test]
async fn test_full_lifecycle() {
    use dig_gossip::{GossipError, GossipService};

    // Step 1: Config
    let config = lifecycle_config();

    // Step 2: Construct (generates TLS cert, creates address manager)
    let service = GossipService::new(config).expect("GossipService::new must succeed");

    // Step 3: Start (binds listener, spawns tasks, returns handle)
    let handle = service.start().await.expect("start() must succeed");

    // Step 4: Use handle — all core methods should work
    handle
        .health_check()
        .await
        .expect("health_check must work while running");

    let stats = handle.stats().await;
    assert_eq!(stats.connected_peers, 0, "no peers connected yet");

    let count = handle.peer_count().await;
    assert_eq!(count, 0, "peer_count = 0");

    // Step 5: Stop (disconnects, saves state, cancels tasks)
    service.stop().await.expect("stop() must succeed");

    // Step 6: Methods return error after stop
    let result = handle.health_check().await;
    assert!(
        matches!(result, Err(GossipError::ServiceNotStarted)),
        "methods after stop must return ServiceNotStarted, got: {:?}",
        result
    );
}

/// **INT-015: broadcast returns 0 with no peers.**
///
/// Proves broadcast is safe to call when no peers are connected.
/// This is the normal state during startup before discovery runs.
#[cfg(feature = "native-tls")]
#[tokio::test]
async fn test_broadcast_no_peers() {
    use dig_gossip::{GossipService, Message, ProtocolMessageTypes};

    let service = GossipService::new(lifecycle_config()).unwrap();
    let handle = service.start().await.unwrap();

    let msg = Message {
        msg_type: ProtocolMessageTypes::NewPeak,
        id: None,
        data: vec![1, 2, 3].into(),
    };

    let sent = handle.broadcast(msg, None).await.unwrap();
    assert_eq!(sent, 0, "broadcast with no peers should return 0");

    service.stop().await.unwrap();
}
