//! Integration tests for **API-001: `GossipService` constructor and lifecycle**.
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`API-001.md`](../docs/requirements/domains/crate_api/specs/API-001.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/crate_api/NORMATIVE.md)
//! - **Verification:** [`VERIFICATION.md`](../docs/requirements/domains/crate_api/VERIFICATION.md)
//!
//! ## Proof strategy
//!
//! Each test maps to the API-001 verification table. We reuse STR-005 helpers (`tests/common`)
//! for temp dirs and valid [`dig_gossip::GossipConfig`] values so failures isolate API-001 logic.

mod common;

use dig_gossip::{Bytes32, GossipError, GossipService};

/// **Row:** `test_new_with_valid_config` — construct with a coherent harness config.
///
/// **Why it proves API-001:** acceptance requires `GossipService::new(config) -> Result<Self, GossipError>`
/// and successful allocation of internal placeholders (TLS + maps) without panicking.
#[test]
fn test_new_with_valid_config() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg);
    assert!(
        svc.is_ok(),
        "expected Ok(GossipService), got {:?}",
        svc.err()
    );
}

/// **Row:** `test_new_generates_cert_when_missing` — PEM files absent under fresh paths.
///
/// **Why:** [`chia_sdk_client::load_ssl_cert`] generates when reads fail; API-001 requires that
/// policy to persist PEMs for later runs (upstream writes in `tls.rs`).
#[test]
fn test_new_generates_cert_when_missing() {
    let dir = common::test_temp_dir();
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.cert_path = dir.path().join("fresh.crt").to_string_lossy().into_owned();
    cfg.key_path = dir.path().join("fresh.key").to_string_lossy().into_owned();
    assert!(!std::path::Path::new(&cfg.cert_path).exists());

    let svc = GossipService::new(cfg).expect("new with missing pem");
    drop(svc);

    assert!(std::path::Path::new(&dir.path().join("fresh.crt")).exists());
    assert!(std::path::Path::new(&dir.path().join("fresh.key")).exists());
}

/// **Row:** `test_new_loads_existing_cert` — reuse PEMs written by the harness.
#[test]
fn test_new_loads_existing_cert() {
    let dir = common::test_temp_dir();
    let (c, k) = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.cert_path = c;
    cfg.key_path = k;
    let first = GossipService::new(cfg.clone()).expect("first new");
    drop(first);
    let second = GossipService::new(cfg).expect("second new loads same pem");
    drop(second);
}

/// **Row:** `test_new_invalid_cert_path` — cert path unusable (directory), expect stable I/O error.
#[test]
fn test_new_invalid_cert_path() {
    let dir = common::test_temp_dir();
    let mut cfg = common::test_gossip_config(dir.path());
    // Using the directory itself as the "cert file" forces read/write failure distinct from
    // "missing file" (which triggers generation).
    cfg.cert_path = dir.path().to_string_lossy().into_owned();
    cfg.key_path = dir.path().join("key.pem").to_string_lossy().into_owned();

    let err = GossipService::new(cfg).unwrap_err();
    match err {
        GossipError::IoError(_) => {}
        other => panic!("expected IoError, got {:?}", other),
    }
}

/// **Row:** `test_new_does_not_start_networking` — lifecycle remains pre-start after construction.
///
/// **How:** we expose a narrow test hook on [`GossipService`] (hidden from rustdoc) that mirrors
/// the internal atomic; no listener tasks exist yet (CON-002).
#[test]
fn test_new_does_not_start_networking() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    assert!(
        !svc.__is_running_for_tests(),
        "constructor must not transition to running without start()"
    );
}

/// **Row:** `test_start_returns_handle` — `start().await` yields a usable [`dig_gossip::GossipHandle`].
#[tokio::test]
async fn test_start_returns_handle() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    handle.health_check().await.expect("running handle");
}

/// **Row:** `test_start_twice_fails` — second `start` surfaces [`GossipError::AlreadyStarted`].
#[tokio::test]
async fn test_start_twice_fails() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let _ = svc.start().await.expect("first start");
    let err = svc.start().await.unwrap_err();
    assert!(matches!(err, GossipError::AlreadyStarted));
}

/// **Row:** `test_stop_disconnects_peers` — with zero peers (pre–CON-001), `stop` completes cleanly.
///
/// **Future:** extend with mock peers once connection map is populated.
#[tokio::test]
async fn test_stop_disconnects_peers() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let _h = svc.start().await.expect("start");
    svc.stop().await.expect("stop");
}

/// **Row:** `test_handle_after_stop` — [`dig_gossip::GossipHandle::health_check`] returns
/// [`GossipError::ServiceNotStarted`] after [`GossipService::stop`].
#[tokio::test]
async fn test_handle_after_stop() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    svc.stop().await.expect("stop");
    let err = handle.health_check().await.unwrap_err();
    assert!(matches!(err, GossipError::ServiceNotStarted));
}

/// **Extra:** invalid `network_id` (all zero) must fail fast with [`GossipError::InvalidConfig`].
#[test]
fn test_new_rejects_zero_network_id() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.network_id = Bytes32::default();
    let err = GossipService::new(cfg).unwrap_err();
    assert!(matches!(err, GossipError::InvalidConfig(_)));
}

/// **Extra:** outbound target cannot exceed connection cap (API-001 validation bullet).
#[test]
fn test_new_rejects_bad_connection_limits() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    cfg.target_outbound_count = 100;
    cfg.max_connections = 10;
    let err = GossipService::new(cfg).unwrap_err();
    assert!(matches!(err, GossipError::InvalidConfig(_)));
}
