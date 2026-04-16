//! Integration and unit tests for **CON-009: mandatory mutual TLS (mTLS) via `chia-ssl` on P2P connections**.
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`CON-009.md`](../docs/requirements/domains/connection/specs/CON-009.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/connection/NORMATIVE.md) (CON-009)
//! - **Verification matrix:** [`VERIFICATION.md`](../docs/requirements/domains/connection/VERIFICATION.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) section 5.3 (Mandatory Mutual TLS)
//!
//! ## Proof strategy
//!
//! 1. **Outbound client identity** — [`dig_gossip::create_native_tls_connector`] (vendored `chia-sdk-client`
//!    `tls.rs`) attaches the node [`ChiaCertificate`](dig_gossip::ChiaCertificate) as a TLS **client**
//!    identity. We assert connector construction succeeds for real PEM material produced by the same
//!    harness as CON-001/CON-002.
//! 2. **Inbound server requires client certs (OpenSSL only)** — On Linux and other **OpenSSL-backed**
//!    `native-tls` targets, this repository patches `native-tls` (see `vendor/native-tls/README.dig-gossip.md`)
//!    so the TLS acceptor sets `CERT_REQUIRED` and trusts the Chia CA. A raw TLS client **without** a
//!    client certificate therefore fails during `TlsConnector::connect` **before** any WebSocket bytes,
//!    proving we do not accept server-only TLS for P2P on that platform matrix.
//! 3. **End-to-end mTLS** — [`GossipHandle::connect_to`] completes against a live [`GossipService`] listener,
//!    demonstrating both sides present Chia-shaped certificates and the connection reaches the
//!    handshake stage (same causal chain as CON-002, now tied to CON-009 normative text).
//! 4. **Windows / macOS note** — `native-tls` uses SChannel / SecureTransport there; the strict
//!    “no client cert” negative test is **cfg-gated** to OpenSSL backends only. See `listener.rs`
//!    module docs for the `peer_id_for_addr` fallback rationale on those OSes.
//!
//! **Relay exemption** (`test_relay_exempt_from_mtls_documented`) is tracked as an ignored placeholder:
//! relay uses public `wss://` without Chia mTLS and is out of scope for this crate’s automated suite.

mod common;

use std::time::Duration;

use dig_gossip::{create_native_tls_connector, load_ssl_cert, GossipHandle, GossipService};
#[cfg(all(
    not(target_os = "windows"),
    not(target_vendor = "apple"),
    feature = "native-tls"
))]
use native_tls::TlsConnector;
#[cfg(all(
    not(target_os = "windows"),
    not(target_vendor = "apple"),
    feature = "native-tls"
))]
use tokio_native_tls::TlsConnector as TokioTlsConnector;

/// Start listener + handle (same pattern as `tests/con_002_tests.rs`).
async fn running_server() -> (
    tempfile::TempDir,
    GossipService,
    GossipHandle,
    std::net::SocketAddr,
) {
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

/// **Row:** `test_native_tls_mtls_connector` — outbound connector includes PKCS#8 identity material.
///
/// Passing proves CON-009 acceptance “outbound uses TLS connector with client cert”: the
/// `create_native_tls_connector` path used by production `connect_to` accepts a [`ChiaCertificate`]
/// produced by the STR-005 harness (same files as CON-001).
#[test]
fn test_native_tls_mtls_connector() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let cert = load_ssl_cert(&cfg.cert_path, &cfg.key_path).expect("load_ssl_cert");
    let _ = create_native_tls_connector(&cert).expect("native-tls connector with client identity");
}

/// **Row:** `test_rustls_mtls_connector` — when the `rustls` feature is enabled, rustls connector also carries client auth.
///
/// Default CI enables both TLS stacks; this compiles only when `rustls` is selected so `--no-default-features`
/// graphs stay checkable.
#[cfg(feature = "rustls")]
#[test]
fn test_rustls_mtls_connector() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let cert = load_ssl_cert(&cfg.cert_path, &cfg.key_path).expect("load_ssl_cert");
    let _ = dig_protocol::create_rustls_connector(&cert)
        .expect("rustls connector with client identity");
}

/// **Row:** `test_cert_generate_on_first_run` / `test_cert_load_on_subsequent_run` — `load_ssl_cert` create vs reuse.
#[test]
fn test_cert_generate_then_load_roundtrip() {
    let dir = common::test_temp_dir();
    let cfg = common::test_gossip_config(dir.path());
    let c1 = load_ssl_cert(&cfg.cert_path, &cfg.key_path).expect("first load generates");
    assert!(!c1.cert_pem.is_empty() && !c1.key_pem.is_empty());
    let c2 = load_ssl_cert(&cfg.cert_path, &cfg.key_path).expect("second load reads same files");
    assert_eq!(c1.cert_pem, c2.cert_pem);
    assert_eq!(c1.key_pem, c2.key_pem);
}

/// **Row:** `test_corrupt_cert_errors` — PKCS#8 identity parse rejects garbage without silently disabling TLS.
#[test]
fn test_corrupt_identity_rejected() {
    let err = native_tls::Identity::from_pkcs8(
        b"not valid pem",
        b"-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----",
    );
    assert!(
        err.is_err(),
        "corrupt cert material must not parse as Identity"
    );
}

/// **Row:** `test_openssl_inbound_rejects_client_without_cert` — server-only TLS client must not complete TLS.
///
/// Only meaningful where the **patched** OpenSSL `native-tls` acceptor runs (Linux-class targets).
#[tokio::test]
#[cfg(all(
    not(target_os = "windows"),
    not(target_vendor = "apple"),
    feature = "native-tls"
))]
async fn test_openssl_inbound_rejects_client_without_cert() {
    let (_dir, svc, h, bound) = running_server().await;
    let tcp = tokio::net::TcpStream::connect(bound)
        .await
        .expect("tcp connect");
    let cx = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("tls connector without client identity");
    let cx = TokioTlsConnector::from(cx);
    let outcome = cx.connect("localhost", tcp).await;
    assert!(
        outcome.is_err(),
        "inbound listener must reject TLS clients that present no client certificate on OpenSSL; got {outcome:?}"
    );
    drop(h);
    svc.stop().await.expect("stop");
}

/// **Row:** `test_inbound_mtls_with_client_cert` / `test_peer_id_derived_from_remote_cert` — full outbound dial succeeds.
///
/// `connect_to` returns the **remote** [`PeerId`] from the dialer’s perspective (hash of the **listener’s**
/// certificate), not the dialer’s own identity — so we assert the listener recorded **one** peer slot,
/// proving the inbound mTLS + WebSocket + handshake pipeline accepted a mutually authenticated session.
#[tokio::test]
async fn test_connect_to_succeeds_with_mutual_chia_certs() {
    let (_dir_a, svc_a, h_a, bound) = running_server().await;
    let (_dir_b, svc_b, h_b) = outbound_client().await;
    let remote_at_client = h_b
        .connect_to(bound)
        .await
        .expect("mTLS connect_to should succeed with Chia client cert");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h_a.peer_count().await, 1);
    let keys = h_a.__peer_ids_for_tests();
    assert_eq!(
        keys.len(),
        1,
        "listener should insert exactly one live peer"
    );
    let _ = h_b.disconnect(&remote_at_client).await;
    let _ = h_a.disconnect(&keys[0]).await;
    let _ = svc_b.stop().await;
    let _ = svc_a.stop().await;
}

async fn outbound_client() -> (tempfile::TempDir, GossipService, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("client new");
    let h = svc.start().await.expect("client start");
    (dir, svc, h)
}

/// **Row:** `test_relay_exempt_from_mtls` — relay uses operator `wss://`, not Chia mTLS (documented / ignored here).
#[test]
#[ignore = "Relay live endpoints are environment-specific; CON-009 exempts relay from chia-ssl mTLS per spec."]
fn test_relay_exempt_from_mtls_documented() {
    // Intentionally empty — the `#[ignore]` documents the acceptance criterion for humans / CI filters.
}
