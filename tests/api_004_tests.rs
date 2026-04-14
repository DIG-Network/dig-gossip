//! Integration tests for **API-004: `GossipError` enum** (variants, `Display`, `Clone`, `From`).
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`API-004.md`](../docs/requirements/domains/crate_api/specs/API-004.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/crate_api/NORMATIVE.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) Section 4
//!
//! ## Proof strategy
//!
//! Each test maps to a row in API-004’s “Verification / Test Plan” table. We assert **stable
//! `Display` substrings** (via [`std::string::ToString`]) rather than pinning upstream `ClientError`
//! formatting beyond the `client error:` prefix, because chia-sdk-client may refine wording in patch
//! releases. **Shape proofs** (`From`, `?`, [`Clone`]) use variants whose messages are fully local.

use dig_gossip::{ClientError, GossipError, PeerId};

fn sample_peer() -> PeerId {
    // Deterministic non-default id so hex appears consistently in Display output.
    PeerId::from([0xABu8; 32])
}

/// **Row:** `test_client_error_from` — [`From`] / [`GossipError::ClientError`].
///
/// **Why:** API-004 requires `ClientError` → `GossipError` conversion; integration tests use a variant
/// that does not need I/O (`UnsupportedTls`).
#[test]
fn test_client_error_from() {
    let e = ClientError::UnsupportedTls;
    let g: GossipError = e.into();
    match g {
        GossipError::ClientError(arc) => {
            assert!(matches!(arc.as_ref(), ClientError::UnsupportedTls));
        }
        _ => panic!("expected ClientError variant"),
    }
}

/// **Row:** `test_peer_not_connected_display`
#[test]
fn test_peer_not_connected_display() {
    let g = GossipError::PeerNotConnected(sample_peer());
    let s = g.to_string();
    assert!(
        s.starts_with("peer not connected:"),
        "unexpected display: {s}"
    );
    assert!(
        s.contains("ab"),
        "PeerId hex should include repeated0xAB bytes: {s}"
    );
}

/// **Row:** `test_peer_banned_display`
#[test]
fn test_peer_banned_display() {
    let g = GossipError::PeerBanned(sample_peer());
    let s = g.to_string();
    assert!(s.starts_with("peer banned:"), "unexpected display: {s}");
}

/// **Row:** `test_max_connections_display`
#[test]
fn test_max_connections_display() {
    let g = GossipError::MaxConnectionsReached(50);
    assert_eq!(g.to_string(), "max connections reached (50)");
}

/// **Row:** `test_duplicate_connection_display`
#[test]
fn test_duplicate_connection_display() {
    let g = GossipError::DuplicateConnection(sample_peer());
    let s = g.to_string();
    assert!(
        s.starts_with("duplicate connection to peer"),
        "unexpected display: {s}"
    );
}

/// **Row:** `test_self_connection_display`
#[test]
fn test_self_connection_display() {
    assert_eq!(
        GossipError::SelfConnection.to_string(),
        "self connection detected"
    );
}

/// **Row:** `test_request_timeout_display`
#[test]
fn test_request_timeout_display() {
    assert_eq!(GossipError::RequestTimeout.to_string(), "request timeout");
}

/// **Row:** `test_introducer_not_configured_display`
#[test]
fn test_introducer_not_configured_display() {
    assert_eq!(
        GossipError::IntroducerNotConfigured.to_string(),
        "introducer not configured"
    );
}

/// **Row:** `test_introducer_error_display`
#[test]
fn test_introducer_error_display() {
    assert_eq!(
        GossipError::IntroducerError("timeout".to_string()).to_string(),
        "introducer error: timeout"
    );
}

/// **Row:** `test_relay_not_configured_display`
#[test]
fn test_relay_not_configured_display() {
    assert_eq!(
        GossipError::RelayNotConfigured.to_string(),
        "relay not configured"
    );
}

/// **Row:** `test_relay_error_display`
#[test]
fn test_relay_error_display() {
    assert_eq!(
        GossipError::RelayError("disconnected".to_string()).to_string(),
        "relay error: disconnected"
    );
}

/// **Row:** `test_service_not_started_display`
#[test]
fn test_service_not_started_display() {
    assert_eq!(
        GossipError::ServiceNotStarted.to_string(),
        "service not started"
    );
}

/// **Row:** `test_channel_closed_display`
#[test]
fn test_channel_closed_display() {
    assert_eq!(GossipError::ChannelClosed.to_string(), "channel closed");
}

/// **Row:** `test_io_error_display`
#[test]
fn test_io_error_display() {
    assert_eq!(
        GossipError::IoError("file not found".to_string()).to_string(),
        "I/O error: file not found"
    );
}

/// **Row:** `test_sketch_error_display`
#[test]
fn test_sketch_error_display() {
    assert_eq!(
        GossipError::SketchError("capacity exceeded".to_string()).to_string(),
        "sketch error: capacity exceeded"
    );
}

/// **Row:** `test_sketch_decode_failed_display`
#[test]
fn test_sketch_decode_failed_display() {
    assert_eq!(
        GossipError::SketchDecodeFailed.to_string(),
        "sketch decode failed"
    );
}

/// **Row:** `test_error_is_debug`
#[test]
fn test_error_is_debug() {
    let g = GossipError::RequestTimeout;
    let d = format!("{g:?}");
    assert!(
        d.contains("RequestTimeout"),
        "Debug should name the variant: {d}"
    );
}

/// **Row:** `test_error_is_clone`
#[test]
fn test_error_is_clone() {
    let a = GossipError::ChannelClosed;
    let b = a.clone();
    assert_eq!(a.to_string(), b.to_string());

    let c: GossipError = ClientError::UnsupportedTls.into();
    let d = c.clone();
    assert_eq!(c.to_string(), d.to_string());
}

/// **Row:** `test_question_mark_operator`
#[test]
fn test_question_mark_operator() {
    fn propagate() -> Result<(), GossipError> {
        Err(ClientError::UnsupportedTls)?;
        Ok(())
    }
    let r = propagate();
    assert!(r.is_err(), "expected Err from ? on ClientError");
    match r {
        Err(GossipError::ClientError(_)) => {}
        e => panic!("unexpected result: {e:?}"),
    }
}
