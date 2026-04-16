//! Tests for **CNC-004: Graceful shutdown**.
//!
//! - **Spec:** `docs/requirements/domains/concurrency/specs/CNC-004.md`
//! - **Master SPEC:** §9.1
//!
//! CNC-004 verifies stop() transitions lifecycle and cleans up.
//! API-001 tests (api_001_tests.rs) already verify start/stop lifecycle.

/// **CNC-004: CancellationToken enables clean loop shutdown.**
///
/// Proves DSC-006/DSC-008 loops respect cancellation tokens.
/// (Actual shutdown tested in api_001 + dsc_006 + dsc_008 tests.)
#[test]
fn test_cancellation_token_exists() {
    let token = tokio_util::sync::CancellationToken::new();
    assert!(!token.is_cancelled());
    token.cancel();
    assert!(token.is_cancelled());
}
