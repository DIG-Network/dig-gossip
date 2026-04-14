//! Unified error type for the gossip crate.
//!
//! **Requirement:** Re-exported at crate root per STR-003 /
//! [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 10.2.
//! **Behavioral spec:** [`API-004.md`](../docs/requirements/domains/crate_api/specs/API-004.md)
//! — this file grows toward that full variant set; API-001 adds lifecycle and I/O surface area
//! needed by [`GossipService::new`](crate::service::gossip_service::GossipService::new).

use thiserror::Error;

/// Top-level error for DIG gossip operations.
///
/// `ClientError` maps TLS / wire failures from `chia-sdk-client`. Plain file failures are often
/// surfaced as [`ClientError::Io`](chia_sdk_client::ClientError::Io); [`GossipService::new`](crate::service::gossip_service::GossipService::new)
/// maps those to [`GossipError::IoError`] so tests can distinguish “bad PEM path” without
/// depending on nested SDK structure (API-001 test plan).
#[derive(Debug, Error)]
pub enum GossipError {
    /// Errors from `chia-sdk-client` (`connect_peer`, certificate loading, wire failures).
    ///
    /// **Layout:** boxed so `Result<_, GossipError>` stays small (`clippy::result_large_err`).
    #[error("client error: {0}")]
    ClientError(Box<chia_sdk_client::ClientError>),

    /// File-system or PEM read/write failures surfaced as stable strings (clone-friendly).
    #[error("I/O error: {0}")]
    IoError(String),

    /// Static validation of [`crate::types::config::GossipConfig`] before runtime work (API-001 §Construction).
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Handle operation while the service is not running (between `stop()` and a future `start()`, or before `start()`).
    #[error("service not started")]
    ServiceNotStarted,

    /// Second [`crate::service::gossip_service::GossipService::start`] while already running (API-001).
    #[error("service already running")]
    AlreadyStarted,
}

impl From<chia_sdk_client::ClientError> for GossipError {
    fn from(value: chia_sdk_client::ClientError) -> Self {
        Self::ClientError(Box::new(value))
    }
}
