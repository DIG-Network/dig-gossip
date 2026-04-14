//! Unified error type for the gossip crate.
//!
//! **Requirement:** Re-exported at crate root per STR-003 /
//! [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 10.2.
//! **Behavioral spec:** [`API-004.md`](../docs/requirements/domains/crate_api/specs/API-004.md)
//! — API-002 extends variants for handle RPCs; full matrix lands with API-004 tests.

use thiserror::Error;

use crate::types::peer::PeerId;

/// Top-level error for DIG gossip operations.
#[derive(Debug, Error)]
pub enum GossipError {
    /// Errors from `chia-sdk-client` (`connect_peer`, certificate loading, wire failures).
    ///
    /// **Layout:** boxed so `Result<_, GossipError>` stays small (`clippy::result_large_err`).
    #[error("client error: {0}")]
    ClientError(Box<chia_sdk_client::ClientError>),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("service not started")]
    ServiceNotStarted,

    #[error("service already running")]
    AlreadyStarted,

    // --- API-002 / API-004 lifecycle & peers ---
    #[error("peer not connected: {0}")]
    PeerNotConnected(PeerId),

    #[error("peer banned: {0}")]
    PeerBanned(PeerId),

    #[error("max connections reached ({0})")]
    MaxConnectionsReached(usize),

    #[error("duplicate connection to peer {0}")]
    DuplicateConnection(PeerId),

    #[error("self connection detected")]
    SelfConnection,

    #[error("request timeout")]
    RequestTimeout,

    #[error("introducer not configured")]
    IntroducerNotConfigured,

    #[error("introducer error: {0}")]
    IntroducerError(String),

    #[error("relay not configured")]
    RelayNotConfigured,

    #[error("relay error: {0}")]
    RelayError(String),

    #[error("channel closed")]
    ChannelClosed,
}

impl From<chia_sdk_client::ClientError> for GossipError {
    fn from(value: chia_sdk_client::ClientError) -> Self {
        Self::ClientError(Box::new(value))
    }
}
