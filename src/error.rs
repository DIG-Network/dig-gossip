//! Unified error type for the gossip crate.
//!
//! **Re-export:** STR-003 — [`SPEC.md`](../docs/resources/SPEC.md) Section 10.2 (`GossipError` at crate root).
//!
//! **Normative matrix:** [`API-004.md`](../docs/requirements/domains/crate_api/specs/API-004.md) and
//! SPEC Section 4 — lifecycle, peer, discovery, relay, and transport errors share one `enum` so
//! [`GossipService`](crate::service::gossip_service::GossipService) / [`GossipHandle`](crate::service::gossip_handle::GossipHandle)
//! callers use a single `Result` boundary.
//!
//! ## `ClientError` and `Clone`
//!
//! Upstream [`chia_sdk_client::ClientError`] derives [`std::fmt::Debug`] and [`thiserror::Error`] but
//! **not** [`Clone`]. API-004 still requires [`GossipError`] to be cloneable (cheap retries, multi-owner
//! handles). We therefore store client failures as [`std::sync::Arc`]`<ClientError>` (see variant
//! [`GossipError::ClientError`]): [`From`] still accepts a bare `ClientError`, and [`Clone`] duplicates
//! the handle only. This matches the API-004 implementation note (“boxed representation”) while
//! satisfying `Clone` without losing structured upstream errors.

use std::sync::Arc;

use thiserror::Error;

use crate::types::peer::PeerId;

/// Top-level error for DIG gossip operations.
///
/// **Variants:** API-004 core set plus API-001 helpers [`GossipError::InvalidConfig`] and
/// [`GossipError::AlreadyStarted`] (constructor / lifecycle — kept to avoid churn in [`API-001.md`](../docs/requirements/domains/crate_api/specs/API-001.md) tests).
#[derive(Debug, Clone, Error)]
pub enum GossipError {
    /// Errors from `chia-sdk-client` (`connect_peer`, certificate loading, wire failures).
    ///
    /// Wrapped in [`Arc`] so [`GossipError`] remains [`Clone`] even though [`chia_sdk_client::ClientError`]
    /// is not (API-004 implementation notes).
    #[error("client error: {0}")]
    ClientError(Arc<chia_sdk_client::ClientError>),

    #[error("I/O error: {0}")]
    IoError(String),

    /// Configuration rejected before networking (API-001 [`GossipService::new`](crate::service::gossip_service::GossipService::new)).
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("service not started")]
    ServiceNotStarted,

    #[error("service already running")]
    AlreadyStarted,

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

    /// Minisketch / set-reconciliation failure (ERLAY — [`SPEC.md`](../docs/resources/SPEC.md) §8.3).
    #[error("sketch error: {0}")]
    SketchError(String),

    /// Sketch could not decode symmetric difference (capacity / corruption — API-004 table).
    #[error("sketch decode failed")]
    SketchDecodeFailed,
}

impl From<chia_sdk_client::ClientError> for GossipError {
    fn from(value: chia_sdk_client::ClientError) -> Self {
        Self::ClientError(Arc::new(value))
    }
}
