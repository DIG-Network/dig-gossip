//! Unified error type for the gossip crate.
//!
//! **Requirement:** Re-exported at crate root per STR-003 /
//! [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 10.2.
//! **Behavioral spec:** [`docs/requirements/domains/crate_api/specs/API-004.md`](../docs/requirements/domains/crate_api/specs/API-004.md)
//! (additional variants will wrap discovery/relay errors later).

use thiserror::Error;

/// Top-level error for DIG gossip operations.
///
/// Today this is a thin wrapper around [`chia_sdk_client::ClientError`] because outbound
/// connects, TLS, and rate limiting all surface that type first. Future requirements
/// extend this enum with discovery, relay, and validation-lite failures without breaking
/// call sites that already pattern-match on `GossipError::Client`.
#[derive(Debug, Error)]
pub enum GossipError {
    /// Errors from `chia-sdk-client` (`connect_peer`, certificate loading, wire failures).
    #[error(transparent)]
    Client(#[from] chia_sdk_client::ClientError),
}
