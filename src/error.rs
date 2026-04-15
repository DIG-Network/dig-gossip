//! Unified error type for all DIG gossip operations.
//!
//! [`GossipError`] is the single `Result` boundary for every public method on
//! [`GossipService`](crate::service::gossip_service::GossipService) and
//! [`GossipHandle`](crate::service::gossip_handle::GossipHandle). Callers never need to
//! match against domain-specific error types -- lifecycle, peer, discovery, relay, and
//! transport errors all collapse into one enum.
//!
//! # Requirement traceability
//!
//! * **API-004** -- normative variant matrix
//!   ([`docs/requirements/domains/crate_api/specs/API-004.md`]).
//! * **SPEC §4** -- canonical enum definition.
//! * **STR-003** -- re-exported at crate root via `pub use error::GossipError`
//!   (SPEC §10.2).
//!
//! # `ClientError` and `Clone`
//!
//! Upstream [`chia_sdk_client::ClientError`] derives [`Debug`] and [`thiserror::Error`]
//! but **not** [`Clone`]. API-004 requires `GossipError` to be cloneable so that handles
//! (which are `Clone`) can cheaply retry or propagate errors. We therefore store client
//! failures as `Arc<ClientError>` (see [`GossipError::ClientError`]):
//!
//! * [`From<ClientError>`] wraps the value in a fresh `Arc`.
//! * [`Clone`] duplicates the `Arc` handle, not the error itself.
//!
//! This matches the API-004 implementation note (“boxed representation”) while satisfying
//! `Clone` without losing structured upstream error information.
//!
//! # Chia equivalent
//!
//! Chia Python raises ad-hoc exceptions throughout `server.py`, `node_discovery.py`, etc.
//! There is no unified error enum. DIG consolidates all error paths so that callers can
//! use a single `?` operator chain regardless of which subsystem failed.

use std::sync::Arc;

use thiserror::Error;

use crate::types::peer::PeerId;

/// Top-level error enum for all DIG gossip operations.
///
/// Every public method on [`GossipService`](crate::service::gossip_service::GossipService)
/// and [`GossipHandle`](crate::service::gossip_handle::GossipHandle) returns
/// `Result<_, GossipError>`. Variants are drawn from the API-004 normative matrix
/// ([`docs/requirements/domains/crate_api/specs/API-004.md`]) plus two API-001 lifecycle
/// helpers ([`InvalidConfig`](Self::InvalidConfig), [`AlreadyStarted`](Self::AlreadyStarted)).
///
/// # Derives
///
/// * [`Debug`] -- required by `thiserror` and for structured logging.
/// * [`Clone`] -- required so [`GossipHandle`](crate::service::gossip_handle::GossipHandle)
///   (which is `Clone`) can propagate errors without consuming them.
/// * [`thiserror::Error`] -- generates `Display` and `Error` impls from `#[error(...)]`.
#[derive(Debug, Clone, Error)]
pub enum GossipError {
    // -- Transport / wire errors -----------------------------------------------

    /// Errors originating from `chia-sdk-client` internals: `connect_peer()`,
    /// TLS connector creation, WebSocket I/O, rate-limiter rejection, etc.
    ///
    /// Wrapped in [`Arc`] so that `GossipError` can derive [`Clone`] even though
    /// [`chia_sdk_client::ClientError`] does not (API-004 implementation notes).
    ///
    /// **When:** Any `chia-sdk-client` call fails (outbound connect, `Peer::send()`,
    /// `Peer::request_raw()`).
    /// **Caller action:** Log the inner error; depending on context, retry the
    /// operation or disconnect the peer.
    /// **Produced by:** [`crate::service::gossip_service::load_tls_material`],
    /// [`crate::service::gossip_handle::GossipHandle::connect_to`],
    /// [`crate::service::gossip_handle::GossipHandle::request`].
    #[error("client error: {0}")]
    ClientError(Arc<chia_sdk_client::ClientError>),

    /// File-system or network I/O failure not covered by [`ClientError`](Self::ClientError).
    ///
    /// Stored as [`String`] (not `std::io::Error`) because `std::io::Error` does not
    /// implement `Clone` (API-004 implementation notes).
    ///
    /// **When:** TLS cert loading/generation, address-manager persistence, TCP bind.
    /// **Caller action:** Check the path or address and retry.
    /// **Produced by:** [`GossipService::new`](crate::service::gossip_service::GossipService::new),
    /// [`GossipService::start`](crate::service::gossip_service::GossipService::start).
    #[error("I/O error: {0}")]
    IoError(String),

    // -- Lifecycle errors ------------------------------------------------------

    /// Configuration validation failed *before* any networking (API-001 §Construction).
    ///
    /// **When:** `GossipService::new()` detects an invalid config field (zero `network_id`,
    /// `target_outbound_count > max_connections`, empty cert path), or `start()` is called
    /// after `stop()`.
    /// **Caller action:** Fix the [`GossipConfig`](crate::types::config::GossipConfig) and
    /// reconstruct.
    /// **Produced by:** [`crate::service::gossip_service::validate_gossip_config`],
    /// [`GossipService::start`](crate::service::gossip_service::GossipService::start).
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// A handle method was called when the service is not in the *running* state.
    ///
    /// **When:** Any [`GossipHandle`](crate::service::gossip_handle::GossipHandle) method
    /// is invoked before `start()` or after `stop()`.
    /// **Caller action:** Ensure `start()` has returned `Ok` and `stop()` has not been
    /// called.
    /// **Produced by:** every `GossipHandle` public method's lifecycle guard.
    #[error("service not started")]
    ServiceNotStarted,

    /// `start()` was called on an already-running service (API-001 acceptance criterion).
    ///
    /// **When:** Second call to `GossipService::start()`.
    /// **Caller action:** Do not call `start()` more than once.
    /// **Produced by:** [`GossipService::start`](crate::service::gossip_service::GossipService::start).
    #[error("service already running")]
    AlreadyStarted,

    // -- Peer-management errors ------------------------------------------------

    /// The specified peer is not in the connection map.
    ///
    /// **When:** `send_to`, `request`, `disconnect`, `ban_peer`, or `penalize_peer`
    /// with an unknown [`PeerId`].
    /// **Caller action:** Verify the peer ID or refresh the connected-peers list.
    /// **Produced by:** [`GossipHandle`](crate::service::gossip_handle::GossipHandle)
    /// peer-targeted methods.
    #[error("peer not connected: {0}")]
    PeerNotConnected(PeerId),

    /// The peer has been banned and the requested operation is refused.
    ///
    /// **When:** `connect_to` or `send_to` targets a peer in the ban list.
    /// **Caller action:** Wait for the ban to expire
    /// ([`BAN_DURATION_SECS`](crate::constants::BAN_DURATION_SECS)) or do not retry.
    /// **Produced by:** [`GossipHandle::connect_to`](crate::service::gossip_handle::GossipHandle),
    /// inbound accept loop.
    #[error("peer banned: {0}")]
    PeerBanned(PeerId),

    /// The connection limit
    /// ([`GossipConfig::max_connections`](crate::types::config::GossipConfig::max_connections))
    /// has been reached.
    ///
    /// **When:** `connect_to` finds the peer map is full.
    /// **Caller action:** Disconnect a low-value peer first, or wait for a disconnect.
    /// **Produced by:** [`GossipHandle::connect_to`](crate::service::gossip_handle::GossipHandle).
    #[error("max connections reached ({0})")]
    MaxConnectionsReached(usize),

    /// A connection to this peer already exists.
    ///
    /// **When:** `connect_to` with a [`PeerId`] that is already in the peer map.
    /// **Caller action:** Use the existing connection.
    /// **Produced by:** [`GossipHandle::connect_to`](crate::service::gossip_handle::GossipHandle).
    #[error("duplicate connection to peer {0}")]
    DuplicateConnection(PeerId),

    /// The target address resolved to our own listen address (self-dial guard).
    ///
    /// **When:** `connect_to` detects that the target matches
    /// [`ServiceState::dial_targets_local_listen`](crate::service::state::ServiceState::dial_targets_local_listen).
    /// **Caller action:** Remove this address from the candidate set.
    /// **Produced by:** [`GossipHandle::connect_to`](crate::service::gossip_handle::GossipHandle).
    #[error("self connection detected")]
    SelfConnection,

    /// An RPC request (`GossipHandle::request`) exceeded its timeout.
    ///
    /// **When:** `tokio::time::timeout` fires before the remote responds.
    /// **Caller action:** Retry or penalize the peer for unresponsiveness.
    /// **Produced by:** [`GossipHandle::request`](crate::service::gossip_handle::GossipHandle),
    /// keepalive loop (CON-004).
    #[error("request timeout")]
    RequestTimeout,

    // -- Discovery errors ------------------------------------------------------

    /// No [`IntroducerConfig`](crate::types::config::IntroducerConfig) was provided.
    ///
    /// **When:** `discover_from_introducer` or `register_with_introducer` is called but
    /// [`GossipConfig::introducer`](crate::types::config::GossipConfig) is `None`.
    /// **Caller action:** Supply an `IntroducerConfig` at construction time.
    /// **Produced by:** introducer-related handle methods.
    #[error("introducer not configured")]
    IntroducerNotConfigured,

    /// Communication with the introducer server failed.
    ///
    /// **When:** Network error, timeout, or malformed response from the introducer.
    /// **Caller action:** Retry with exponential backoff (SPEC §6.4 step 1).
    /// **Produced by:** [`crate::discovery::introducer_client::IntroducerClient`].
    #[error("introducer error: {0}")]
    IntroducerError(String),

    /// No [`RelayConfig`](crate::types::config::RelayConfig) was provided.
    ///
    /// **When:** A relay operation is attempted but
    /// [`GossipConfig::relay`](crate::types::config::GossipConfig) is `None`.
    /// **Caller action:** Supply a `RelayConfig` at construction time if relay fallback
    /// is desired.
    /// **Produced by:** relay-related handle methods.
    #[error("relay not configured")]
    RelayNotConfigured,

    /// Communication with the relay server failed.
    ///
    /// **When:** WebSocket disconnect, message serialization error, or relay protocol
    /// violation (SPEC §7).
    /// **Caller action:** The relay service auto-reconnects; callers can check
    /// `relay_stats()` for status.
    /// **Produced by:** [`crate::relay`] subsystem (future implementation).
    #[error("relay error: {0}")]
    RelayError(String),

    // -- Channel / internal errors ---------------------------------------------

    /// An internal `mpsc` or `broadcast` channel has been closed unexpectedly.
    ///
    /// **When:** The service is shutting down or a background task panicked.
    /// **Caller action:** Treat as fatal for this service instance; create a new one.
    /// **Produced by:** inbound message dispatch, broadcast fan-out.
    #[error("channel closed")]
    ChannelClosed,

    // -- ERLAY / sketch errors -------------------------------------------------

    /// Minisketch encoding or parameter error during ERLAY set reconciliation
    /// (SPEC §8.3).
    ///
    /// **When:** Sketch creation fails (bad capacity), or the remote sent an
    /// incompatible sketch.
    /// **Caller action:** Log and skip this reconciliation round; the next round will
    /// catch up.
    /// **Produced by:** ERLAY reconciliation loop (future implementation).
    #[error("sketch error: {0}")]
    SketchError(String),

    /// Minisketch decoding returned no result because the symmetric difference exceeds
    /// the sketch capacity (API-004 table, SPEC §8.3).
    ///
    /// **When:** The number of differing transaction IDs between local and remote sets
    /// exceeds [`ERLAY_SKETCH_CAPACITY`](crate::constants::ERLAY_SKETCH_CAPACITY).
    /// **Caller action:** Fall back to a full `RequestMempoolTransactions` for this peer.
    /// **Produced by:** ERLAY reconciliation loop (future implementation).
    #[error("sketch decode failed")]
    SketchDecodeFailed,
}

/// Manual [`From`] implementation because the `ClientError` variant stores an [`Arc`],
/// not the value directly. The `#[from]` derive attribute cannot be used with `Arc`
/// wrapping, so we implement it by hand (API-004 acceptance criterion: "ClientError can
/// be converted to GossipError via `?` operator").
impl From<chia_sdk_client::ClientError> for GossipError {
    fn from(value: chia_sdk_client::ClientError) -> Self {
        Self::ClientError(Arc::new(value))
    }
}
