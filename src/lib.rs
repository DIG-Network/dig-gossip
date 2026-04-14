//! # dig-gossip
//!
//! DIG Network L2 peer gossip, discovery, relay, and related protocol plumbing.
//!
//! ## Documentation map
//!
//! - **Master specification:** [`docs/resources/SPEC.md`](../docs/resources/SPEC.md)
//! - **Traceable requirements:** [`docs/requirements/README.md`](../docs/requirements/README.md)
//! - **Crate layout:** STR-002 —
//!   [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! - **Public re-exports (this file, bottom):** STR-003 —
//!   [`docs/requirements/domains/crate_structure/specs/STR-003.md`](../docs/requirements/domains/crate_structure/specs/STR-003.md)
//!   and SPEC Section 10.2.
//! - **Feature flags:** STR-004 —
//!   [`docs/requirements/domains/crate_structure/specs/STR-004.md`](../docs/requirements/domains/crate_structure/specs/STR-004.md)
//!   and SPEC Section 10.3.
//!
//! ## Module tree (STR-002)
//!
//! Subsystems are split so each directory maps to a requirements domain (`connection/`,
//! `discovery/`, `gossip/`, …). Optional compilation (`relay`, `compact-blocks`, `erlay`,
//! `dandelion`, `tor`) keeps minimal TLS-only graphs lean for CI.
//!
//! ## Design constraints (from SPEC)
//!
//! - Reuse Chia crates for protocol types and peer IO; do not redefine
//!   `Handshake`, `Message`, `Peer`, etc.
//! - No consensus validation in this crate — it transports messages only.
//!
//! ## Safety
//!
//! This crate forbids `unsafe` at the crate root so new modules inherit the policy.

#![forbid(unsafe_code)]

pub mod connection;
pub mod constants;
pub mod discovery;
pub mod error;
pub mod gossip;
pub mod service;
pub mod types;
pub mod util;

/// Relay fallback — WebSocket client, service lifecycle, relay wire types.
///
/// **Feature:** `relay` ([`Cargo.toml`](../Cargo.toml)).
/// **Spec:** [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 7.
#[cfg(feature = "relay")]
pub mod relay;

/// Privacy transport and propagation (`dandelion`, `tor` features — STR-004 / SPEC 10.1 `privacy/`).
///
/// Compiled when **either** `dandelion` or `tor` is enabled so Tor-only builds do not pull Dandelion code.
#[cfg(any(feature = "dandelion", feature = "tor"))]
pub mod privacy;

// =============================================================================
// Re-exports — STR-003 / SPEC Section 10.2
// =============================================================================
//
// Rationale: downstream crates (`l2_driver`, tools, tests) import Chia and DIG types from
// `dig_gossip::*` so they never depend on our internal module paths staying stable.

// ---------------------------------------------------------------------------
// Chia crates (NOT reimplemented)
// ---------------------------------------------------------------------------
// Introducer opcodes (`RequestPeersIntroducer`, `RespondPeersIntroducer`) live on
// [`ProtocolMessageTypes`] in `chia-protocol` 0.26 — they are not standalone structs.
pub use chia_protocol::{
    Bytes32, ChiaProtocolMessage, FullBlock, Handshake, Message, NewPeak, NewTransaction,
    NewUnfinishedBlock, NodeType, ProtocolMessageTypes, RejectBlock, RejectBlocks, RequestBlock,
    RequestBlocks, RequestMempoolTransactions, RequestPeers, RequestTransaction,
    RequestUnfinishedBlock, RespondBlock, RespondBlocks, RespondPeers, RespondTransaction,
    RespondUnfinishedBlock, SpendBundle, TimestampedPeerInfo,
};
pub use chia_sdk_client::{
    load_ssl_cert, Client, ClientError, ClientState, Network, Peer, PeerOptions, RateLimit,
    RateLimiter, RateLimits, V2_RATE_LIMITS,
};
pub use chia_ssl::ChiaCertificate;
pub use chia_traits::Streamable;

// ---------------------------------------------------------------------------
// DIG-specific (implemented here)
// ---------------------------------------------------------------------------
pub use gossip::backpressure::BackpressureConfig;
#[cfg(feature = "dandelion")]
pub use types::config::DandelionConfig;
#[cfg(feature = "erlay")]
pub use types::config::ErlayConfig;
pub use types::config::{GossipConfig, IntroducerConfig, PeerIdRotationConfig, RelayConfig};
pub use types::dig_messages::DigMessageType;
pub use types::peer::{peer_id_from_tls_spki_der, PeerConnection, PeerId, PeerInfo};
pub use types::reputation::{PeerReputation, PenaltyReason};
pub use types::stats::{GossipStats, RelayStats};

pub use discovery::address_manager::AddressManager;
pub use discovery::introducer_client::IntroducerClient;
pub use discovery::introducer_peers::{IntroducerPeers, VettedPeer};

pub use error::GossipError;

pub use service::gossip_handle::GossipHandle;
pub use service::gossip_service::GossipService;

/// Relay protocol types — only when `relay` feature is enabled (matches STR-003 notes).
#[cfg(feature = "relay")]
pub use relay::relay_types::{RelayMessage, RelayPeerInfo};

#[cfg(feature = "compact-blocks")]
pub use gossip::compact_block::{
    CompactBlock, PrefilledTransaction, RequestBlockTransactions, RespondBlockTransactions,
    ShortTxId,
};

#[cfg(feature = "erlay")]
pub use gossip::erlay::{ErlayState, ReconciliationSketch};

#[cfg(feature = "dandelion")]
pub use privacy::dandelion::StemTransaction;

/// Tor/SOCKS transport configuration (feature `tor`). `TorTransportConfig` is a legacy alias.
#[cfg(feature = "tor")]
pub use privacy::tor::{TorConfig, TorTransportConfig};

pub use constants::*;
