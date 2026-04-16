//! # dig-gossip
//!
//! Peer-to-peer networking and gossip for the DIG Network L2 blockchain.
//!
//! ## What this crate does
//!
//! `dig-gossip` handles peer discovery, connection management, and message routing
//! between DIG full nodes. It accepts application-level payloads (blocks, transactions,
//! attestations) as opaque `Message` bytes and delivers them to connected peers via
//! a Chia-compatible gossip protocol enhanced with Plumtree, ERLAY, priority lanes,
//! compact blocks, Dandelion++ privacy, and relay fallback.
//!
//! ## What this crate does NOT do
//!
//! - **No block validation** — the caller validates blocks before broadcasting
//! - **No CLVM execution** — payload-agnostic transport only
//! - **No mempool management** — handled by `dig-mempool`
//! - **No consensus** — fork choice, finality, validator management are external
//!
//! ## Lifecycle
//!
//! ```rust,ignore
//! use dig_gossip::{GossipConfig, GossipService, GossipError};
//!
//! // 1. Configure
//! let config = GossipConfig::default();
//!
//! // 2. Construct (loads TLS certificates, creates address manager)
//! let service = GossipService::new(config)?;
//!
//! // 3. Start (binds listener, spawns background tasks, returns handle)
//! let handle = service.start().await?;
//!
//! // 4. Use the handle (Send + Sync + Clone — share across tasks)
//! handle.broadcast(message, None).await?;          // send to peers
//! let rx = handle.inbound_receiver()?;              // receive from peers
//! let stats = handle.stats().await;                 // observe metrics
//! let peer_id = handle.connect_to(addr).await?;     // manual connect
//!
//! // 5. Stop (disconnects peers, saves address manager, cancels tasks)
//! service.stop().await?;
//! ```
//!
//! ## Inputs and Outputs
//!
//! | Direction | Type | Description |
//! |-----------|------|-------------|
//! | **In** | [`GossipConfig`] | All configuration (ports, TLS, discovery, relay) |
//! | **In** | [`Message`] via [`GossipHandle::broadcast()`] | Payload to send to peers |
//! | **Out** | `(PeerId, Message)` via [`GossipHandle::inbound_receiver()`] | Received payloads |
//! | **Out** | [`GossipStats`] via [`GossipHandle::stats()`] | Network metrics |
//!
//! ## Feature Flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `native-tls` | ✓ | OS-native TLS (OpenSSL/Schannel/SecureTransport) |
//! | `rustls` | | Pure-Rust TLS alternative |
//! | `relay` | ✓ | Relay server fallback for NAT traversal |
//! | `erlay` | ✓ | ERLAY transaction relay (low-fanout + reconciliation) |
//! | `compact-blocks` | ✓ | Compact block relay (BIP 152 style) |
//! | `dandelion` | ✓ | Dandelion++ transaction origin privacy |
//! | `tor` | | Tor/SOCKS5 proxy transport (opt-in) |
//!
//! ## SPEC Reference
//!
//! - **Master specification:** `docs/resources/SPEC.md`
//! - **Requirements:** `docs/requirements/README.md`
//! - **Implementation order:** `docs/requirements/IMPLEMENTATION_ORDER.md`

#![forbid(unsafe_code)]
// Suppress pre-existing clippy warnings from ported CAddrMan code and known patterns.
#![allow(
    clippy::needless_range_loop,
    clippy::if_same_then_else,
    clippy::doc_lazy_continuation,
    clippy::manual_unwrap_or_default
)]

// =============================================================================
// Modules
// =============================================================================

pub mod connection;
pub mod constants;
pub mod discovery;
pub mod error;
pub mod gossip;
pub mod service;
pub mod types;
pub mod util;

#[cfg(feature = "relay")]
pub mod relay;

#[cfg(any(feature = "dandelion", feature = "tor"))]
pub mod privacy;

// =============================================================================
// Public API — what external callers import (INT-013)
// =============================================================================

// -- Core lifecycle types --
pub use error::GossipError;
pub use service::gossip_handle::GossipHandle;
pub use service::gossip_service::GossipService;

// -- Configuration --
#[cfg(feature = "dandelion")]
pub use types::config::DandelionConfig;
#[cfg(feature = "erlay")]
pub use types::config::ErlayConfig;
pub use types::config::{GossipConfig, IntroducerConfig, PeerIdRotationConfig, RelayConfig};

// -- Peer types --
pub use types::dig_messages::{DigMessageType, UnknownDigMessageType};
pub use types::peer::{ExtendedPeerInfo, PeerConnection, PeerId, PeerInfo};
pub use types::reputation::{PeerReputation, PenaltyReason};
pub use types::stats::{GossipStats, RelayStats};

// -- Discovery --
pub use discovery::address_manager::AddressManager;
pub use discovery::introducer_client::IntroducerClient;
pub use discovery::introducer_peers::{IntroducerPeers, VettedPeer};

// -- Chia protocol types (re-exported, not reimplemented) --
pub use dig_protocol::{
    Bytes, Bytes32, ChiaProtocolMessage, FullBlock, Handshake, Message, NewPeak, NewTransaction,
    NewUnfinishedBlock, NodeType, ProtocolMessageTypes, RejectBlock, RejectBlocks, RequestBlock,
    RequestBlocks, RequestMempoolTransactions, RequestPeers, RequestTransaction,
    RequestUnfinishedBlock, RespondBlock, RespondBlocks, RespondPeers, RespondTransaction,
    RespondUnfinishedBlock, SpendBundle, TimestampedPeerInfo,
};
pub use dig_protocol::{
    load_ssl_cert, Client, ClientError, ClientState, Network, Peer, PeerOptions, RateLimit,
    RateLimiter, RateLimits, V2_RATE_LIMITS,
};
pub use dig_protocol::ChiaCertificate;
pub use dig_protocol::Streamable;

// -- Feature-gated public types --
#[cfg(feature = "native-tls")]
pub use dig_protocol::create_native_tls_connector;
#[cfg(all(feature = "rustls", not(feature = "native-tls")))]
pub use dig_protocol::create_rustls_connector;

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

#[cfg(feature = "tor")]
pub use privacy::tor::{TorConfig, TorTransportConfig};

// -- Constants (flat namespace) --
pub use constants::*;

// =============================================================================
// Internal re-exports — visible to tests but not part of the user-facing API.
// These are #[doc(hidden)] so `cargo doc` doesn't show them.
// Tests import via `dig_gossip::` but they won't appear in documentation.
// =============================================================================

#[doc(hidden)]
pub use connection::inbound_limits::{
    dig_extension_rate_limits_map, gossip_inbound_rate_limits, new_inbound_rate_limiter,
};
#[doc(hidden)]
pub use discovery::address_manager_store::{
    AddressManagerState, AddressManagerStore, ADDRESS_MANAGER_STATE_VERSION,
};
#[doc(hidden)]
pub use discovery::introducer_client::PeerRegistration;
#[doc(hidden)]
pub use discovery::introducer_register_wire::{RegisterAck, RegisterPeer};
#[doc(hidden)]
pub use discovery::introducer_wire::{RequestPeersIntroducer, RespondPeersIntroducer};
#[doc(hidden)]
pub use discovery::node_discovery::{
    cap_received_peers, dig_network_from_gossip_config, dns_lookup_seed_addrs,
    dns_seed_resolve_and_merge, merge_dns_seed_addrs_into_address_manager, parallel_connect_batch,
    poisson_next_interval, run_discovery_loop, run_feeler_loop,
    timestamped_peer_infos_from_dns_addrs, ConnectResult, DiscoveryAction, FeelerAction,
};
#[doc(hidden)]
pub use gossip::backpressure::BackpressureConfig;
#[doc(hidden)]
pub use service::state::{apply_inbound_rate_limit_violation, peer_id_for_addr, ServiceState};
#[doc(hidden)]
pub use types::config::DEFAULT_INTRODUCER_NETWORK_ID;
#[doc(hidden)]
pub use types::peer::{
    aggregate_peer_connection_io, message_wire_len, metric_unix_timestamp_secs,
    peer_id_from_tls_spki_der, PeerConnectionWireMetrics,
};
