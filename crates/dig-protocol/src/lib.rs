//! # dig-protocol
//!
//! DIG Network L2 protocol types — a superset of `chia-protocol`.
//!
//! This crate re-exports the entire Chia protocol ecosystem (`chia-protocol`,
//! `chia-sdk-client`, `chia-ssl`, `chia-traits`) plus DIG-specific extensions
//! (opcodes 200–219). Consumers depend on `dig-protocol` alone instead of
//! importing multiple `chia-*` crates individually.
//!
//! ## What's included
//!
//! | Source crate | What's re-exported |
//! |-------------|-------------------|
//! | `chia-protocol` | All wire types: `Message`, `Handshake`, `ProtocolMessageTypes`, `NodeType`, etc. |
//! | `chia-sdk-client` | `Peer`, `Client`, `ClientError`, `ClientState`, `Network`, `PeerOptions`, rate limiting, TLS connectors |
//! | `chia-ssl` | `ChiaCertificate` |
//! | `chia-traits` | `Streamable` trait |
//! | `chia_streamable_macro` | `#[streamable]` proc macro |
//! | **DIG extensions** | `DigMessage`, `DigMessageType`, `RegisterPeer`, `RegisterAck`, introducer wire types |
//!
//! ## Feature flags
//!
//! | Flag | Forwards to |
//! |------|-------------|
//! | `native-tls` | `chia-sdk-client/native-tls` — OS-native TLS |
//! | `rustls` | `chia-sdk-client/rustls` — pure-Rust TLS |

// ============================================================================
// Re-export: chia-protocol (all wire types)
// ============================================================================
pub use chia_protocol::*;

// ============================================================================
// Re-export: chia-sdk-client (peer IO, TLS, rate limiting)
// ============================================================================
pub use chia_sdk_client::{
    Client, ClientError, ClientState, Connector, Network, Peer, PeerOptions, RateLimit,
    RateLimiter, RateLimits, V2_RATE_LIMITS,
};

#[cfg(feature = "native-tls")]
pub use chia_sdk_client::create_native_tls_connector;

#[cfg(feature = "rustls")]
pub use chia_sdk_client::create_rustls_connector;

pub use chia_sdk_client::load_ssl_cert;

// ============================================================================
// Re-export: chia-ssl (certificate types)
// ============================================================================
pub use chia_ssl::ChiaCertificate;

// ============================================================================
// Re-export: chia-traits (serialization)
// ============================================================================
pub use chia_traits::Streamable;

// ============================================================================
// Re-export: chia_streamable_macro (proc macro for wire structs)
// ============================================================================
pub use chia_streamable_macro::streamable;

// ============================================================================
// DIG extensions
// ============================================================================
mod dig_message;
mod dig_message_type;
mod introducer_wire;

pub use dig_message::DigMessage;
pub use dig_message_type::{DigMessageType, UnknownDigMessageType};
pub use introducer_wire::{
    RegisterAck, RegisterPeer, RequestPeersIntroducer, RespondPeersIntroducer,
};
