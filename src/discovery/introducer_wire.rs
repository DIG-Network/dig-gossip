//! Introducer **wire structs** for Chia protocol opcodes **63** (`RequestPeersIntroducer`) and **64**
//! (`RespondPeersIntroducer`).
//!
//! # Why this module exists
//!
//! [`chia_protocol::ProtocolMessageTypes`](chia_protocol::ProtocolMessageTypes) names the introducer
//! RPC opcodes, but **`chia-protocol` 0.26** does not export standalone Rust structs for those bodies
//! (unlike [`RequestPeers`](chia_protocol::RequestPeers) / [`RespondPeers`](chia_protocol::RespondPeers)
//! in `full_node_protocol.rs`). DIG still needs [`ChiaProtocolMessage`](chia_protocol::ChiaProtocolMessage)
//! + [`Streamable`](chia_traits::Streamable) types so [`Peer::request_infallible`](chia_sdk_client::Peer::request_infallible)
//! can serialize requests and decode responses (DSC-004).
//!
//! The [`chia_streamable_macro::streamable`] attribute generates `msg_type()` mappings from the **Rust
//! struct identifier**, so the names here **must** stay `RequestPeersIntroducer` / `RespondPeersIntroducer`
//! to line up with the upstream enum variants.
//!
//! # Traceability
//!
//! - **DSC-004:** [`docs/requirements/domains/discovery/specs/DSC-004.md`](../../docs/requirements/domains/discovery/specs/DSC-004.md)
//! - **STR-003:** re-exported from [`crate::lib`](../../lib.rs) alongside other protocol surface types.

use chia_protocol::TimestampedPeerInfo;
use chia_streamable_macro::streamable;

/// Empty introducer “get peers” request (protocol type **63**).
#[streamable(message)]
pub struct RequestPeersIntroducer {}

/// Introducer peer list response (protocol type **64**).
///
/// **Wire shape:** identical to [`RespondPeers`](chia_protocol::RespondPeers) (`peer_list` only) —
/// this matches Chia’s historical introducer implementation and keeps bincode-compatible decoding
/// aligned with what introducer daemons emit today.
#[streamable(message)]
pub struct RespondPeersIntroducer {
    peer_list: Vec<TimestampedPeerInfo>,
}
