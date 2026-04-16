//! Introducer **registration** wire bodies for DIG opcodes **218** (`RegisterPeer`) and **219** (`RegisterAck`).
//!
//! # Why this module exists (**DSC-005**)
//!
//! Introducer registration is a **DIG extension** — it is not part of stock Chia’s introducer RPC
//! ([`ProtocolMessageTypes::RequestPeersIntroducer`] / [`RespondPeersIntroducer`] only cover peer
//! list fetch). We still send traffic inside the standard [`chia_protocol::Message`] envelope so
//! [`dig_protocol::Peer::request_infallible`] can correlate request/response `id`s exactly like
//! full-node RPCs.
//!
//! Stock **`chia-protocol` 0.26** on crates.io stops enumerating [`ProtocolMessageTypes`] at **107**,
//! which means `Message::from_bytes` would reject opcodes **218/219** during decode. `dig-gossip`
//! therefore **vendors** `chia-protocol` with two extra enum variants (see `vendor/chia-protocol/README.dig-gossip.md`).
//! The [`chia_streamable_macro::streamable`] `message` attribute maps struct names **one-to-one**
//! onto those variants — keep the Rust identifiers `RegisterPeer` / `RegisterAck`.
//!
//! # Traceability
//!
//! - **DSC-005:** [`docs/requirements/domains/discovery/specs/DSC-005.md`](../../docs/requirements/domains/discovery/specs/DSC-005.md)
//! - **API-009 alignment:** [`DigMessageType::RegisterPeer`](crate::types::dig_messages::DigMessageType) /
//!   [`DigMessageType::RegisterAck`](crate::types::dig_messages::DigMessageType) mirror the same numeric IDs for
//!   documentation, inbound rate-limit tables, and future non-`Peer` transports.
//! - **STR-003:** re-exported from [`crate::lib`](../../lib.rs).

use chia_streamable_macro::streamable;
use dig_protocol::NodeType;

/// Registration request: advertise this node’s P2P reachability to the introducer index.
#[streamable(message)]
pub struct RegisterPeer {
    /// Externally reachable IP or hostname (operator-supplied; often **not** the bind address).
    ip: String,
    /// P2P listening port.
    port: u16,
    /// Declared service role — gossip nodes register as [`NodeType::FullNode`] per SPEC §6.5.
    node_type: NodeType,
}

/// Introducer acknowledgement — `success == false` is a **valid** wire outcome (policy rejection).
#[streamable(message)]
pub struct RegisterAck {
    success: bool,
}
