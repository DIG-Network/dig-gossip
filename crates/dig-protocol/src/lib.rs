//! # dig-protocol
//!
//! DIG Network L2 protocol types extending Chia's wire protocol.
//!
//! ## Purpose
//!
//! Chia's `ProtocolMessageTypes` enum (crates.io `chia-protocol` 0.26) covers opcodes 0–107.
//! DIG's L2 overlay adds opcodes **200–219** for attestation gossip, checkpoint protocol,
//! compact block relay, ERLAY reconciliation, Dandelion++ stem, Plumtree gossip, and
//! introducer registration.
//!
//! This crate provides:
//!
//! - [`DigMessage`] — same wire format as `chia_protocol::Message` but stores `msg_type`
//!   as raw `u8`, so DIG extension opcodes decode without patching the Chia enum.
//! - [`DigMessageType`] — `#[repr(u8)]` enum for all DIG opcodes (200–219).
//! - Wire body structs for DIG-specific RPCs: [`RegisterPeer`], [`RegisterAck`],
//!   [`RequestPeersIntroducer`], [`RespondPeersIntroducer`].
//! - Full re-export of `chia-protocol` types for one-stop imports.
//!
//! ## Wire format
//!
//! On the wire, both Chia and DIG messages share the same framing:
//!
//! ```text
//! [u8 msg_type] [Option<u16> id] [Bytes data]
//! ```
//!
//! The receiver dispatches on numeric value: `< 200` → Chia handler, `>= 200` → DIG handler.
//! [`DigMessage`] can represent either.

// Re-export all chia-protocol types — consumers import from dig-protocol instead
pub use chia_protocol::*;
pub use chia_traits::Streamable;

mod dig_message;
mod dig_message_type;
mod introducer_wire;

pub use dig_message::DigMessage;
pub use dig_message_type::{DigMessageType, UnknownDigMessageType};
pub use introducer_wire::{
    RegisterAck, RegisterPeer, RequestPeersIntroducer, RespondPeersIntroducer,
};
