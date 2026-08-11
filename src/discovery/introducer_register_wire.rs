//! Introducer **registration** wire bodies for DIG opcodes **218** (`RegisterPeer`) and
//! **219** (`RegisterAck`) — re-exported from `dig-peer-protocol`.
//!
//! # Why these live upstream now (**DSC-005**)
//!
//! Introducer registration is a **DIG extension**: stock Chia's introducer RPC covers only
//! peer-list fetch ([`ProtocolMessageTypes::RequestPeersIntroducer`] /
//! [`RespondPeersIntroducer`](chia_protocol::ProtocolMessageTypes::RespondPeersIntroducer)).
//!
//! These bodies used to be declared here with `#[streamable(message)]`, which makes the
//! proc-macro emit a `ProtocolMessageTypes::RegisterPeer` path — a variant that exists only
//! in a **forked** `chia-protocol`. That single attribute was one of the two things keeping
//! `vendor/chia-protocol` alive (dig_ecosystem#2228).
//!
//! `dig-peer-protocol` declares them with plain `#[streamable]` and pairs each with
//! `to_dig_message` / `from_dig_message`, carrying opcode 218/219 as a raw
//! [`DigMessage`](dig_peer_protocol::DigMessage) byte. That needs no enum variant, so the
//! fork is no longer required — and the bodies now have a single definition shared with
//! every other consumer instead of one per repo.
//!
//! The encoded bytes are unchanged; `tests/wire_golden_vectors_tests.rs` pins them.
//!
//! # Traceability
//!
//! - **DSC-005:** [`docs/requirements/domains/discovery/specs/DSC-005.md`](../../docs/requirements/domains/discovery/specs/DSC-005.md)
//! - **API-009 alignment:** [`DigMessageType::RegisterPeer`](crate::types::dig_messages::DigMessageType) /
//!   [`DigMessageType::RegisterAck`](crate::types::dig_messages::DigMessageType) mirror the same
//!   numeric ids for documentation, inbound rate-limit tables, and future non-link transports.
//! - **STR-003:** re-exported from [`crate::lib`](../../lib.rs).

pub use dig_peer_protocol::{RegisterAck, RegisterPeer};
