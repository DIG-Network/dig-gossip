//! Peer discovery: address manager, persistence, DNS/introducer loops, vetting.
//!
//! **Requirement:** STR-002 — [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! **Spec:** [`docs/resources/SPEC.md`](../../docs/resources/SPEC.md) Section 10.1 (`discovery/`).
//! **Domain specs:** [`docs/requirements/domains/discovery/`](../../docs/requirements/domains/discovery/).

pub mod address_manager;
pub mod address_manager_store;
pub mod introducer_client;
pub mod introducer_peers;
/// DIG introducer **registration** wire types (**218** / **219**) — DSC-005.
///
/// Depends on the vendored [`chia_protocol::ProtocolMessageTypes`] extension (see `vendor/chia-protocol`).
pub mod introducer_register_wire;
/// Introducer wire structs for protocol IDs **63** / **64** (DSC-004).
///
/// `chia-protocol` 0.26 lists these only on [`ProtocolMessageTypes`](chia_protocol::ProtocolMessageTypes);
/// the streamable bodies match Chia’s introducer wire layout (empty request, `peer_list` response —
/// same shape as [`RespondPeers`](chia_protocol::RespondPeers)).
pub mod introducer_wire;
pub mod node_discovery;
