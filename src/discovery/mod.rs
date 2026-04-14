//! Peer discovery: address manager, persistence, DNS/introducer loops, vetting.
//!
//! **Requirement:** STR-002 — [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../../../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! **Spec:** [`docs/resources/SPEC.md`](../../../docs/resources/SPEC.md) Section 10.1 (`discovery/`).
//! **Domain specs:** [`docs/requirements/domains/discovery/`](../../../docs/requirements/domains/discovery/).

pub mod address_manager;
pub mod address_manager_store;
pub mod introducer_client;
pub mod introducer_peers;
pub mod node_discovery;
