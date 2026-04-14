//! Shared DIG data types used across service, discovery, and gossip layers.
//!
//! **Requirement:** STR-002 — [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../../../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! **Spec:** [`docs/resources/SPEC.md`](../../../docs/resources/SPEC.md) Section 10.1 (`types/`).
//!
//! Concrete structs/enums are introduced by crate API requirements (e.g.
//! [`docs/requirements/domains/crate_api/`](../../../docs/requirements/domains/crate_api/)).

pub mod config;
pub mod dig_messages;
pub mod peer;
pub mod reputation;
pub mod stats;
