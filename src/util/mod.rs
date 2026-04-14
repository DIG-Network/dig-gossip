//! Cross-cutting helpers: IP bucketing, AS lookups, RTT scoring.
//!
//! **Requirement:** STR-002 — [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../../../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! **Spec:** [`docs/resources/SPEC.md`](../../../docs/resources/SPEC.md) Section 10.1 (`util/`).

pub mod as_lookup;
pub mod ip_address;
pub mod latency;
