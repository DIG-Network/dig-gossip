//! Structured gossip (Plumtree), optional compact blocks / ERLAY, priority, backpressure.
//!
//! **Requirement:** STR-002 — [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../../../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! **Spec:** [`docs/resources/SPEC.md`](../../../docs/resources/SPEC.md) Section 8, Section 10.1 (`gossip/`).
//!
//! ## Feature gates (STR-002 implementation notes)
//!
//! - **`compact-blocks`** — [`compact_block`](crate::gossip::compact_block) (SipHash short IDs, BIP-152-style relay).
//! - **`erlay`** — [`erlay`](crate::gossip::erlay) (set reconciliation flood set).

pub mod plumtree;

#[cfg(feature = "compact-blocks")]
pub mod compact_block;

#[cfg(feature = "erlay")]
pub mod erlay;

pub mod backpressure;
pub mod broadcaster;
pub mod message_cache;
pub mod priority;
pub mod seen_set;
