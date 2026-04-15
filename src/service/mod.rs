//! `GossipService` construction / lifecycle and the `GossipHandle` RPC surface.
//!
//! **Requirement:** STR-002 — [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../../../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! **Spec:** [`docs/resources/SPEC.md`](../../../docs/resources/SPEC.md) Section 10.1 (`service/`).
//! **API specs:** [`docs/requirements/domains/crate_api/specs/API-001.md`](../../../docs/requirements/domains/crate_api/specs/API-001.md),
//! [`API-002.md`](../../../docs/requirements/domains/crate_api/specs/API-002.md).

/// Shared [`ServiceState`] — `pub(crate)` so connection/listener (CON-002) can accept inbound peers
/// without exposing internal types at the crate root (STR-002).
pub(crate) mod state;

pub mod gossip_handle;
pub mod gossip_service;
