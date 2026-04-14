//! Relay WebSocket client, reconnecting service shell, relay message types.
//!
//! **Requirement:** STR-002 — this directory is compiled only when feature `relay` is enabled
//! from the crate root (`src/lib.rs`).
//! **Spec:** [`docs/resources/SPEC.md`](../../../docs/resources/SPEC.md) Section 7, Section 10.1 (`relay/`).
//! **Domain:** [`docs/requirements/domains/relay/`](../../../docs/requirements/domains/relay/).

pub mod relay_client;
pub mod relay_service;
pub mod relay_types;
