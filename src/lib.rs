//! # dig-gossip
//!
//! DIG Network L2 peer gossip, discovery, relay, and related protocol plumbing.
//!
//! ## Documentation map
//!
//! - **Master specification:** [`docs/resources/SPEC.md`](../docs/resources/SPEC.md)
//! - **Traceable requirements:** [`docs/requirements/README.md`](../docs/requirements/README.md)
//! - **Crate layout (this file’s children):** STR-002 —
//!   [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! - **Dependency / feature baseline:** STR-001 (same `docs/requirements/domains/crate_structure/` tree)
//!
//! ## Module tree (STR-002)
//!
//! The `pub mod` statements below mirror SPEC Section 10.1 as narrowed by STR-002
//! acceptance criteria (types, service, connection, discovery, relay, gossip, util).
//! **Note:** SPEC 10.1 also lists a `privacy/` subtree for Dandelion++/Tor; that lands
//! under later requirements—STR-002’s checklist does not require those paths yet.
//!
//! Feature gates (see STR-002 implementation notes):
//!
//! - **`relay`** — entire `relay/` subsystem (SPEC Section 7).
//! - **`compact-blocks`** / **`erlay`** — wired inside [`crate::gossip`] so optional
//!   algorithms do not compile when features are disabled.
//!
//! ## Design constraints (from SPEC)
//!
//! - Reuse Chia crates for protocol types and peer IO; do not redefine
//!   `Handshake`, `Message`, `Peer`, etc.
//! - No consensus validation in this crate — it transports messages only.
//!
//! ## Safety
//!
//! This crate forbids `unsafe` at the crate root so new modules inherit the policy.

#![forbid(unsafe_code)]

pub mod connection;
pub mod constants;
pub mod discovery;
pub mod error;
pub mod service;
pub mod types;

/// Relay fallback — WebSocket client, service lifecycle, relay wire types.
///
/// **Feature:** `relay` ([`Cargo.toml`](../Cargo.toml), STR-002 notes).
/// **Spec:** [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 7, Section 10.1 (`relay/`).
#[cfg(feature = "relay")]
pub mod relay;

pub mod gossip;
pub mod util;
