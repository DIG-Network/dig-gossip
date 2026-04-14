//! # dig-gossip
//!
//! DIG Network L2 peer gossip, discovery, relay, and related protocol plumbing.
//!
//! ## Documentation map
//!
//! - **Master specification:** [`docs/resources/SPEC.md`](../../docs/resources/SPEC.md)
//! - **Traceable requirements:** [`docs/requirements/README.md`](../../docs/requirements/README.md)
//! - **This crate’s dependency baseline:** STR-001 in
//!   [`docs/requirements/domains/crate_structure/specs/STR-001.md`](../../docs/requirements/domains/crate_structure/specs/STR-001.md)
//!
//! ## Current implementation stage
//!
//! STR-001 only establishes the dependency and feature-flag baseline so the crate
//! resolves and builds in CI. The public API, module hierarchy (`src/**`), and
//! re-export surface land in STR-002 / STR-003 per
//! [`docs/requirements/IMPLEMENTATION_ORDER.md`](../../docs/requirements/IMPLEMENTATION_ORDER.md).
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
