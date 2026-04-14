//! Tor / SOCKS5 transport hooks (opt-in feature `tor`).
//!
//! **Requirement:** STR-004 — `tor` enables `arti-client` + `tokio-socks` in [`Cargo.toml`](../../../Cargo.toml).
//! **Behavior:** [`docs/requirements/domains/privacy/specs/PRV-009.md`](../../../docs/requirements/domains/privacy/specs/PRV-009.md),
//! [`PRV-010.md`](../../../docs/requirements/domains/privacy/specs/PRV-010.md).
//!
//! ## Dependencies
//!
//! - **`arti-client`** — Tor protocol client (async, `tokio` feature enabled in `Cargo.toml`).
//! - **`tokio-socks`** — SOCKS5 connector for hybrid / fallback paths.
//!
//! This module is a **structural shell** for STR-004; connection logic lands under PRV-010.

/// Placeholder for SOCKS proxy endpoint configuration (expanded in PRV-009/010).
#[derive(Debug, Clone, Default)]
pub struct TorTransportConfig {}
