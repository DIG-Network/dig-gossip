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
//!
//! **API-003:** [`GossipConfig`](crate::types::config::GossipConfig) carries `Option<TorConfig>` when
//! feature `tor` is enabled ([`SPEC.md`](../../../docs/resources/SPEC.md) §1.9.3).

/// SOCKS / onion endpoint knobs for hybrid transports (expanded in PRV-009/010).
///
/// Named `TorConfig` in API-003 / SPEC; [`TorTransportConfig`] remains a type alias for STR-004
/// tests and older call sites.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TorConfig {}

/// Historical name from STR-004 shell — identical to [`TorConfig`].
pub type TorTransportConfig = TorConfig;
