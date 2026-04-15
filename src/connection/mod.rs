//! Inbound peer acceptance (`TcpListener` + TLS + `Peer::from_websocket`).
//!
//! **Requirement:** STR-002 — [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../../../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! **Outbound** connect uses `chia-sdk-client` TLS + WSS (CON-001) — see [`outbound`].
//! **Related requirements:** `docs/requirements/domains/connection/`.

pub mod handshake;

/// Outbound `wss://` + handshake + SPKI capture (CON-001).
pub mod outbound;

pub mod listener;
