//! Inbound peer acceptance (`TcpListener` + TLS + `Peer::from_websocket`).
//!
//! **Requirement:** STR-002 — [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../../../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! **Outbound** connect uses `chia-sdk-client` directly (SPEC Section 5).
//! **Related requirements:** `docs/requirements/domains/connection/`.

pub mod listener;
