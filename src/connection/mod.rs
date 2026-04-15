//! Inbound peer acceptance (`TcpListener` + TLS + `Peer::from_websocket`).
//!
//! **Requirement:** STR-002 — [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../../../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! **Outbound** connect uses `chia-sdk-client` TLS + WSS (CON-001) — see [`outbound`].
//! **Related requirements:** `docs/requirements/domains/connection/`.

pub mod handshake;

/// CON-004 keepalive + RTT sampling (application-level `RequestPeers` probe).
pub mod keepalive;

/// CON-005 inbound [`RateLimiter`] configuration (`V2_RATE_LIMITS` + DIG `dig_wire`).
pub mod inbound_limits;

pub mod listener;

/// Outbound `wss://` + handshake + SPKI capture (CON-001).
pub mod outbound;
