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

/// CON-009 inbound rustls acceptor — requests + captures the peer cert on all platforms (#1371).
#[cfg(feature = "rustls")]
pub mod rustls_inbound;

/// Outbound `wss://` + handshake + SPKI capture (CON-001).
pub mod outbound;

use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// Maximum size (bytes) of a single inbound WebSocket **frame** tungstenite will buffer.
///
/// tungstenite's default is 16 MiB. We pin it explicitly so the bound is a documented
/// contract rather than a library default that could drift on upgrade. 16 MiB is 4× the
/// reassembler's per-stream buffer cap ([`crate::MAX_BUFFERED_BYTES`] = 4 MiB) — the largest
/// legitimate application payload a single frame ever carries — so no legit traffic is
/// clipped while a hostile frame is refused before allocation.
pub const WS_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Maximum size (bytes) of a single inbound WebSocket **message** tungstenite will buffer
/// before rejecting it at the transport layer (below any application-level envelope cap).
///
/// tungstenite's default is **64 MiB**, which sits ABOVE every DIG application cap: a hostile
/// peer could make the transport buffer up to 64 MiB per message before the dig-message
/// envelope cap or the reassembler's per-stream cap ([`crate::MAX_BUFFERED_BYTES`] = 4 MiB)
/// ever sees the bytes. We bound it to 32 MiB — generous headroom over the 4 MiB reassembler
/// cap and the ~16 MiB envelope ceiling, yet half the tungstenite default — so an over-cap
/// message is refused by the protocol layer, not amplified into a per-connection memory DoS.
pub const WS_MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

/// The single bounded [`WebSocketConfig`] every DIG WebSocket handshake uses — inbound accept
/// paths ([`listener`]) and the outbound dial ([`outbound`]) alike (CON-002 / §5.2 transport
/// hardening). One source of truth keeps the caps from drifting between directions.
///
/// Only the two size caps are tightened; all other tungstenite defaults (write buffering, RFC
/// masking) are kept.
pub(crate) fn ws_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(WS_MAX_MESSAGE_BYTES),
        max_frame_size: Some(WS_MAX_FRAME_BYTES),
        ..Default::default()
    }
}

#[cfg(test)]
mod ws_config_tests {
    use super::*;

    /// The transport caps must be explicitly bounded and sit strictly below tungstenite's
    /// 64 MiB / 16 MiB defaults' DoS ceiling, yet stay above the largest legitimate payload
    /// (the 4 MiB reassembler per-stream cap) so real traffic is never clipped.
    #[test]
    fn ws_config_is_bounded_below_tungstenite_default() {
        const TUNGSTENITE_DEFAULT_MESSAGE_CAP: usize = 64 * 1024 * 1024;
        let cfg = ws_config();

        // The live config carries exactly our two bounded caps and nothing looser.
        assert_eq!(cfg.max_message_size, Some(WS_MAX_MESSAGE_BYTES));
        assert_eq!(cfg.max_frame_size, Some(WS_MAX_FRAME_BYTES));

        // The caps derived from the config (runtime values, so these are real assertions rather
        // than compile-time-const tautologies) stay bounded below the tungstenite default yet
        // above the largest legitimate payload.
        let message_cap = cfg.max_message_size.expect("message cap set");
        let frame_cap = cfg.max_frame_size.expect("frame cap set");

        // Bounded well under the 64 MiB tungstenite default that this fix exists to shrink.
        assert!(message_cap < TUNGSTENITE_DEFAULT_MESSAGE_CAP);
        // A message may span several frames but a frame is never larger than a message.
        assert!(frame_cap <= message_cap);
        // Headroom over the largest legitimate application payload — nothing legit is clipped.
        assert!(message_cap > crate::MAX_BUFFERED_BYTES);
    }
}
