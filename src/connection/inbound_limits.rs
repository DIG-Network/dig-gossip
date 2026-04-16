//! CON-005 — per-connection **inbound** rate limits on top of [`V2_RATE_LIMITS`](dig_protocol::V2_RATE_LIMITS).
//!
//! ## Normative trace
//!
//! - [`CON-005.md`](../../../docs/requirements/domains/connection/specs/CON-005.md)
//! - [`NORMATIVE.md`](../../../docs/requirements/domains/connection/NORMATIVE.md) §CON-005
//! - [`SPEC.md`](../../../docs/resources/SPEC.md) §5.3
//!
//! ## Outbound vs inbound
//!
//! Outbound sends go through [`dig_protocol::Peer::send_raw`] which already applies
//! [`RateLimiter`] with `incoming = false` (CON-005 acceptance: *no custom outbound implementation*).
//! Inbound frames are delivered on the per-connection `mpsc` from [`Peer::from_websocket`]; **DIG**
//! enforces [`RateLimiter::handle_message`] here **before** forwarding to the broadcast hub.
//!
//! ## DIG wire types (`200..=219` subset here)
//!
//! [`crate::types::dig_messages::DigMessageType`] discriminants are **not** [`ProtocolMessageTypes`]
//! variants in `chia-protocol` 0.26, so they cannot appear in [`dig_protocol::RateLimits`] `tx` /
//! `other` maps. We attach them to [`RateLimits::dig_wire`](dig_protocol::RateLimits::dig_wire)
//! (vendored `chia-sdk-client`) and validate with [`RateLimiter::check_dig_extension`] when a future
//! ingress path decodes raw DIG frames. Today’s integration path only sees Chia [`Message`] values;
//! the extension table is still installed so limits are centralized and unit-tested per CON-005.

use std::collections::HashMap;

use dig_protocol::{RateLimit, RateLimiter, RateLimits, V2_RATE_LIMITS};

use crate::types::dig_messages::DigMessageType;

/// Table from [`CON-005.md`](../../../docs/requirements/domains/connection/specs/CON-005.md) §DIG Extension Rate Limits.
///
/// Frequencies are **per rolling minute bucket** (see [`RateLimiter::new`] `reset_seconds: 60` in
/// call sites). Sizes are maximum **single-frame** payload bytes unless `max_total_size` is set.
pub fn dig_extension_rate_limits_map() -> HashMap<u8, RateLimit> {
    let mut m = HashMap::new();
    m.insert(
        DigMessageType::NewAttestation as u8,
        RateLimit::new(100.0, 4096.0, None),
    );
    m.insert(
        DigMessageType::NewCheckpointProposal as u8,
        RateLimit::new(10.0, 8192.0, None),
    );
    m.insert(
        DigMessageType::NewCheckpointSignature as u8,
        RateLimit::new(100.0, 4096.0, None),
    );
    m.insert(
        DigMessageType::RequestCheckpointSignatures as u8,
        RateLimit::new(10.0, 1024.0, None),
    );
    m.insert(
        DigMessageType::RespondCheckpointSignatures as u8,
        RateLimit::new(10.0, 65536.0, None),
    );
    m.insert(
        DigMessageType::RequestStatus as u8,
        RateLimit::new(10.0, 1024.0, None),
    );
    m.insert(
        DigMessageType::RespondStatus as u8,
        RateLimit::new(10.0, 8192.0, None),
    );
    m.insert(
        DigMessageType::NewCheckpointSubmission as u8,
        RateLimit::new(10.0, 65536.0, None),
    );
    m.insert(
        DigMessageType::ValidatorAnnounce as u8,
        RateLimit::new(10.0, 4096.0, None),
    );
    // DSC-005 — introducer registration is low-frequency but still needs bounded ingress if ever
    // proxied through a gossip peer path (defensive; primary flow is introducer WSS client).
    m.insert(
        DigMessageType::RegisterPeer as u8,
        RateLimit::new(4.0, 512.0, None),
    );
    m.insert(
        DigMessageType::RegisterAck as u8,
        RateLimit::new(4.0, 256.0, None),
    );
    m
}

/// Chia **V2** limits plus DIG `dig_wire` rows — shared definition for every inbound [`LiveSlot`](crate::service::state::LiveSlot).
pub fn gossip_inbound_rate_limits() -> RateLimits {
    let mut limits = (*V2_RATE_LIMITS).clone();
    limits.dig_wire = dig_extension_rate_limits_map();
    limits
}

/// Build a per-connection inbound limiter: **incoming = true**, **60 s** window, scaled by
/// [`crate::types::config::GossipConfig::peer_options`](crate::types::config::GossipConfig::peer_options).
pub fn new_inbound_rate_limiter(rate_limit_factor: f64) -> RateLimiter {
    RateLimiter::new(true, 60, rate_limit_factor, gossip_inbound_rate_limits())
}
