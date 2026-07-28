//! Regression test for #10 — the WS transport must be given an explicit BOUNDED
//! [`WebSocketConfig`](tokio_tungstenite::tungstenite::protocol::WebSocketConfig) on every
//! handshake, so a hostile peer's oversized frame/message is refused at the tungstenite layer
//! instead of being buffered up to tungstenite's 64 MiB default before any app-level cap applies.
//!
//! ## Why this is a contract test, not a socket-level test
//!
//! A socket-level "send an over-cap message and watch it fail" test cannot *deterministically*
//! isolate a TRANSPORT-layer rejection from an APPLICATION-layer rejection: against either the
//! bounded config or the old 64 MiB default, an oversized garbage payload ends with the server
//! closing the connection (the transport refuses the frame in one case, the handshake decoder
//! rejects the bytes in the other) — the client observes a close either way, so the assertion
//! would pass even WITHOUT the fix. The load-bearing, regression-catching fact is instead the
//! bounded-cap *contract*: the crate exposes bounded caps that sit strictly below tungstenite's
//! 64 MiB DoS ceiling and are wired into the accept/connect paths. This test pins that public
//! contract from an external consumer's vantage point; the companion in-crate unit test
//! `ws_config_is_bounded_below_tungstenite_default` (src/connection/mod.rs) pins the concrete
//! `ws_config()` values and that both handshake directions use it.

use dig_gossip::connection::{WS_MAX_FRAME_BYTES, WS_MAX_MESSAGE_BYTES};

/// tungstenite's default `max_message_size` — the 64 MiB buffering ceiling this fix shrinks.
const TUNGSTENITE_DEFAULT_MESSAGE_CAP: usize = 64 * 1024 * 1024;
/// tungstenite's default `max_frame_size`.
const TUNGSTENITE_DEFAULT_FRAME_CAP: usize = 16 * 1024 * 1024;
/// The reassembler's per-stream buffer cap (`dig_gossip::MAX_BUFFERED_BYTES`, 4 MiB) — the
/// largest legitimate application payload a single WS message ever carries.
const APP_REASSEMBLER_CAP: usize = 4 * 1024 * 1024;

/// The transport caps the crate advertises must be explicitly bounded BELOW tungstenite's
/// 64 MiB default (so an over-cap message is refused before large allocation) yet remain
/// comfortably ABOVE the largest legitimate payload (so real traffic is never clipped).
#[test]
fn advertised_ws_caps_are_bounded_below_tungstenite_default() {
    // Read the exported caps through a runtime boundary: these are `const`s, and asserting on
    // purely-constant expressions both trips clippy's `assertions_on_constants` and would only
    // re-check compile-time literals. `black_box` treats them as opaque runtime values, so the
    // assertions genuinely exercise the public contract an external consumer depends on.
    let message_cap = std::hint::black_box(WS_MAX_MESSAGE_BYTES);
    let frame_cap = std::hint::black_box(WS_MAX_FRAME_BYTES);
    let reassembler_cap = std::hint::black_box(dig_gossip::MAX_BUFFERED_BYTES);

    assert_eq!(
        reassembler_cap, APP_REASSEMBLER_CAP,
        "sanity: reassembler per-stream cap is 4 MiB — the sizing anchor for the transport caps"
    );

    // Bounded strictly under the tungstenite defaults this hardening exists to shrink.
    assert!(
        message_cap < TUNGSTENITE_DEFAULT_MESSAGE_CAP,
        "message cap must be below tungstenite's 64 MiB default"
    );
    assert!(
        frame_cap <= TUNGSTENITE_DEFAULT_FRAME_CAP,
        "frame cap must not exceed tungstenite's 16 MiB default"
    );

    // A frame never exceeds a message; both leave generous headroom over legit payloads.
    assert!(frame_cap <= message_cap);
    assert!(
        message_cap > reassembler_cap,
        "message cap must exceed the 4 MiB reassembler cap so legit traffic is never clipped"
    );
}
