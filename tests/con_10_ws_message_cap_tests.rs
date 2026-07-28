//! Regression tests for #10 — the WS transport must reject an over-cap message at
//! the tungstenite layer (explicit bounded `WebSocketConfig`), never buffer up to
//! the 64 MiB tungstenite default before an app-level cap can reject it.
//!
//! Filled in by the implementer lane (TDD red→green).

#[test]
#[ignore = "stub anchor for #10 — implemented by the harden lane"]
fn ws_message_cap_placeholder() {}
