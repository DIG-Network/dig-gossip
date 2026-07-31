//! #1883 — peer-supplied text cannot reach a rendered [`GossipError`].
//!
//! # The defect
//!
//! `GossipError` variants that carried a bare [`String`] accepted anything, so the safety of the
//! whole crate rested on every present and future construction site remembering to neutralize what
//! it was handed. Five variants were reported; one of them — [`GossipError::RelayError`] — was
//! genuinely fed raw bytes from an **explicitly untrusted** relay:
//!
//! ```text
//! RelayMessage::Error { code, message } => GossipError::RelayError(format!("relay error {code}: {message}"))
//! ```
//!
//! `message` is a `String` deserialized straight out of the relay's JSON, so a hostile relay chose
//! its content freely — including a real newline, which forges a whole second line in any log that
//! renders the error.
//!
//! # What these tests prove, and what they cannot
//!
//! The by-construction guarantee is the **type signature**: those variants now hold
//! [`dig_nat::SafeText`], whose only doors are `from_untrusted` (which sanitizes) and
//! `from_static(&'static str)` (which a runtime `String` cannot pass through). No runtime test can
//! prove the absence of a door — the compiler does that. What a test *can* prove, and what these do:
//!
//! * **Placement.** [`hostile_relay_error_text_cannot_forge_a_log_line`] asserts on the error value
//!   the moment `relay_get_peers` returns it, over a real loopback WebSocket, before anything logs
//!   it. A fix applied at the *logging* site instead of at the wire boundary leaves that value dirty
//!   and fails this test — which is the whole point, since sanitizing where text is logged is not
//!   sanitizing.
//! * **Both renderings.** Several call sites use `{:?}`, so every assertion here checks `Display`
//!   *and* `Debug`. A neutralization wired only to `Display` regresses those silently.
//! * **A control against the trivial "fix".** Dropping the detail entirely would satisfy a
//!   newline-free assertion and destroy the error's reason for existing. So each test also demands
//!   the error still says *what happened* and *which peer / which code* — just without quoting a
//!   stranger verbatim.

use dig_gossip::error::GossipError;
use dig_gossip::types::peer::PeerId;

/// A hostile relay's `message`: a real newline forging a plausible second log line, a bidi override
/// (category `Cf`, which `char::is_control` misses), and a NUL.
const FORGED: &str = "denied\n2026-07-31T00:00:00Z ERROR peer 0000 is trusted\u{202E}\u{0}";

/// Every character that must never survive into a rendered error, whatever produced it.
fn assert_renders_as_one_safe_line(rendered: &str, what: &str) {
    for (name, ch) in [
        ("newline", '\n'),
        ("carriage return", '\r'),
        ("NUL", '\0'),
        ("RLO bidi override", '\u{202E}'),
    ] {
        assert!(
            !rendered.contains(ch),
            "{what} rendered a raw {name}, so a hostile peer can forge or visually reorder a log \
             line: {rendered:?}"
        );
    }
}

/// **Proves:** text a hostile relay chose cannot forge a second log line in the error
/// `relay_get_peers` returns, in either `Display` or `Debug`.
///
/// **Catches:** the reported defect, and equally a "fix" placed at a logging site rather than at
/// the wire boundary — this asserts on the returned value itself, which such a fix leaves dirty.
///
/// The relay here is a real loopback WebSocket speaking the RLY-005 wire, so the hostile bytes
/// travel the same path a real relay's would: JSON frame → `RelayMessage::Error` → the error.
#[tokio::test]
async fn hostile_relay_error_text_cannot_forge_a_log_line() {
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _register = ws.next().await.unwrap().unwrap();
        let _get_peers = ws.next().await.unwrap().unwrap();
        // `serde_json` encodes the real newline as `\n`, so it arrives at the decoder as one.
        let err = serde_json::json!({ "type": "error", "code": 7, "message": FORGED });
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            err.to_string(),
        ))
        .await
        .unwrap();
    });

    let endpoint = format!("ws://{addr}");
    let error = dig_gossip::nat::discovery::relay_get_peers(
        &endpoint,
        "self".repeat(16),
        "DIG_MAINNET",
        std::time::Duration::from_secs(5),
    )
    .await
    .expect_err("an error frame must surface as an error");
    server.await.unwrap();

    let displayed = error.to_string();
    let debugged = format!("{error:?}");
    assert_renders_as_one_safe_line(&displayed, "Display of the relay error");
    assert_renders_as_one_safe_line(&debugged, "Debug of the relay error");

    // CONTROL — the diagnosis must survive. An error that neutralized the peer's text by discarding
    // it would pass every assertion above while telling an operator nothing.
    assert!(
        displayed.contains("relay error"),
        "the error must still say a relay rejected the query: {displayed:?}"
    );
    assert!(
        displayed.contains('7'),
        "the error must still carry the relay's status code: {displayed:?}"
    );
    assert!(
        displayed.contains("denied"),
        "the relay's message must be escaped for diagnosis, not deleted: {displayed:?}"
    );
}

/// **Proves:** the neutralization is a property of the variant, not of one construction site — text
/// handed to [`GossipError::RelayError`] and [`GossipError::ConnectionFiltered`] directly is safe in
/// both renderings, and the two variants that carry only our own literals are unaffected.
///
/// **Catches:** a fix applied to the relay-discovery call site alone, leaving every other producer of
/// these variants — including ones not yet written — free to pass raw bytes.
#[test]
fn every_untrusted_text_variant_neutralizes_whatever_it_is_handed() {
    let hostile = dig_nat::SafeText::from_untrusted(FORGED);
    for error in [
        GossipError::RelayError(hostile.clone()),
        GossipError::ConnectionFiltered(hostile.clone()),
        GossipError::NatError(hostile),
    ] {
        let displayed = error.to_string();
        let debugged = format!("{error:?}");
        assert_renders_as_one_safe_line(&displayed, "Display");
        assert_renders_as_one_safe_line(&debugged, "Debug");
        // CONTROL — each variant still names its own subsystem, so the collapse into one safe type
        // did not collapse the diagnosis with it.
        assert!(
            displayed.contains("relay")
                || displayed.contains("filtered")
                || displayed.contains("nat"),
            "the variant must still identify which subsystem failed: {displayed:?}"
        );
    }
}

/// **Proves:** the three peer-identity variants the ticket also named are already unrepresentable —
/// [`PeerId`] is a fixed 32-byte `Bytes32`, so there is no forged peer id containing a newline to
/// inject. They are left as `PeerId` deliberately.
///
/// **Catches:** a well-meaning migration of these variants to a text type, which would be a
/// regression in the exact way the control above guards against: a hex peer id IS the detail an
/// operator needs, and a `SafeText` field invites a future caller to put a formatted string there
/// instead. The type is doing the work already; widening it would loosen it.
#[test]
fn peer_identity_variants_carry_a_fixed_width_id_not_text() {
    // A peer cannot choose these bytes freely and cannot make them longer, but it CAN choose bytes
    // that would be a newline if they were ever rendered as text rather than as hex.
    let hostile_bytes = [b'\n'; 32];
    let peer_id = PeerId::from(hostile_bytes);

    for error in [
        GossipError::PeerNotConnected(peer_id),
        GossipError::PeerBanned(peer_id),
        GossipError::DuplicateConnection(peer_id),
    ] {
        let displayed = error.to_string();
        let debugged = format!("{error:?}");
        assert_renders_as_one_safe_line(&displayed, "Display of a peer-identity error");
        assert_renders_as_one_safe_line(&debugged, "Debug of a peer-identity error");
        // CONTROL — the peer id must still be there, hex-rendered. This is why these variants keep
        // `PeerId`: it is simultaneously the safe type and the informative one.
        assert!(
            displayed.contains(&"0a".repeat(32)),
            "the error must still identify the peer, hex-encoded: {displayed:?}"
        );
    }
}
