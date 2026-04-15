//! Integration tests for **CON-008: version string sanitization** on [`Handshake::software_version`].
//!
//! ## Traceability
//!
//! - **Spec + test plan table:** [`CON-008.md`](../docs/requirements/domains/connection/specs/CON-008.md)
//! - **Normative one-liner:** [`NORMATIVE.md`](../docs/requirements/domains/connection/NORMATIVE.md) (CON-008)
//! - **Cross-domain:** [`CON-003.md`](../docs/requirements/domains/connection/specs/CON-003.md) reuses the same
//!   [`validate_remote_handshake`](dig_gossip::connection::handshake::validate_remote_handshake) helper; this file
//!   owns the **CON-008** acceptance matrix so `TRACKING.yaml` can point at a single dedicated suite.
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) sections 5.1–5.2 (handshake metadata on wire).
//!
//! ## Proof strategy (causal chain)
//!
//! 1. **Unit rows** exercise [`dig_gossip::connection::handshake::sanitize_software_version`] directly. Each test
//!    name maps to a row in CON-008’s “Test Plan” table. Passing asserts **Cc** (control) and **Cf** (format) code points
//!    never appear in the output, while letters, punctuation, emoji, and CJK survive — exactly the contract Chia
//!    encodes in `ws_connection.py:61-63` via `unicodedata.category`.
//! 2. **Policy bridge** — [`validate_remote_handshake`](dig_gossip::connection::handshake::validate_remote_handshake)
//!    must return the same string as `sanitize_software_version` on the handshake’s `software_version` whenever
//!    network/protocol checks pass. That proves production never stores raw wire text before sanitization
//!    (outbound: [`dig_gossip::connection::outbound::connect_outbound_peer`]; inbound:
//!    [`dig_gossip::connection::listener::negotiate_inbound_over_ws`] both call `validate_remote_handshake`).
//! 3. **`test_matches_chia_category_policy`** — after sanitization, `unicode-general-category` reports neither
//!    [`GeneralCategory::Control`] nor [`GeneralCategory::Format`] for any output grapheme. That is the same
//!    distinction Python’s `not category.startswith(("Cc","Cf"))` implements, so we stay aligned with upstream
//!    category tables rather than a hand-maintained allow list alone.

mod common;

use chia_protocol::Handshake;
use dig_gossip::connection::handshake::{sanitize_software_version, validate_remote_handshake};
use dig_gossip::NodeType;
use unicode_general_category::{get_general_category, GeneralCategory};

/// Baseline remote [`Handshake`] for CON-008 policy tests: only `software_version` is malicious.
fn handshake_with_version(network_id: &str, software_version: String) -> Handshake {
    Handshake {
        network_id: network_id.to_string(),
        protocol_version: "0.0.37".to_string(),
        software_version,
        server_port: 8444,
        node_type: NodeType::FullNode,
        capabilities: vec![],
    }
}

/// **Row:** `test_strip_null` — NUL is Cc and must not appear in logs or stored metadata.
#[test]
fn test_strip_null() {
    assert_eq!(sanitize_software_version("dig\x00gossip"), "diggossip");
}

/// **Row:** `test_strip_newline` — LINE FEED is Cc.
#[test]
fn test_strip_newline() {
    assert_eq!(sanitize_software_version("dig\ngossip"), "diggossip");
}

/// **Row:** `test_strip_tab` — CHARACTER TABULATION is Cc.
#[test]
fn test_strip_tab() {
    assert_eq!(sanitize_software_version("dig\tgossip"), "diggossip");
}

/// **Row:** `test_strip_del` — DELETE (U+007F) is Cc.
#[test]
fn test_strip_del() {
    assert_eq!(sanitize_software_version("dig\x7Fgossip"), "diggossip");
}

/// **Row:** `test_strip_c1_controls` — C1 controls U+0080..U+009F are Cc (UTF-8 scalar values, not Latin-1 bytes).
#[test]
fn test_strip_c1_controls() {
    assert_eq!(
        sanitize_software_version("dig\u{0080}\u{009F}gossip"),
        "diggossip"
    );
}

/// **Row:** `test_strip_zero_width_space` — U+200B is Cf.
#[test]
fn test_strip_zero_width_space() {
    assert_eq!(sanitize_software_version("dig\u{200B}gossip"), "diggossip");
}

/// **Row:** `test_strip_bom` — U+FEFF is Cf (also strips leading BOM from vendor strings).
#[test]
fn test_strip_bom() {
    assert_eq!(
        sanitize_software_version("\u{FEFF}dig-gossip/0.1.0"),
        "dig-gossip/0.1.0"
    );
}

/// **Row:** `test_strip_rtl_override` — U+202E is Cf (mitigates display/UI attacks in version banners).
#[test]
fn test_strip_rtl_override() {
    assert_eq!(sanitize_software_version("dig\u{202E}gossip"), "diggossip");
}

/// **Row:** `test_strip_soft_hyphen` — U+00AD is Cf.
#[test]
fn test_strip_soft_hyphen() {
    assert_eq!(sanitize_software_version("dig\u{00AD}gossip"), "diggossip");
}

/// **Row:** `test_preserve_normal_ascii` — printable ASCII is neither Cc nor Cf.
#[test]
fn test_preserve_normal_ascii() {
    let v = "dig-gossip/0.1.0";
    assert_eq!(sanitize_software_version(v), v);
}

/// **Row:** `test_preserve_emoji` — astral emoji are outside Cc/Cf for this policy.
#[test]
fn test_preserve_emoji() {
    let v = "dig-gossip \u{1F680}";
    assert_eq!(sanitize_software_version(v), v);
}

/// **Row:** `test_preserve_cjk` — logographs are Lo, not stripped.
#[test]
fn test_preserve_cjk() {
    let v = "dig-gossip-\u{4E16}\u{754C}";
    assert_eq!(sanitize_software_version(v), v);
}

/// **Row:** `test_all_control_chars` — representative C0/C1 controls collapse to empty.
#[test]
fn test_all_control_chars() {
    assert_eq!(sanitize_software_version("\x00\x01\x1F\x7F"), "");
}

/// **Row:** `test_mixed_normal_and_control` — interleaved safe and unsafe code points.
#[test]
fn test_mixed_normal_and_control() {
    assert_eq!(sanitize_software_version("a\x00b\u{200B}c\x7Fd"), "abcd");
}

/// **Row:** `test_idempotent` — stripping twice cannot remove additional characters.
#[test]
fn test_idempotent() {
    let inputs = [
        "dig\x00gossip",
        "a\u{200B}b\u{FEFF}c",
        "normal",
        "",
        "\u{202E}\u{2060}z",
    ];
    for s in inputs {
        let once = sanitize_software_version(s);
        let twice = sanitize_software_version(&once);
        assert_eq!(once, twice, "idempotent fail for input {:?}", s);
    }
}

/// **Row:** `test_matches_chia_python` / `test_matches_chia_category_policy` — Chia filters by Unicode general
/// category prefix `Cc` and `Cf`. We assert the post-sanitize string contains **no** characters whose category is
/// Control or Format per the same `unicode-general-category` tables.
#[test]
fn test_matches_chia_category_policy() {
    let seeds = [
        "evil\u{0000}\u{200B}mixed",
        "\u{FEFF}\u{061C}wrap",
        "safe-text",
        "\u{2066}isolate\u{2069}",
    ];
    for seed in seeds {
        let out = sanitize_software_version(seed);
        for ch in out.chars() {
            let cat = get_general_category(ch);
            assert_ne!(
                cat,
                GeneralCategory::Control,
                "char {:?} U+{:04X} should not survive sanitize (Cc)",
                ch,
                ch as u32
            );
            assert_ne!(
                cat,
                GeneralCategory::Format,
                "char {:?} U+{:04X} should not survive sanitize (Cf)",
                ch,
                ch as u32
            );
        }
    }
}

/// **Acceptance:** empty sanitize result is valid and still passes other handshake gates.
#[test]
fn test_empty_after_sanitize_passes_validate() {
    let net = common::test_network_id().to_string();
    let hs = handshake_with_version(&net, "\u{FEFF}\u{200B}".to_string());
    let out = validate_remote_handshake(&hs, &net).expect("empty software_version is allowed");
    assert!(out.is_empty());
}

/// **Acceptance:** `validate_remote_handshake` returns exactly `sanitize_software_version` on `software_version`
/// when the peer is otherwise acceptable — this is the value copied into
/// `OutboundConnectResult::remote_software_version_sanitized` / the inbound `LiveSlot`.
#[test]
fn test_validate_remote_handshake_matches_sanitize() {
    let net = common::test_network_id().to_string();
    let raw = "dig\x00-gossip\u{200B}/\u{FEFF}0.1.0";
    let hs = handshake_with_version(&net, raw.to_string());
    let from_validate = validate_remote_handshake(&hs, &net).expect("valid handshake");
    assert_eq!(from_validate, sanitize_software_version(raw));
    assert_eq!(from_validate, "dig-gossip/0.1.0");
}
