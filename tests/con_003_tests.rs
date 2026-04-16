//! Tests for **CON-003: handshake validation** (network id, protocol version, software version policy).
//!
//! ## Traceability
//!
//! - **Spec + matrix:** [`CON-003.md`](../docs/requirements/domains/connection/specs/CON-003.md)
//!   (§Test Plan table — each `test_*` name maps to a row where applicable).
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/connection/NORMATIVE.md) §CON-003
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §5.1–5.2
//!
//! ## Proof strategy
//!
//! **Unit rows** call [`dig_gossip::connection::handshake`] helpers directly — they encode the same
//! rules as production without sockets. **Integration** [`test_validation_both_directions`] spins two
//! [`GossipService`] instances (CON-002 listener + CON-001 outbound) and verifies
//! [`GossipHandle::__con003_peer_versions_for_tests`] reflects accepted handshakes on **both**
//! sides, proving [`validate_remote_handshake`](dig_gossip::connection::handshake::validate_remote_handshake)
//! runs in [`dig_gossip::connection::listener`] and [`dig_gossip::connection::outbound`] before the
//! peer is admitted as a live TLS slot in the service peer map.

mod common;

use dig_gossip::Handshake;
use dig_gossip::connection::handshake::{
    is_compatible_protocol_version, sanitize_software_version, validate_remote_handshake,
    HandshakeValidationError, MAX_SOFTWARE_VERSION_BYTES, MIN_COMPATIBLE_PROTOCOL_VERSION,
};
use dig_gossip::{NodeType, PeerId};

/// Build a valid baseline [`Handshake`] for mutation in individual tests.
///
/// Defaults to protocol `0.0.37`, software `dig-gossip/0.1.0`, FullNode, port 8444.
/// Each test overrides the field under test while keeping other fields valid, isolating
/// the specific validation rule being exercised.
fn sample_handshake_base(network_id: &str) -> Handshake {
    Handshake {
        network_id: network_id.to_string(),
        protocol_version: "0.0.37".to_string(),
        software_version: "dig-gossip/0.1.0".to_string(),
        server_port: 8444,
        node_type: NodeType::FullNode,
        capabilities: vec![],
    }
}

/// **Row:** `test_reject_network_id_mismatch` — wrong `network_id` must surface
/// [`HandshakeValidationError::NetworkIdMismatch`] before any socket accept logic runs.
#[test]
fn test_reject_network_id_mismatch() {
    let hs = sample_handshake_base("deadbeef");
    let err = validate_remote_handshake(&hs, "cafe").unwrap_err();
    assert_eq!(
        err,
        HandshakeValidationError::NetworkIdMismatch {
            expected: "cafe".to_string(),
            actual: "deadbeef".to_string(),
        }
    );
}

/// **Row:** `test_reject_empty_network_id` — empty `network_id` must fail fast.
///
/// CON-003 implementation notes require that empty strings are caught before any
/// string comparison logic runs, preventing subtle bugs from comparing "" == "".
#[test]
fn test_reject_empty_network_id() {
    let net = common::test_network_id().to_string();
    let mut hs = sample_handshake_base(&net);
    hs.network_id = String::new();
    assert!(matches!(
        validate_remote_handshake(&hs, &net),
        Err(HandshakeValidationError::EmptyNetworkId)
    ));
}

/// **Row:** `test_reject_empty_protocol_version` — whitespace-only version strings are rejected.
///
/// The validator trims before checking, so `"   "` should be treated as empty.
#[test]
fn test_reject_empty_protocol_version() {
    let net = common::test_network_id().to_string();
    let mut hs = sample_handshake_base(&net);
    hs.protocol_version = "   ".to_string();
    assert!(matches!(
        validate_remote_handshake(&hs, &net),
        Err(HandshakeValidationError::EmptyProtocolVersion)
    ));
}

/// **Row:** `test_accept_matching_network_id` — identical wire id (hex [`Bytes32`] display) passes.
#[test]
fn test_accept_matching_network_id() {
    let net = common::test_network_id().to_string();
    let hs = sample_handshake_base(&net);
    let out = validate_remote_handshake(&hs, &net).expect("ok");
    assert_eq!(out, "dig-gossip/0.1.0");
}

/// **Row:** `test_reject_incompatible_protocol_version` — below [`MIN_COMPATIBLE_PROTOCOL_VERSION`] floor.
#[test]
fn test_reject_incompatible_protocol_version() {
    let net = common::test_network_id().to_string();
    let mut hs = sample_handshake_base(&net);
    hs.protocol_version = "0.0.1".to_string();
    let err = validate_remote_handshake(&hs, &net).unwrap_err();
    assert_eq!(
        err,
        HandshakeValidationError::IncompatibleProtocolVersion {
            version: "0.0.1".to_string(),
        }
    );
}

/// **Row:** `test_accept_compatible_protocol_version` — boundary at declared minimum is accepted.
#[test]
fn test_accept_compatible_protocol_version() {
    assert!(is_compatible_protocol_version(
        MIN_COMPATIBLE_PROTOCOL_VERSION
    ));
    let net = common::test_network_id().to_string();
    let mut hs = sample_handshake_base(&net);
    hs.protocol_version = MIN_COMPATIBLE_PROTOCOL_VERSION.to_string();
    assert!(validate_remote_handshake(&hs, &net).is_ok());
}

/// **Row:** `test_sanitize_strips_cc_chars` — ASCII controls are Cc (NUL, unit separator, DEL).
#[test]
fn test_sanitize_strips_cc_chars() {
    let s = sanitize_software_version("a\x00\x1f\x7Fb");
    assert_eq!(s, "ab");
}

/// **Row:** `test_sanitize_strips_cf_chars` — zero-width space + BOM are Cf.
#[test]
fn test_sanitize_strips_cf_chars() {
    let s = sanitize_software_version("x\u{200B}y\u{FEFF}z");
    assert_eq!(s, "xyz");
}

/// **Row:** `test_sanitize_preserves_normal_chars` — typical release string unchanged.
#[test]
fn test_sanitize_preserves_normal_chars() {
    let v = "dig-gossip/0.1.0";
    assert_eq!(sanitize_software_version(v), v);
}

/// **Row:** `test_sanitize_mixed_chars` — combined Cc + Cf removal.
#[test]
fn test_sanitize_mixed_chars() {
    let s = sanitize_software_version("dig\x00-gossip\u{200B}/0.1.0");
    assert_eq!(s, "dig-gossip/0.1.0");
}

/// **Row:** `test_reject_version_too_long` — byte length after sanitize, not grapheme count.
#[test]
fn test_reject_version_too_long() {
    let net = common::test_network_id().to_string();
    let mut hs = sample_handshake_base(&net);
    hs.software_version = "a".repeat(MAX_SOFTWARE_VERSION_BYTES + 1);
    let err = validate_remote_handshake(&hs, &net).unwrap_err();
    assert!(
        matches!(err, HandshakeValidationError::SoftwareVersionTooLong { len, max } if len > max),
        "{err:?}"
    );
}

/// **Row:** `test_accept_version_at_limit` — exactly [`MAX_SOFTWARE_VERSION_BYTES`] UTF-8 bytes OK.
#[test]
fn test_accept_version_at_limit() {
    let net = common::test_network_id().to_string();
    let mut hs = sample_handshake_base(&net);
    hs.software_version = "a".repeat(MAX_SOFTWARE_VERSION_BYTES);
    let out = validate_remote_handshake(&hs, &net).expect("at limit");
    assert_eq!(out.len(), MAX_SOFTWARE_VERSION_BYTES);
}

/// **Row:** `test_sanitize_empty_result` — only strippable characters yields empty (valid for policy).
#[test]
fn test_sanitize_empty_result() {
    assert_eq!(sanitize_software_version("\x00\x1f\u{200B}"), "");
    let net = common::test_network_id().to_string();
    let mut hs = sample_handshake_base(&net);
    hs.software_version = "\u{FEFF}\u{200B}".to_string();
    let out = validate_remote_handshake(&hs, &net).expect("empty sanitized is ok");
    assert!(out.is_empty());
}

/// **Row:** `test_validation_both_directions` — **Integration:** shared [`validate_remote_handshake`]
/// runs for inbound (server) and outbound (client); stored strings match handshakes each side saw
/// from its peer after validation + sanitize.
#[tokio::test]
async fn test_validation_both_directions() {
    // Listener (A): accepts inbound from B after handshake policy.
    let dir_a = common::test_temp_dir();
    let _ = common::generate_test_certs(dir_a.path());
    let mut cfg_a = common::test_gossip_config(dir_a.path());
    cfg_a.listen_addr = "127.0.0.1:0".parse().unwrap();
    let svc_a = dig_gossip::GossipService::new(cfg_a).expect("A new");
    let handle_a = svc_a.start().await.expect("A start");
    let bound = handle_a
        .__listen_bound_addr_for_tests()
        .expect("A must bind for CON-002 path");

    // Client (B): outbound dial to A.
    let dir_b = common::test_temp_dir();
    let _ = common::generate_test_certs(dir_b.path());
    let cfg_b = common::test_gossip_config(dir_b.path());
    let svc_b = dig_gossip::GossipService::new(cfg_b).expect("B new");
    let handle_b = svc_b.start().await.expect("B start");

    let peer_b_id = handle_a.__peer_ids_for_tests();
    assert!(
        peer_b_id.is_empty(),
        "A starts with no peers before B connects"
    );

    let peer_a_tls_id = handle_b.connect_to(bound).await.expect("B connects to A");

    // A should now see exactly one peer (B’s TLS identity).
    let keys_a = handle_a.__peer_ids_for_tests();
    assert_eq!(keys_a.len(), 1, "A should record one inbound peer");
    let from_b_on_a = keys_a[0];

    // B’s view of A uses A’s server certificate SPKI hash.
    assert_ne!(from_b_on_a, PeerId::default());
    assert_ne!(peer_a_tls_id, PeerId::default());

    let (prot_a, soft_b_to_a) = handle_a
        .__con003_peer_versions_for_tests(from_b_on_a)
        .expect("A stores LiveSlot for inbound peer");
    assert_eq!(prot_a, "0.0.37");
    // Outbound client hello uses placeholder software_version until it is customized (CON-001).
    assert_eq!(soft_b_to_a, "0.0.0");

    let (prot_b, soft_a_to_b) = handle_b
        .__con003_peer_versions_for_tests(peer_a_tls_id)
        .expect("B stores LiveSlot for outbound peer");
    assert_eq!(prot_b, "0.0.37");
    let expected_soft = format!("dig-gossip/{}", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        soft_a_to_b, expected_soft,
        "A’s listener replies with crate software tag"
    );
}
