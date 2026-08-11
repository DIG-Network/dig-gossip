//! Golden wire vectors — the byte-level contract dig-gossip must never break.
//!
//! # Why these exist
//!
//! dig-gossip is a **live peer network**, and its wire encoding is vendored
//! byte-identical into **dig-relay** (GPL-2.0). Any refactor of the framing code —
//! notably the migration off the vendored `chia-protocol` fork onto
//! `dig_peer_protocol`'s native types (dig_ecosystem#2228) — must leave every
//! encoded frame bit-for-bit unchanged.
//!
//! These vectors are the **instrument** for that claim, not a feature gate. They
//! pin literal hex captured from the encoder as it stands *before* any such
//! refactor, so a later change that alters the bytes fails here instead of
//! silently partitioning the network.
//!
//! # How to read a failure
//!
//! A diff here is never "update the expectation". It means the on-wire format
//! moved, which is a **coordinated network change** plus a matching dig-relay
//! update — not a refactor. Stop and escalate.
//!
//! # Both directions, one set of literals
//!
//! Every vector is a `const` hex string asserted in **both** directions: the
//! encoder must emit it, and [`DigMessage::from_bytes`] must recover the original
//! fields from it. Encode-only vectors would prove the wrong half — the vendored
//! fork existed precisely because `Message::from_bytes` *rejected* DIG opcodes, and
//! dig-relay encodes frames this crate has to decode. Sharing one literal between
//! the two directions is deliberate: two independent literals could drift into
//! agreeing with each other and with neither peer.
//!
//! # Fixture design
//!
//! Each vector is chosen to distinguish the real encoding from the nearest wrong
//! one, rather than merely to exercise the code path:
//!
//! - **Both `id` states.** `Message.id` is `Option<u16>`, encoded as a one-byte
//!   presence flag plus a big-endian `u16` when present. A vector with only
//!   `None` cannot see a lost or byte-swapped correlation id, so every opcode is
//!   pinned in both states where it is reachable.
//! - **A payload longer than one byte, with distinguishable ends.** The `data`
//!   field carries a `u32` big-endian length prefix; a one-byte or palindromic
//!   payload would hide both a wrong prefix width and a reversed body.
//! - **A `node_type` that is not the default.** `NodeType::FullNode` is
//!   discriminant `1`, which is indistinguishable from a bool-ish or
//!   off-by-one encoding. `Introducer = 5` is pinned alongside it so a collapsed
//!   discriminant mapping is visible.
//! - **Both `RegisterAck` outcomes.** `success == false` is a valid wire result
//!   (policy rejection), so pinning only `true` would miss an inverted flag.
//! - **An opcode no `ProtocolMessageTypes` variant can represent.** Accepting DIG
//!   opcodes is the entire reason `DigMessage` keys on a raw `u8`; without a frame
//!   the forked enum genuinely rejects, nothing here separates "decodes DIG
//!   opcodes" from "has not happened to reject one yet".

use chia_traits::Streamable;
use dig_gossip::{
    frame_dig_message, frame_envelope, DigMessageType, NodeType, ProtocolMessageTypes, RegisterAck,
    RegisterPeer,
};
use dig_peer_protocol::{DigMessage, DIG_MESSAGE};

/// Lowercase hex of a byte slice, for readable assertion diffs.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Bytes of a lowercase-hex literal — the inverse of [`hex`], so a decode vector reads
/// the same literal the matching encode vector asserts.
fn unhex(text: &str) -> Vec<u8> {
    assert!(
        text.len().is_multiple_of(2),
        "hex literal has an odd length"
    );
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex literal is well-formed"))
        .collect()
}

/// Decode a golden literal as a frame, failing loudly rather than returning `None` into
/// an assertion that could read a rejection as a mismatch.
fn decode(golden: &str) -> DigMessage {
    DigMessage::from_bytes(&unhex(golden)).expect("a golden frame must decode")
}

/// Wire opcode 218 — `RegisterPeer`.
const REGISTER_PEER: u8 = DigMessageType::RegisterPeer as u8;

/// Wire opcode 219 — `RegisterAck`.
const REGISTER_ACK: u8 = DigMessageType::RegisterAck as u8;

/// A payload whose two ends differ, so a reversed or truncated body is visible.
const ENVELOPE_PAYLOAD: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x7f];

// ============================================================================
// The golden literals — each asserted in both directions below.
// ============================================================================

const GOLDEN_220_WITH_ID: &str = "dc01123400000008deadbeef0102037f";
const GOLDEN_220_NO_ID: &str = "dc0000000008deadbeef0102037f";
const GOLDEN_220_EMPTY: &str = "dc0000000000";
const GOLDEN_200: &str = "c80000000008deadbeef0102037f";
const GOLDEN_217: &str = "d90000000008deadbeef0102037f";
const GOLDEN_218_FULL_NODE: &str = "da010007000000110000000a3139322e302e322e3838255301";
const GOLDEN_218_INTRODUCER: &str = "da00000000120000000b323030313a6462383a3a3124e405";
const GOLDEN_219_SUCCESS: &str = "db0100070000000101";
const GOLDEN_219_REJECTION: &str = "db0100070000000100";

/// The correlation id carried by every vector that pins the `Some` branch.
const CORRELATION_ID: u16 = 0x0007;

// ============================================================================
// Opcode 220 — DigMessage (the directed-envelope send path)
// ============================================================================

#[test]
fn golden_opcode_220_dig_message_with_correlation_id() {
    let frame = frame_envelope(ENVELOPE_PAYLOAD, Some(0x1234)).to_bytes();
    assert_eq!(hex(&frame), GOLDEN_220_WITH_ID);
}

#[test]
fn golden_opcode_220_dig_message_without_correlation_id() {
    let frame = frame_envelope(ENVELOPE_PAYLOAD, None).to_bytes();
    assert_eq!(hex(&frame), GOLDEN_220_NO_ID);
}

#[test]
fn golden_opcode_220_dig_message_empty_envelope() {
    let frame = frame_envelope(&[], None).to_bytes();
    assert_eq!(hex(&frame), GOLDEN_220_EMPTY);
}

#[test]
fn decode_opcode_220_recovers_the_correlation_id() {
    let msg = decode(GOLDEN_220_WITH_ID);
    assert_eq!(msg.msg_type, DIG_MESSAGE);
    assert_eq!(msg.id, Some(0x1234), "a byte-swapped id would read 0x3412");
    assert_eq!(msg.data.as_ref(), ENVELOPE_PAYLOAD);
}

#[test]
fn decode_opcode_220_recovers_the_absent_correlation_id() {
    let msg = decode(GOLDEN_220_NO_ID);
    assert_eq!(msg.msg_type, DIG_MESSAGE);
    assert_eq!(msg.id, None, "the presence flag is 0, so there is no id");
    assert_eq!(msg.data.as_ref(), ENVELOPE_PAYLOAD);
}

#[test]
fn decode_opcode_220_recovers_the_empty_envelope() {
    let msg = decode(GOLDEN_220_EMPTY);
    assert_eq!(msg.msg_type, DIG_MESSAGE);
    assert_eq!(msg.id, None);
    assert!(
        msg.data.is_empty(),
        "a zero-length payload is a valid frame, not a truncated one"
    );
}

// ============================================================================
// Consensus band 200-217 — frame_dig_message
// ============================================================================

#[test]
fn golden_consensus_band_first_opcode_200() {
    let frame =
        frame_dig_message(DigMessageType::NewAttestation, ENVELOPE_PAYLOAD.to_vec()).to_bytes();
    assert_eq!(hex(&frame), GOLDEN_200);
}

#[test]
fn golden_consensus_band_last_opcode_217() {
    let frame = frame_dig_message(
        DigMessageType::PlumtreeRequestByHash,
        ENVELOPE_PAYLOAD.to_vec(),
    )
    .to_bytes();
    assert_eq!(hex(&frame), GOLDEN_217);
}

#[test]
fn decode_consensus_band_first_opcode_200() {
    let msg = decode(GOLDEN_200);
    assert_eq!(msg.msg_type, DigMessageType::NewAttestation as u8);
    assert_eq!(msg.id, None);
    assert_eq!(msg.data.as_ref(), ENVELOPE_PAYLOAD);
}

#[test]
fn decode_consensus_band_last_opcode_217() {
    let msg = decode(GOLDEN_217);
    assert_eq!(msg.msg_type, DigMessageType::PlumtreeRequestByHash as u8);
    assert_eq!(msg.id, None);
    assert_eq!(msg.data.as_ref(), ENVELOPE_PAYLOAD);
}

// ============================================================================
// Opcodes 218/219 — introducer registration
// ============================================================================

/// Wrap an already-serialized opcode body in the standard frame envelope and return
/// its full on-wire bytes.
///
/// This is the same envelope `DigLink` puts on the socket for the introducer opcodes,
/// reproduced here so the vector pins the *frame* rather than just the body.
///
/// The opcode is passed in rather than derived from the body type: 218/219 have no
/// `ProtocolMessageTypes` variant to derive one from, which is the whole reason this
/// path moved off the forked enum.
fn envelope_bytes<T: Streamable>(body: &T, opcode: u8, id: Option<u16>) -> Vec<u8> {
    DigMessage::new(opcode, id, body.to_bytes().expect("body serializes").into()).to_bytes()
}

/// Recover an introducer body from a golden literal, asserting the frame around it first.
///
/// The opcode and id are checked here rather than in each caller so a body-level
/// assertion can never pass on a frame addressed to the wrong opcode.
fn decode_body<T: Streamable>(golden: &str, opcode: u8, id: Option<u16>) -> T {
    let msg = decode(golden);
    assert_eq!(msg.msg_type, opcode, "frame carries the wrong opcode");
    assert_eq!(msg.id, id, "frame carries the wrong correlation id");
    T::from_bytes(&msg.data).expect("a golden body must decode")
}

#[test]
fn golden_opcode_218_register_peer_full_node() {
    let body = RegisterPeer::new("192.0.2.88".into(), 9555, NodeType::FullNode);
    assert_eq!(
        hex(&envelope_bytes(&body, REGISTER_PEER, Some(CORRELATION_ID))),
        GOLDEN_218_FULL_NODE
    );
}

#[test]
fn golden_opcode_218_register_peer_introducer_no_id() {
    let body = RegisterPeer::new("2001:db8::1".into(), 9444, NodeType::Introducer);
    assert_eq!(
        hex(&envelope_bytes(&body, REGISTER_PEER, None)),
        GOLDEN_218_INTRODUCER
    );
}

#[test]
fn golden_opcode_219_register_ack_success() {
    assert_eq!(
        hex(&envelope_bytes(
            &RegisterAck::new(true),
            REGISTER_ACK,
            Some(CORRELATION_ID)
        )),
        GOLDEN_219_SUCCESS
    );
}

#[test]
fn golden_opcode_219_register_ack_rejection() {
    assert_eq!(
        hex(&envelope_bytes(
            &RegisterAck::new(false),
            REGISTER_ACK,
            Some(CORRELATION_ID)
        )),
        GOLDEN_219_REJECTION
    );
}

#[test]
fn decode_opcode_218_register_peer_full_node() {
    let body: RegisterPeer = decode_body(GOLDEN_218_FULL_NODE, REGISTER_PEER, Some(CORRELATION_ID));
    assert_eq!(
        body,
        RegisterPeer::new("192.0.2.88".into(), 9555, NodeType::FullNode)
    );
}

#[test]
fn decode_opcode_218_register_peer_introducer_no_id() {
    let body: RegisterPeer = decode_body(GOLDEN_218_INTRODUCER, REGISTER_PEER, None);
    assert_eq!(
        body,
        RegisterPeer::new("2001:db8::1".into(), 9444, NodeType::Introducer),
        "Introducer is discriminant 5 — a collapsed mapping would decode as FullNode"
    );
}

#[test]
fn decode_opcode_219_register_ack_success() {
    let body: RegisterAck = decode_body(GOLDEN_219_SUCCESS, REGISTER_ACK, Some(CORRELATION_ID));
    assert_eq!(body, RegisterAck::new(true));
}

#[test]
fn decode_opcode_219_register_ack_rejection() {
    let body: RegisterAck = decode_body(GOLDEN_219_REJECTION, REGISTER_ACK, Some(CORRELATION_ID));
    assert_eq!(
        body,
        RegisterAck::new(false),
        "an inverted flag would decode a policy rejection as an acceptance"
    );
}

// ============================================================================
// The negative vector — an opcode the forked enum cannot represent
// ============================================================================

/// An opcode assigned by neither Chia nor DIG.
///
/// Deliberately outside the DIG bands too: a DIG opcode would prove only that *these*
/// extensions decode, where the contract is that **any** byte does.
const UNASSIGNED_OPCODE: u8 = 0xfe;

/// The same shape as [`GOLDEN_220_NO_ID`], differing only in the opcode byte.
const GOLDEN_UNASSIGNED_OPCODE: &str = "fe0000000008deadbeef0102037f";

#[test]
fn the_unassigned_opcode_really_is_unrepresentable_as_a_protocol_message_type() {
    // Without this the negative vector below is unfalsifiable: it would pass just as
    // happily on an opcode the forked enum accepts.
    assert!(
        ProtocolMessageTypes::from_bytes(&[UNASSIGNED_OPCODE]).is_err(),
        "0xfe must have no ProtocolMessageTypes variant, or the vector proves nothing"
    );
}

#[test]
fn golden_unassigned_opcode_encodes() {
    let frame =
        DigMessage::new(UNASSIGNED_OPCODE, None, ENVELOPE_PAYLOAD.to_vec().into()).to_bytes();
    assert_eq!(hex(&frame), GOLDEN_UNASSIGNED_OPCODE);
}

#[test]
fn decode_unassigned_opcode_succeeds_where_the_forked_enum_rejected() {
    let msg = decode(GOLDEN_UNASSIGNED_OPCODE);
    assert_eq!(msg.msg_type, UNASSIGNED_OPCODE);
    assert_eq!(msg.id, None);
    assert_eq!(msg.data.as_ref(), ENVELOPE_PAYLOAD);
}
