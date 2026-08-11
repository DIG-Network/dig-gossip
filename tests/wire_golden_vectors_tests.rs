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

use chia_traits::Streamable;
use dig_gossip::{
    frame_dig_message, frame_envelope, DigMessageType, NodeType, RegisterAck, RegisterPeer,
};
use dig_peer_protocol::{ChiaProtocolMessage, Message};

/// Lowercase hex of a byte slice, for readable assertion diffs.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Wrap an already-serialized opcode body in the standard `Message` envelope and
/// return its full on-wire bytes.
///
/// This is the same envelope `Peer::send`/`request_infallible` puts on the socket
/// for the introducer opcodes, reproduced here so the vector pins the *frame*
/// rather than just the body.
fn envelope_bytes<T: Streamable + ChiaProtocolMessage>(body: &T, id: Option<u16>) -> Vec<u8> {
    Message {
        msg_type: T::msg_type(),
        id,
        data: body.to_bytes().expect("body serializes").into(),
    }
    .to_bytes()
    .expect("envelope serializes")
}

/// A payload whose two ends differ, so a reversed or truncated body is visible.
const ENVELOPE_PAYLOAD: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x7f];

// ============================================================================
// Opcode 220 — DigMessage (the directed-envelope send path)
// ============================================================================

#[test]
fn golden_opcode_220_dig_message_with_correlation_id() {
    let frame = frame_envelope(ENVELOPE_PAYLOAD, Some(0x1234))
        .to_bytes()
        .expect("frame serializes");
    assert_eq!(hex(&frame), "dc01123400000008deadbeef0102037f");
}

#[test]
fn golden_opcode_220_dig_message_without_correlation_id() {
    let frame = frame_envelope(ENVELOPE_PAYLOAD, None)
        .to_bytes()
        .expect("frame serializes");
    assert_eq!(hex(&frame), "dc0000000008deadbeef0102037f");
}

#[test]
fn golden_opcode_220_dig_message_empty_envelope() {
    let frame = frame_envelope(&[], None)
        .to_bytes()
        .expect("frame serializes");
    assert_eq!(hex(&frame), "dc0000000000");
}

// ============================================================================
// Consensus band 200-217 — frame_dig_message
// ============================================================================

#[test]
fn golden_consensus_band_first_opcode_200() {
    let frame = frame_dig_message(DigMessageType::NewAttestation, ENVELOPE_PAYLOAD.to_vec())
        .to_bytes()
        .expect("frame serializes");
    assert_eq!(hex(&frame), "c80000000008deadbeef0102037f");
}

#[test]
fn golden_consensus_band_last_opcode_217() {
    let frame = frame_dig_message(
        DigMessageType::PlumtreeRequestByHash,
        ENVELOPE_PAYLOAD.to_vec(),
    )
    .to_bytes()
    .expect("frame serializes");
    assert_eq!(hex(&frame), "d90000000008deadbeef0102037f");
}

// ============================================================================
// Opcodes 218/219 — introducer registration
// ============================================================================

#[test]
fn golden_opcode_218_register_peer_full_node() {
    let body = RegisterPeer::new("192.0.2.88".into(), 9555, NodeType::FullNode);
    assert_eq!(
        hex(&envelope_bytes(&body, Some(0x0007))),
        "da010007000000110000000a3139322e302e322e3838255301"
    );
}

#[test]
fn golden_opcode_218_register_peer_introducer_no_id() {
    let body = RegisterPeer::new("2001:db8::1".into(), 9444, NodeType::Introducer);
    assert_eq!(
        hex(&envelope_bytes(&body, None)),
        "da00000000120000000b323030313a6462383a3a3124e405"
    );
}

#[test]
fn golden_opcode_219_register_ack_success() {
    assert_eq!(
        hex(&envelope_bytes(&RegisterAck::new(true), Some(0x0007))),
        "db0100070000000101"
    );
}

#[test]
fn golden_opcode_219_register_ack_rejection() {
    assert_eq!(
        hex(&envelope_bytes(&RegisterAck::new(false), Some(0x0007))),
        "db0100070000000100"
    );
}
