//! Golden wire vectors for the DIG extension opcodes — the instrument that proves a vendored-fork
//! rebase did not move the wire.
//!
//! ## Why these exist
//!
//! `dig-gossip` speaks to a LIVE peer network, and its wire is vendored byte-identical into
//! `dig-relay` (GPL-2.0). A change to how a DIG frame encodes is therefore not a refactor — it is a
//! network-wide coordination event. When the vendored `chia-protocol` / `chia-sdk-client` trees are
//! rebased onto a newer upstream, the ONLY question that matters is whether the bytes on the wire
//! stayed the same.
//!
//! These vectors are recorded against the PRE-rebase tree and asserted unchanged afterwards. A
//! vector added *after* a change measures nothing — it merely re-records whatever the new code
//! happens to emit. That is the entire reason this file is committed separately from, and before,
//! any vendor bump.
//!
//! ## What is pinned
//!
//! The `Message` envelope — `[u8 msg_type][bool has_id][u16 id?][u32 data_len][u8… data]` — carried
//! for each of the three DIG opcodes dig-gossip puts on the wire, plus the raw discriminant of every
//! DIG opcode in the vendored `ProtocolMessageTypes`. Two properties are load-bearing and are
//! asserted independently:
//!
//! 1. **The discriminant.** Opcode 220 must stay 220. An upstream that later claims 220 for its own
//!    message would force a renumber, which is a wire break.
//! 2. **The envelope encoding.** Field order, the `Option<u16>` presence byte, and the big-endian
//!    `u32` length prefix must all survive the rebase.

use dig_peer_protocol::{Bytes, Message, ProtocolMessageTypes, Streamable};

/// Encode a `Message` to its wire bytes as a lowercase hex string.
///
/// Hex rather than a byte array so a failing assertion prints a diff a human can read against the
/// layout comment above, instead of a wall of decimal.
fn frame_hex(msg_type: ProtocolMessageTypes, id: Option<u16>, data: &[u8]) -> String {
    let msg = Message {
        msg_type,
        id,
        data: Bytes::new(data.to_vec()),
    };
    msg.to_bytes()
        .expect("a Message over an in-memory payload always encodes")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The DIG opcodes MUST keep the exact discriminants the live network already speaks.
///
/// Pinned as literals rather than derived from the enum: deriving them from the thing under test
/// would make this assertion circular, and a renumber is precisely the failure it exists to catch.
#[test]
fn dig_opcode_discriminants_are_pinned() {
    // DIG L2 consensus band (200–217) — extends Chia's namespace so a stock `Message` can carry a
    // DIG consensus opcode (#1404).
    assert_eq!(ProtocolMessageTypes::NewAttestation as u8, 200);
    assert_eq!(ProtocolMessageTypes::PlumtreeRequestByHash as u8, 217);

    // DIG introducer registration (218–219, DSC-005).
    assert_eq!(ProtocolMessageTypes::RegisterPeer as u8, 218);
    assert_eq!(ProtocolMessageTypes::RegisterAck as u8, 219);

    // DIG directed envelope + broadcast (220–222).
    assert_eq!(ProtocolMessageTypes::DigMessage as u8, 220); // WU6 / epic #796
    assert_eq!(ProtocolMessageTypes::StoreMelted as u8, 221); // epic #1316
    assert_eq!(ProtocolMessageTypes::HoldingsAnnounce as u8, 222); // #1428
}

/// `RegisterPeer` (218) — the introducer registration request, sent with a correlation id so the
/// `RegisterAck` can be matched to it.
#[test]
fn register_peer_frame_is_byte_stable() {
    // da = 218, 01 = id present, 002a = id 42, 00000004 = 4-byte payload, deadbeef = payload.
    assert_eq!(
        frame_hex(
            ProtocolMessageTypes::RegisterPeer,
            Some(42),
            &[0xde, 0xad, 0xbe, 0xef]
        ),
        "da01002a00000004deadbeef"
    );
}

/// `RegisterAck` (219) — the introducer's reply, which MUST come back on the requester's id.
#[test]
fn register_ack_frame_is_byte_stable() {
    // db = 219, id 42 echoed back, 1-byte payload.
    assert_eq!(
        frame_hex(ProtocolMessageTypes::RegisterAck, Some(42), &[0x01]),
        "db01002a0000000101"
    );
}

/// `DigMessage` (220) — the directed envelope, whose payload is opaque bytes to this layer.
///
/// Also pinned WITHOUT an id, because the `Option<u16>` presence byte is the one part of the
/// envelope whose encoding a streamable-macro change could plausibly alter without any DIG code
/// changing.
#[test]
fn dig_message_frame_is_byte_stable() {
    // dc = 220, 01 = id present, 0007 = id 7, 3-byte opaque payload.
    assert_eq!(
        frame_hex(ProtocolMessageTypes::DigMessage, Some(7), &[0xaa, 0xbb, 0xcc]),
        "dc01000700000003aabbcc"
    );

    // dc = 220, 00 = NO id (no u16 follows), 3-byte opaque payload.
    assert_eq!(
        frame_hex(ProtocolMessageTypes::DigMessage, None, &[0xaa, 0xbb, 0xcc]),
        "dc0000000003aabbcc"
    );
}

/// An empty payload must still emit its four-byte length prefix.
///
/// The zero-length case is where a length-prefix change hides: a codec that switched to a varint
/// would encode `0` as one byte and every non-empty vector above would still look plausible.
#[test]
fn empty_payload_keeps_its_four_byte_length_prefix() {
    assert_eq!(
        frame_hex(ProtocolMessageTypes::DigMessage, None, &[]),
        "dc0000000000"
    );
}

/// A DIG frame must survive a full round trip through the vendored decoder.
///
/// The encode-only vectors above prove the bytes we emit are unchanged; this proves the vendored
/// `Message::from_bytes` still ACCEPTS a DIG opcode. That acceptance is the sole reason the
/// `chia-protocol` fork exists, so a rebase that silently dropped the enum extension would pass
/// every assertion above and fail here.
#[test]
fn dig_frames_round_trip_through_the_vendored_decoder() {
    for opcode in [
        ProtocolMessageTypes::RegisterPeer,
        ProtocolMessageTypes::RegisterAck,
        ProtocolMessageTypes::DigMessage,
        ProtocolMessageTypes::StoreMelted,
        ProtocolMessageTypes::HoldingsAnnounce,
    ] {
        let original = Message {
            msg_type: opcode,
            id: Some(9),
            data: Bytes::new(vec![0x01, 0x02, 0x03]),
        };
        let encoded = original.to_bytes().expect("encodes");
        let decoded = Message::from_bytes(&encoded)
            .expect("the vendored enum must accept a DIG opcode off the wire");
        assert_eq!(decoded, original, "round trip changed the frame for {opcode:?}");
    }
}
