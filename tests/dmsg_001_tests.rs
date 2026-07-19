//! DMSG-001 — dig-message transport seam (opcode 220 / `DIG_MESSAGE`), WU6 of epic #796.
//!
//! dig-gossip carries a dig-message envelope as **opaque bytes** over opcode 220. These
//! tests prove the four seam contracts the Wave-A adoption depends on:
//!
//! 1. **Opcode routing** — opcode 220 is recognised inbound and routed to the
//!    dig-message handler seam ([`is_dig_message`] / [`dig_message_payload`]); a
//!    non-220 frame is not.
//! 2. **Opaque round-trip** — bytes framed into an opcode-220 envelope come back
//!    byte-identical (bytes in == bytes out), including empty + arbitrary binary.
//! 3. **Send helper** — `send_dig_message` frames + delivers correctly (stub /
//!    unknown / banned peer behaviour mirrors `send_to`).
//! 4. **Streaming** — `StreamFrame` encode/decode round-trips and
//!    [`StreamReassembler`] restores in-order delivery across out-of-order transport.
//!
//! Pure framing/reassembly logic is tested directly; the send + inbound-routing rows
//! use the standard stub-peer harness (no real sockets).

mod common;

use std::net::SocketAddr;

use dig_gossip::gossip::broadcaster::{classify_broadcast, BroadcastStrategy};
use dig_gossip::{
    dig_message_payload, frame_envelope, is_dig_message, Bytes32, GossipError, GossipHandle,
    GossipService, NewPeak, NodeType, PenaltyReason, ProtocolMessageTypes, ReassembleError,
    StreamFrame, StreamReassembler, Streamable, DIG_MESSAGE, MAX_BUFFERED_BYTES,
    MAX_BUFFERED_CHUNKS,
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Spin up a running [`GossipService`] and return the service (kept alive) + handle.
async fn running_handle() -> (GossipService, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let h = svc.start().await.expect("start");
    (svc, h)
}

/// A deterministic loopback socket address for a stub peer.
fn stub_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().expect("addr")
}

// ---------------------------------------------------------------------------
// 1. Opcode constant + routing
// ---------------------------------------------------------------------------

/// **Row:** the canonical opcode is 220 and matches the vendored enum.
/// **Why sufficient:** 220 is a cross-repo canonical value; drift breaks the wire.
#[test]
fn dig_message_opcode_is_220() {
    assert_eq!(DIG_MESSAGE, 220);
    assert_eq!(DIG_MESSAGE, ProtocolMessageTypes::DigMessage as u8);
}

/// **Row:** `is_dig_message` recognises 220 and only 220.
#[test]
fn is_dig_message_recognises_only_220() {
    assert!(is_dig_message(220));
    assert!(!is_dig_message(219)); // RegisterAck (consensus band ceiling)
    assert!(!is_dig_message(200)); // NewAttestation
    assert!(!is_dig_message(0));
}

/// **Row:** an opcode-220 frame routes to the handler seam; a non-220 frame does not.
/// **Assertion:** `dig_message_payload` yields the opaque envelope for a 220 frame and
/// `None` for a `NewPeak` (non-directed) message.
#[test]
fn payload_extracted_only_from_opcode_220_frame() {
    let envelope = b"sealed-envelope-bytes".to_vec();
    let msg = frame_envelope(&envelope, None);
    assert_eq!(dig_message_payload(&msg), Some(envelope.as_slice()));

    let z = Bytes32::default();
    let not_dig = dig_gossip::Message {
        msg_type: ProtocolMessageTypes::NewPeak,
        id: None,
        data: NewPeak::new(z, 1, 1, 0, z).to_bytes().unwrap().into(),
    };
    assert_eq!(dig_message_payload(&not_dig), None);
}

/// **Row:** a directed dig-message is Unicast — it must NEVER be Plumtree-broadcast.
#[test]
fn dig_message_is_classified_unicast() {
    assert_eq!(
        classify_broadcast(ProtocolMessageTypes::DigMessage, false),
        BroadcastStrategy::Unicast
    );
}

// ---------------------------------------------------------------------------
// 2. Opaque round-trip (bytes in == bytes out)
// ---------------------------------------------------------------------------

/// **Row:** framing preserves the envelope byte-for-byte, including id correlation.
#[test]
fn frame_envelope_round_trips_bytes_opaquely() {
    for envelope in [
        Vec::new(),                       // empty
        b"hello".to_vec(),                // ascii
        vec![0u8, 255, 1, 254, 0, 0, 42], // arbitrary binary incl. NULs
    ] {
        let msg = frame_envelope(&envelope, Some(7));
        assert_eq!(msg.msg_type as u8, DIG_MESSAGE);
        assert_eq!(msg.id, Some(7));
        assert_eq!(
            msg.data.as_ref(),
            envelope.as_slice(),
            "bytes in == bytes out"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Send helper
// ---------------------------------------------------------------------------

/// **Row:** `send_dig_message` to a connected (stub) peer succeeds and is counted.
#[tokio::test]
async fn send_dig_message_to_stub_peer_succeeds() {
    let (_s, h) = running_handle().await;
    let peer = h
        .__connect_stub_peer_with_direction(stub_addr(41001), NodeType::FullNode, true)
        .await
        .expect("stub");

    h.send_dig_message(peer, b"envelope", None)
        .await
        .expect("send ok");

    assert_eq!(h.stats().await.messages_sent, 1);
}

/// **Row:** sending to an unknown peer is a clean `PeerNotConnected` error.
#[tokio::test]
async fn send_dig_message_to_unknown_peer_errors() {
    let (_s, h) = running_handle().await;
    let unknown = dig_gossip::PeerId::from([9u8; 32]);
    let err = h.send_dig_message(unknown, b"x", None).await.unwrap_err();
    assert!(matches!(err, GossipError::PeerNotConnected(_)));
}

/// **Row:** a banned peer is refused before any bytes are framed to it.
#[tokio::test]
async fn send_dig_message_to_banned_peer_errors() {
    let (_s, h) = running_handle().await;
    let peer = h
        .__connect_stub_peer_with_direction(stub_addr(41002), NodeType::FullNode, true)
        .await
        .expect("stub");
    h.ban_peer(&peer, PenaltyReason::ProtocolViolation)
        .await
        .expect("ban");

    let err = h.send_dig_message(peer, b"x", None).await.unwrap_err();
    assert!(matches!(err, GossipError::PeerBanned(_)));
}

/// **Row:** the stream send helpers frame + deliver OPEN/DATA/CLOSE over opcode 220.
#[tokio::test]
async fn stream_helpers_deliver_over_opcode_220() {
    let (_s, h) = running_handle().await;
    let peer = h
        .__connect_stub_peer_with_direction(stub_addr(41003), NodeType::FullNode, true)
        .await
        .expect("stub");

    h.open_dig_stream(peer, 42).await.expect("open");
    h.send_dig_stream_data(peer, 42, 0, b"chunk-0".to_vec())
        .await
        .expect("data");
    h.close_dig_stream(peer, 42).await.expect("close");

    assert_eq!(h.stats().await.messages_sent, 3);
}

// ---------------------------------------------------------------------------
// 4. Inbound routing end-to-end
// ---------------------------------------------------------------------------

/// **Row:** an injected opcode-220 inbound frame is delivered on the inbound bus and
/// its opaque envelope is recoverable by the dig-message seam.
#[tokio::test]
async fn inbound_opcode_220_frame_routes_to_seam() {
    let (_s, h) = running_handle().await;
    let mut rx = h.inbound_receiver().expect("rx");

    let sender = dig_gossip::PeerId::from([3u8; 32]);
    let envelope = b"inbound-sealed".to_vec();
    h.__inject_inbound_for_tests(sender, frame_envelope(&envelope, Some(1)))
        .expect("inject");

    let (got_sender, msg) = rx.recv().await.expect("recv");
    assert_eq!(got_sender, sender);
    assert_eq!(dig_message_payload(&msg), Some(envelope.as_slice()));
}

// ---------------------------------------------------------------------------
// 5. Streaming frame codec
// ---------------------------------------------------------------------------

/// **Row:** every `StreamFrame` variant round-trips through encode/decode.
#[test]
fn stream_frame_encode_decode_round_trips() {
    let frames = [
        StreamFrame::Open { stream_id: 7 },
        StreamFrame::Data {
            stream_id: 7,
            seq: 3,
            payload: vec![1, 2, 3, 0, 255],
        },
        StreamFrame::Data {
            stream_id: 7,
            seq: 4,
            payload: Vec::new(), // empty chunk is valid
        },
        StreamFrame::Close { stream_id: 7 },
    ];
    for f in frames {
        let decoded = StreamFrame::decode(&f.encode()).expect("decode");
        assert_eq!(decoded, f);
    }
}

/// **Row:** malformed stream frames decode to `None`, never panic.
#[test]
fn stream_frame_decode_rejects_malformed() {
    assert_eq!(StreamFrame::decode(&[]), None); // no kind byte
    assert_eq!(StreamFrame::decode(&[0, 1, 2]), None); // OPEN with short stream_id
    assert_eq!(StreamFrame::decode(&[1, 0, 0, 0, 0, 0, 0, 0, 1]), None); // DATA missing seq
    assert_eq!(StreamFrame::decode(&[99]), None); // unknown kind
}

// ---------------------------------------------------------------------------
// 6. Ordered reassembly
// ---------------------------------------------------------------------------

/// **Row:** in-order chunks are released immediately.
#[test]
fn reassembler_releases_in_order_chunks_immediately() {
    let mut r = StreamReassembler::new();
    assert_eq!(r.accept(0, b"a".to_vec()).unwrap(), vec![b"a".to_vec()]);
    assert_eq!(r.accept(1, b"b".to_vec()).unwrap(), vec![b"b".to_vec()]);
    assert_eq!(r.next_seq(), 2);
    assert_eq!(r.pending(), 0);
}

/// **Row:** out-of-order chunks buffer, then flush in order once the gap fills.
#[test]
fn reassembler_orders_out_of_order_delivery() {
    let mut r = StreamReassembler::new();
    // seq 2 and 1 arrive before seq 0 — nothing deliverable yet.
    assert!(r.accept(2, b"c".to_vec()).unwrap().is_empty());
    assert!(r.accept(1, b"b".to_vec()).unwrap().is_empty());
    assert_eq!(r.pending(), 2);
    // seq 0 arrives — the whole contiguous run flushes in order.
    assert_eq!(
        r.accept(0, b"a".to_vec()).unwrap(),
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
    );
    assert_eq!(r.next_seq(), 3);
    assert_eq!(r.pending(), 0);
}

/// **Row:** an already-delivered (duplicate/replayed) chunk is dropped.
#[test]
fn reassembler_drops_duplicate_chunks() {
    let mut r = StreamReassembler::new();
    assert_eq!(r.accept(0, b"a".to_vec()).unwrap(), vec![b"a".to_vec()]);
    assert!(r.accept(0, b"a-again".to_vec()).unwrap().is_empty()); // below next_seq — dropped
    assert_eq!(r.next_seq(), 1);
}

// ---------------------------------------------------------------------------
// 6b. Safe-by-default bounds (DoS hardening, #1182)
// ---------------------------------------------------------------------------

/// **Row:** a peer withholding `next_seq` while flooding higher sequences is
/// bounded — the reassembler rejects at the chunk cap instead of buffering forever.
#[test]
fn reassembler_bounds_withheld_seq_chunk_flood() {
    let mut r = StreamReassembler::with_caps(4, MAX_BUFFERED_BYTES);
    // seq 0 is withheld; the attacker streams 1..=4 (fills the 4-chunk cap).
    for seq in 1..=4 {
        assert!(r.accept(seq, b"x".to_vec()).unwrap().is_empty());
    }
    assert_eq!(r.pending(), 4);
    // The 5th out-of-order chunk is rejected — memory stays bounded.
    assert_eq!(
        r.accept(5, b"x".to_vec()),
        Err(ReassembleError::TooManyChunks { limit: 4 })
    );
    assert_eq!(r.pending(), 4, "buffer did not grow past the cap");
    // The gap-filling chunk at next_seq is still accepted and drains the buffer.
    assert_eq!(r.accept(0, b"g".to_vec()).unwrap().len(), 5);
    assert_eq!(r.pending(), 0);
}

/// **Row:** a few-huge-chunks flood is bounded by the byte cap even under the
/// chunk cap.
#[test]
fn reassembler_bounds_huge_chunk_byte_flood() {
    // Generous chunk cap, tiny byte cap: bytes are the binding constraint.
    let mut r = StreamReassembler::with_caps(MAX_BUFFERED_CHUNKS, 10);
    assert!(r.accept(1, vec![0u8; 6]).unwrap().is_empty());
    assert_eq!(r.buffered_bytes(), 6);
    // Another 6-byte chunk would total 12 > 10 — rejected.
    assert_eq!(
        r.accept(2, vec![0u8; 6]),
        Err(ReassembleError::TooManyBytes { limit: 10 })
    );
    assert_eq!(
        r.buffered_bytes(),
        6,
        "byte total did not grow past the cap"
    );
    assert_eq!(r.pending(), 1);
}

/// **Row:** a re-sent out-of-order chunk (already buffered) is idempotent — it
/// neither errors nor double-counts bytes against the cap.
#[test]
fn reassembler_rebuffered_chunk_is_idempotent() {
    let mut r = StreamReassembler::with_caps(2, MAX_BUFFERED_BYTES);
    assert!(r.accept(1, vec![0u8; 3]).unwrap().is_empty());
    assert!(r.accept(1, vec![0u8; 3]).unwrap().is_empty()); // dup of a buffered seq
    assert_eq!(r.pending(), 1);
    assert_eq!(
        r.buffered_bytes(),
        3,
        "duplicate did not double-count bytes"
    );
}

/// **Row:** default caps expose the safe-by-default values.
#[test]
fn reassembler_default_caps_are_safe() {
    assert_eq!(MAX_BUFFERED_CHUNKS, 256);
    assert_eq!(MAX_BUFFERED_BYTES, 4 * 1024 * 1024);
    // A default reassembler tolerates ordinary reordering without erroring.
    let mut r = StreamReassembler::new();
    for seq in (1..=100).rev() {
        assert!(r.accept(seq, b"x".to_vec()).unwrap().is_empty());
    }
    assert_eq!(r.accept(0, b"x".to_vec()).unwrap().len(), 101);
}

/// **Row:** the error type carries a human-readable message.
#[test]
fn reassemble_error_displays() {
    let e = ReassembleError::TooManyChunks { limit: 7 };
    assert!(e.to_string().contains('7'));
}
