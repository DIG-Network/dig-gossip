//! dig-message transport seam — opcode 220 (`DIG_MESSAGE`).
//!
//! # What this is
//!
//! dig-gossip is the **transport** for the DIG directed-message protocol
//! (`dig-message`): it carries a sealed dig-message *envelope* between peers but
//! never inspects, seals, or opens it. On the wire a directed message is a stock
//! [`Message`](dig_peer_protocol::Message) with `msg_type = 220` ([`DIG_MESSAGE`]) whose
//! `data` field holds the envelope as **opaque bytes** — bytes in equal bytes out.
//!
//! This is WU6 of epic #796 (Wave A, envelope-only): the seam that the dig-message
//! streaming state machine (WU4) and its consumers build on. dig-gossip has **no**
//! knowledge of sealing (no BLS-G1 dependency) — the envelope is untyped payload.
//!
//! # Layers
//!
//! - [`DIG_MESSAGE`] — the canonical opcode (220), first of the free 220-255 band
//!   (200-219 are the consensus band, [`DigMessageType`](dig_peer_protocol::DigMessageType)).
//! - [`is_dig_message`] / [`dig_message_payload`] — inbound routing: recognise an
//!   opcode-220 frame and lift its opaque envelope.
//! - [`frame_envelope`] — build the outbound [`Message`] carrying an envelope.
//! - [`StreamFrame`] + [`StreamReassembler`] — the streaming seam: OPEN/DATA/CLOSE
//!   frames ride *inside* the opaque envelope payload; the reassembler restores
//!   in-order delivery. The streaming *state machine* itself lives in dig-message
//!   (WU4); dig-gossip only frames the bytes and delivers them ordered.
//!
//! The send/stream helpers on [`GossipHandle`](crate::service::gossip_handle::GossipHandle)
//! (`send_dig_message`, `open_dig_stream`, `send_dig_stream_data`, `close_dig_stream`)
//! put these frames on the wire.

use std::collections::BTreeMap;

use dig_peer_protocol::{DigMessageType, Message, ProtocolMessageTypes, Streamable};

/// Wire opcode for a directed dig-message envelope.
///
/// Canonical value **220** — the first opcode of the free 220-255 band. Mirrors
/// [`ProtocolMessageTypes::DigMessage`]; also exported as `dig_peer_protocol::DIG_MESSAGE`
/// for consumers that do not depend on dig-gossip. This value is a cross-repo
/// canonical constant — it MUST NOT drift.
pub const DIG_MESSAGE: u8 = ProtocolMessageTypes::DigMessage as u8;

/// True iff `msg_type` is the directed dig-message opcode ([`DIG_MESSAGE`]).
///
/// Inbound dispatch calls this on `Message.msg_type as u8` to route opcode-220
/// frames to the dig-message handler seam.
#[must_use]
pub fn is_dig_message(msg_type: u8) -> bool {
    msg_type == DIG_MESSAGE
}

/// Lift the opaque dig-message envelope from an inbound [`Message`].
///
/// Returns `Some(&envelope_bytes)` iff `msg` is an opcode-220 frame, else `None`.
/// The returned slice is the payload verbatim — dig-gossip does not parse it.
#[must_use]
pub fn dig_message_payload(msg: &Message) -> Option<&[u8]> {
    if is_dig_message(msg.msg_type as u8) {
        Some(msg.data.as_ref())
    } else {
        None
    }
}

/// Build the outbound opcode-220 [`Message`] that carries `envelope` as opaque bytes.
///
/// `correlation_id` maps to `Message.id` — used to pair a streaming exchange (all
/// frames of one stream share an id) or a request/response. `None` for a
/// fire-and-forget directed message.
#[must_use]
pub fn frame_envelope(envelope: &[u8], correlation_id: Option<u16>) -> Message {
    Message {
        msg_type: ProtocolMessageTypes::DigMessage,
        id: correlation_id,
        data: envelope.to_vec().into(),
    }
}

/// Build the on-wire [`Message`] that carries a DIG **consensus-band** opcode (200-219).
///
/// The DIG opcodes extend Chia's namespace: the vendored [`ProtocolMessageTypes`] mirrors every
/// [`DigMessageType`] discriminant 1:1 (#1404), so a stock [`Message`] can carry a DIG opcode in
/// its `msg_type` field. This is the SINGLE opcode-encoding path for the consensus band — the
/// dispatch authority ([`GossipHandle::broadcast_dig`](crate::service::gossip_handle::GossipHandle)
/// / [`send_dig`](crate::service::gossip_handle::GossipHandle)) frames every DIG message through
/// here so no second, drifting encoder can appear.
///
/// `body` is the already-serialized opcode payload; it is carried verbatim in `Message.data`.
/// The frame has no correlation `id` — the consensus band is fire-and-forget on the overlay,
/// unlike the directed opcode-220 envelope built by [`frame_envelope`].
#[must_use]
pub fn frame_dig_message(msg_type: DigMessageType, body: Vec<u8>) -> Message {
    // Total for the whole 200-219 band: `ProtocolMessageTypes` has a variant for every
    // `DigMessageType` discriminant (vendored, #1404), so this single-byte decode never fails.
    let pmt = ProtocolMessageTypes::from_bytes(&[msg_type as u8])
        .expect("every DigMessageType opcode has a mirrored ProtocolMessageTypes variant (#1404)");
    Message {
        msg_type: pmt,
        id: None,
        data: body.into(),
    }
}

// ============================================================================
// Streaming seam
// ============================================================================

/// Wire discriminant for a [`StreamFrame`] — the first byte of a stream payload.
mod stream_kind {
    pub const OPEN: u8 = 0;
    pub const DATA: u8 = 1;
    pub const CLOSE: u8 = 2;
}

/// One frame of a directed dig-message stream, carried inside the opaque
/// opcode-220 payload.
///
/// dig-gossip delivers these bytes ordered; the streaming *state machine*
/// (windowing, credit/backpressure, timeouts) belongs to dig-message (WU4). A
/// stream is identified by `stream_id`; `DATA` frames carry a monotonic `seq`
/// so [`StreamReassembler`] can restore order across out-of-order transport
/// delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamFrame {
    /// Open a new stream.
    Open {
        /// Caller-chosen stream identifier, unique per peer + direction.
        stream_id: u64,
    },
    /// A chunk of stream data at monotonic sequence `seq` (0-based).
    Data {
        /// The stream this chunk belongs to.
        stream_id: u64,
        /// Monotonic 0-based sequence number within the stream.
        seq: u64,
        /// Opaque chunk payload.
        payload: Vec<u8>,
    },
    /// Close the stream — no further frames follow.
    Close {
        /// The stream being closed.
        stream_id: u64,
    },
}

impl StreamFrame {
    /// Encode the frame to the opaque bytes that ride as an opcode-220 payload.
    ///
    /// Layout: `[u8 kind] [u64 stream_id]` then, for `Data`, `[u64 seq] [payload…]`.
    /// All integers are big-endian.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Open { stream_id } => {
                let mut buf = Vec::with_capacity(1 + 8);
                buf.push(stream_kind::OPEN);
                buf.extend_from_slice(&stream_id.to_be_bytes());
                buf
            }
            Self::Close { stream_id } => {
                let mut buf = Vec::with_capacity(1 + 8);
                buf.push(stream_kind::CLOSE);
                buf.extend_from_slice(&stream_id.to_be_bytes());
                buf
            }
            Self::Data {
                stream_id,
                seq,
                payload,
            } => {
                let mut buf = Vec::with_capacity(1 + 8 + 8 + payload.len());
                buf.push(stream_kind::DATA);
                buf.extend_from_slice(&stream_id.to_be_bytes());
                buf.extend_from_slice(&seq.to_be_bytes());
                buf.extend_from_slice(payload);
                buf
            }
        }
    }

    /// Decode a stream frame from an opcode-220 payload.
    ///
    /// Returns `None` if the buffer is truncated or the kind byte is unknown —
    /// a malformed frame is rejected, never panics.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&kind, rest) = bytes.split_first()?;
        match kind {
            stream_kind::OPEN => Some(Self::Open {
                stream_id: read_u64(rest)?,
            }),
            stream_kind::CLOSE => Some(Self::Close {
                stream_id: read_u64(rest)?,
            }),
            stream_kind::DATA => {
                let stream_id = read_u64(rest.get(..8)?)?;
                let seq = read_u64(rest.get(8..16)?)?;
                let payload = rest.get(16..)?.to_vec();
                Some(Self::Data {
                    stream_id,
                    seq,
                    payload,
                })
            }
            _ => None,
        }
    }
}

/// Read a big-endian `u64` from exactly the first 8 bytes of `bytes`.
///
/// Returns `None` unless `bytes` is at least 8 bytes long.
fn read_u64(bytes: &[u8]) -> Option<u64> {
    let eight: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    Some(u64::from_be_bytes(eight))
}

/// Default cap on the number of out-of-order chunks buffered ahead of `next_seq`.
///
/// A peer that withholds `next_seq` while streaming higher sequences would
/// otherwise buffer chunks forever; this bounds that gap to at most this many
/// pending chunks. `256` is generous for real reordering yet small enough that a
/// flood is rejected quickly. Override per stream with [`StreamReassembler::with_caps`].
pub const MAX_BUFFERED_CHUNKS: usize = 256;

/// Default cap on the total bytes of out-of-order chunk payloads held ahead of
/// `next_seq`.
///
/// Guards the few-huge-chunks variant of the flood (a handful of oversized chunks
/// that stay under [`MAX_BUFFERED_CHUNKS`] but exhaust memory). `4 MiB` bounds the
/// worst-case per-stream buffer. Override per stream with [`StreamReassembler::with_caps`].
pub const MAX_BUFFERED_BYTES: usize = 4 * 1024 * 1024;

/// Why an out-of-order chunk was rejected instead of buffered.
///
/// Returned by [`StreamReassembler::accept`] when accepting the chunk would grow
/// the pending buffer past a safe-by-default cap. The caller (the dig-message
/// streaming state machine, WU4) treats this as a fatal stream error and RESETs
/// the stream — the reassembler never panics and never grows past the cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassembleError {
    /// The pending out-of-order chunk count would exceed `limit`.
    TooManyChunks {
        /// The [`MAX_BUFFERED_CHUNKS`]-style cap that was hit.
        limit: usize,
    },
    /// The pending out-of-order byte total would exceed `limit`.
    TooManyBytes {
        /// The [`MAX_BUFFERED_BYTES`]-style cap that was hit.
        limit: usize,
    },
}

impl std::fmt::Display for ReassembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyChunks { limit } => {
                write!(f, "reassembler buffer full: {limit} out-of-order chunks")
            }
            Self::TooManyBytes { limit } => {
                write!(f, "reassembler buffer full: {limit} out-of-order bytes")
            }
        }
    }
}

impl std::error::Error for ReassembleError {}

/// Restores in-order delivery of a stream's `DATA` chunks — safe-by-default bounded.
///
/// Transport may deliver opcode-220 frames out of order; the reassembler buffers
/// chunks by `seq` and releases the longest contiguous run starting at the next
/// expected sequence. Duplicate or already-delivered chunks are dropped.
///
/// # Bounds (DoS-safe by default)
///
/// The pending out-of-order buffer is capped on BOTH dimensions so an attacker who
/// withholds `next_seq` while streaming higher sequences cannot grow memory without
/// bound: at most [`MAX_BUFFERED_CHUNKS`] chunks AND [`MAX_BUFFERED_BYTES`] total
/// bytes (configurable via [`with_caps`](Self::with_caps)). A chunk that would push
/// the buffer past either cap is rejected with a [`ReassembleError`] rather than
/// buffered — the caller RESETs the stream. A gap-filling chunk (at `next_seq`) is
/// always accepted, since it drains rather than grows the buffer.
///
/// This is a **single-stream** primitive: it holds ordering state for ONE stream and
/// carries no window/credit state — windowing, backpressure, timeouts, and bounding
/// the number of *concurrent* streams are the streaming state machine's job (WU4,
/// which owns the per-peer stream registry).
#[derive(Debug)]
pub struct StreamReassembler {
    /// The next sequence number expected for in-order delivery.
    next_seq: u64,
    /// Chunks received ahead of `next_seq`, keyed by their sequence.
    buffered: BTreeMap<u64, Vec<u8>>,
    /// Running total of `buffered` payload bytes (invariant: sum of all values' lengths).
    buffered_bytes: usize,
    /// Cap on `buffered.len()` for out-of-order chunks.
    max_chunks: usize,
    /// Cap on `buffered_bytes` for out-of-order chunks.
    max_bytes: usize,
}

impl Default for StreamReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamReassembler {
    /// A fresh reassembler expecting sequence 0 first, with the default caps
    /// ([`MAX_BUFFERED_CHUNKS`] / [`MAX_BUFFERED_BYTES`]).
    #[must_use]
    pub fn new() -> Self {
        Self::with_caps(MAX_BUFFERED_CHUNKS, MAX_BUFFERED_BYTES)
    }

    /// A fresh reassembler with explicit out-of-order buffer caps.
    ///
    /// `max_chunks` bounds the pending chunk COUNT and `max_bytes` the pending byte
    /// TOTAL; a chunk that would exceed either is rejected by [`accept`](Self::accept).
    #[must_use]
    pub fn with_caps(max_chunks: usize, max_bytes: usize) -> Self {
        Self {
            next_seq: 0,
            buffered: BTreeMap::new(),
            buffered_bytes: 0,
            max_chunks,
            max_bytes,
        }
    }

    /// Accept a `DATA` chunk and return every chunk now deliverable, in order.
    ///
    /// Feeding chunks in any order yields the same in-order output; a chunk with a
    /// `seq` below `next_seq` (a duplicate/replay) — or an out-of-order `seq` already
    /// buffered — is ignored and yields `Ok(empty)`.
    ///
    /// # Errors
    ///
    /// Returns [`ReassembleError`] when buffering a NEW out-of-order chunk would push
    /// the pending buffer past [`max_chunks`](Self::with_caps) or
    /// [`max_bytes`](Self::with_caps). The buffer is left unchanged (never grows past
    /// the cap); the caller RESETs the stream. A gap-filling chunk at `next_seq` is
    /// always accepted — it drains the buffer rather than growing it.
    pub fn accept(&mut self, seq: u64, payload: Vec<u8>) -> Result<Vec<Vec<u8>>, ReassembleError> {
        if seq < self.next_seq {
            return Ok(Vec::new()); // already delivered — drop duplicate
        }

        // A seq already buffered is a re-send: keep the FIRST payload and ignore this
        // one. A buffered chunk is immutable, so a peer cannot resize it — this closes
        // the byte-cap bypass where re-sending a buffered seq with a larger payload
        // would otherwise grow `buffered_bytes` past `max_bytes`. (`next_seq` is never
        // in `buffered` — it is drained on arrival — so this never blocks a gap fill.)
        if self.buffered.contains_key(&seq) {
            return Ok(Vec::new());
        }

        // A NEW out-of-order chunk (seq > next_seq) must be buffered until the gap
        // fills — enforce the caps here so a withheld `next_seq` cannot grow memory
        // without bound. An in-order chunk (seq == next_seq) is exempt: it drains
        // immediately, so it never grows the buffer even when it is at capacity.
        if seq > self.next_seq {
            if self.buffered.len() >= self.max_chunks {
                return Err(ReassembleError::TooManyChunks {
                    limit: self.max_chunks,
                });
            }
            if self.buffered_bytes.saturating_add(payload.len()) > self.max_bytes {
                return Err(ReassembleError::TooManyBytes {
                    limit: self.max_bytes,
                });
            }
        }

        // The seq is not yet buffered (guarded above), so this insert always adds a
        // new entry — maintain the `buffered_bytes == Σ payload lengths` invariant.
        self.buffered_bytes += payload.len();
        self.buffered.insert(seq, payload);

        let mut ready = Vec::new();
        while let Some(chunk) = self.buffered.remove(&self.next_seq) {
            self.buffered_bytes -= chunk.len();
            ready.push(chunk);
            self.next_seq += 1;
        }
        Ok(ready)
    }

    /// The next sequence number this reassembler is waiting for.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Number of chunks buffered ahead of `next_seq` awaiting a gap fill.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffered.len()
    }

    /// Total bytes currently held in the out-of-order buffer.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }
}
