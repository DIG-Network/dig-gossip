//! Profile-sync wire messages — opcodes 223/224/225 (epic #3008, W3).
//!
//! # What this is
//!
//! A dig-profile is a DID singleton plus a dig-store whose contents are summarised by a
//! sparse-merkle-tree **root**. Peers keep their view of a profile fresh with a three-message
//! exchange carried on the ordinary gossip transport:
//!
//! | Opcode | Name | Shape | Body |
//! |---|---|---|---|
//! | 223 | [`PROFILE_ROOT_ANNOUNCE`] | public flood | `store_id ‖ root`, exactly [`ENCODED_LEN`] bytes |
//! | 224 | [`PROFILE_BODY_REQUEST`] | directed | `store_id ‖ root`, exactly [`ENCODED_LEN`] bytes |
//! | 225 | [`PROFILE_BODY`] | directed | `store_id ‖ root ‖ len:u32be ‖ body` |
//!
//! This module is the WIRE ONLY: the opcode constants, byte-exact encode/decode, the size
//! bounds the rate-limit rows are tied to, and the three `frame_*` builders. It mirrors
//! [`dig_peer_protocol`]'s definitions, which are the single source of truth for the opcode
//! values and the layouts.
//!
//! # dig-gossip NEVER parses a profile body
//!
//! [`ProfileBody::body`] is **opaque bytes** here — exactly the discipline opcode 220
//! ([`DIG_MESSAGE`](crate::service::dig_message::DIG_MESSAGE)) already follows. This module
//! validates only the FRAME: that the two hashes are present, that the declared `len` agrees
//! with the bytes actually carried, and that the whole frame fits
//! [`MAX_PROFILE_BODY_FRAME_BYTES`]. Every semantic check — rehashing the body against `root`,
//! comparing that root against chain, canonicality, and any structural bound inside the body —
//! belongs to dig-node (W6). Decoding the body here would put a parser for untrusted peer input
//! in the transport layer and duplicate a check that must exist downstream anyway.
//!
//! # 223 is deliberately UNSIGNED, and a receiver MUST NOT reject it for that
//!
//! The authority for a profile root is the **on-chain** root, never the announcing peer, so a
//! receiver verifies any announced root against chain before trusting it. A forged announce
//! therefore costs an attacker at most one wasted [`PROFILE_BODY_REQUEST`] whose answer then
//! fails the receiver's root compare. A receiver that demanded a signature would silently drop
//! the entire protocol, since no honest sender produces one — so no code path in this crate
//! consults a signature for 223, and none may be added. `dig-peer-protocol`'s SPEC states this
//! in both directions.
//!
//! # Rate limits are load-bearing here
//!
//! [`DigRateLimiter::check`](crate::connection::dig_rate_limiter::DigRateLimiter::check) **fails
//! OPEN** for a 220-band opcode with no row, so an opcode added without one is effectively
//! unlimited — and 223 is a broadcast. All three opcodes therefore carry a deliberate row in
//! [`dig_extension_rate_limits_map`](crate::connection::inbound_limits::dig_extension_rate_limits_map),
//! each `max_size` referencing the constants below rather than a bare literal, so the enforced
//! frame bound and the limiter bound cannot drift apart.

use chia_protocol::Bytes32;
use dig_peer_protocol::{Bytes, DigMessage};

/// Wire opcode for a **profile-root announce** broadcast.
///
/// Canonical value **223**, mirroring [`dig_peer_protocol::PROFILE_ROOT_ANNOUNCE`] (the single
/// definition). Cross-repo canonical — dig-node pins it to decode the broadcast.
pub const PROFILE_ROOT_ANNOUNCE: u8 = dig_peer_protocol::PROFILE_ROOT_ANNOUNCE;

/// Wire opcode for a directed **profile-body request**.
///
/// Canonical value **224**, mirroring [`dig_peer_protocol::PROFILE_BODY_REQUEST`].
pub const PROFILE_BODY_REQUEST: u8 = dig_peer_protocol::PROFILE_BODY_REQUEST;

/// Wire opcode for a directed **profile-body** response.
///
/// Canonical value **225**, mirroring [`dig_peer_protocol::PROFILE_BODY`].
pub const PROFILE_BODY: u8 = dig_peer_protocol::PROFILE_BODY;

/// Exact on-wire length, in bytes, of a [`ProfileRootRef`] — the payload of BOTH the 223
/// announce and the 224 request.
///
/// Two 32-byte hashes (`store_id ‖ root`) with no framing, no padding and no length prefix, so
/// the length is fixed. [`ProfileRootRef::decode`] accepts a slice only at exactly this length:
/// a truncated or padded frame is refused rather than silently reinterpreted.
pub const ENCODED_LEN: usize = 64;

/// Maximum total on-wire size, in bytes, of an encoded [`PROFILE_BODY`] (225) frame.
///
/// **1 MiB, taken from the protocol's own ceiling rather than picked by feel.** It is exactly the
/// `max_size` of Chia's `default_settings` row, which
/// [`InboundRateLimiter::allows`](crate::connection::inbound_limits::InboundRateLimiter::allows)
/// applies to every frame before the DIG row is consulted — so a bound any larger could never be
/// reached in practice and would only create a range of frames this crate emits and the live gate
/// drops. It sits far below [`DigMessage::MAX_MESSAGE_SIZE`] (16 MiB), the absolute framing cap.
///
/// The bound is ENFORCED, not advisory: [`ProfileBody::decode`] refuses a longer frame and
/// [`frame_profile_body`] refuses to build one, so every accepted 225 frame is provably within
/// the opcode-225 limiter row (which references this constant) and is never hard-dropped.
pub const MAX_PROFILE_BODY_FRAME_BYTES: usize = 1024 * 1024;

/// Fixed overhead of a [`PROFILE_BODY`] frame: `store_id ‖ root ‖ len:u32be`.
const BODY_FRAME_HEADER_LEN: usize = ENCODED_LEN + 4;

/// Maximum length, in bytes, of the opaque body a single [`PROFILE_BODY`] frame may carry.
///
/// Derived from [`MAX_PROFILE_BODY_FRAME_BYTES`] minus the fixed header, so the two can never
/// disagree about which bodies fit.
pub const MAX_PROFILE_BODY_BYTES: usize = MAX_PROFILE_BODY_FRAME_BYTES - BODY_FRAME_HEADER_LEN;

/// A `(store_id, root)` pair — the entire payload of a 223 announce and a 224 request.
///
/// The two opcodes share one payload type because they carry byte-identical content: the
/// announce states "my profile for this store is at this root", and the request asks "send me
/// the body behind that exact root". Only the opcode distinguishes them on the wire, which is
/// why the [`frame_profile_root_announce`] / [`frame_profile_body_request`] builders exist
/// rather than a single builder taking an opcode argument a caller could get wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileRootRef {
    /// The dig-store whose profile this refers to.
    pub store_id: Bytes32,
    /// The profile-SMT root. Authority for this value is on-chain, never the sender.
    pub root: Bytes32,
}

impl ProfileRootRef {
    /// Encode to the fixed-length ([`ENCODED_LEN`]) wire bytes: `store_id[32] ‖ root[32]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ENCODED_LEN);
        buf.extend_from_slice(self.store_id.as_ref());
        buf.extend_from_slice(self.root.as_ref());
        buf
    }

    /// Decode from the fixed-length wire bytes produced by [`encode`](Self::encode).
    ///
    /// Returns `None` unless `bytes` is exactly [`ENCODED_LEN`] long — a truncated or padded
    /// frame is refused, never reinterpreted and never a panic.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ENCODED_LEN {
            return None;
        }
        Some(Self {
            store_id: Bytes32::from(<[u8; 32]>::try_from(&bytes[0..32]).ok()?),
            root: Bytes32::from(<[u8; 32]>::try_from(&bytes[32..64]).ok()?),
        })
    }
}

/// A profile-body response payload: the `(store_id, root)` the request named, plus the opaque
/// body bytes behind that root.
///
/// `body` is NEVER interpreted by this crate — see the module docs. dig-node rehashes it against
/// `root` and applies every semantic rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileBody {
    /// The dig-store whose profile body this is.
    pub store_id: Bytes32,
    /// The root the body claims to hash to. The receiver, not this crate, checks that claim.
    pub root: Bytes32,
    /// Opaque profile-body bytes, at most [`MAX_PROFILE_BODY_BYTES`] long.
    pub body: Vec<u8>,
}

impl ProfileBody {
    /// The exact on-wire length this value encodes to.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        BODY_FRAME_HEADER_LEN + self.body.len()
    }

    /// Whether this value fits [`MAX_PROFILE_BODY_FRAME_BYTES`] and can therefore be framed.
    #[must_use]
    pub fn fits_frame_cap(&self) -> bool {
        self.encoded_len() <= MAX_PROFILE_BODY_FRAME_BYTES
    }

    /// Encode to the wire bytes: `store_id[32] ‖ root[32] ‖ len[4, big-endian] ‖ body[len]`.
    ///
    /// Encoding an over-cap value is possible (it is a plain serialisation); it is
    /// [`frame_profile_body`] that refuses to put one on the wire, and
    /// [`decode`](Self::decode) that refuses to accept one.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        buf.extend_from_slice(self.store_id.as_ref());
        buf.extend_from_slice(self.root.as_ref());
        buf.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Decode from the wire bytes produced by [`encode`](Self::encode).
    ///
    /// Returns `None` — never a panic, never a partial value — when any of these hold:
    ///
    /// - the frame is shorter than the fixed `store_id ‖ root ‖ len` header (truncated);
    /// - the declared `len` disagrees with the number of bytes actually present, in EITHER
    ///   direction (a short read AND trailing garbage are both refusals);
    /// - the whole frame exceeds [`MAX_PROFILE_BODY_FRAME_BYTES`].
    ///
    /// The cap is checked against the frame ACTUALLY received, so an over-long frame is refused
    /// on its real size rather than on a self-declared length a hostile sender controls.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_PROFILE_BODY_FRAME_BYTES {
            return None;
        }
        if bytes.len() < BODY_FRAME_HEADER_LEN {
            return None;
        }
        let store_id = Bytes32::from(<[u8; 32]>::try_from(&bytes[0..32]).ok()?);
        let root = Bytes32::from(<[u8; 32]>::try_from(&bytes[32..64]).ok()?);
        let declared = u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[64..68]).ok()?) as usize;
        let actual = bytes.len() - BODY_FRAME_HEADER_LEN;
        if declared != actual {
            return None;
        }
        Some(Self {
            store_id,
            root,
            body: bytes[BODY_FRAME_HEADER_LEN..].to_vec(),
        })
    }
}

/// True iff `msg_type` is the profile-root-announce opcode ([`PROFILE_ROOT_ANNOUNCE`]).
#[must_use]
pub fn is_profile_root_announce(msg_type: u8) -> bool {
    msg_type == PROFILE_ROOT_ANNOUNCE
}

/// True iff `msg_type` is the profile-body-request opcode ([`PROFILE_BODY_REQUEST`]).
#[must_use]
pub fn is_profile_body_request(msg_type: u8) -> bool {
    msg_type == PROFILE_BODY_REQUEST
}

/// True iff `msg_type` is the profile-body opcode ([`PROFILE_BODY`]).
#[must_use]
pub fn is_profile_body(msg_type: u8) -> bool {
    msg_type == PROFILE_BODY
}

/// Lift and decode a [`ProfileRootRef`] from an inbound opcode-223 frame.
///
/// Returns `Some` iff `msg` is a 223 frame whose `data` decodes. The caller MUST still compare
/// the root against chain — an announce is unsigned and carries no authority of its own.
#[must_use]
pub fn profile_root_announce_payload(msg: &DigMessage) -> Option<ProfileRootRef> {
    if is_profile_root_announce(msg.msg_type) {
        ProfileRootRef::decode(msg.data.as_ref())
    } else {
        None
    }
}

/// Lift and decode a [`ProfileRootRef`] from an inbound opcode-224 frame.
#[must_use]
pub fn profile_body_request_payload(msg: &DigMessage) -> Option<ProfileRootRef> {
    if is_profile_body_request(msg.msg_type) {
        ProfileRootRef::decode(msg.data.as_ref())
    } else {
        None
    }
}

/// Lift and decode a [`ProfileBody`] from an inbound opcode-225 frame.
///
/// Frame-level checks only ([`ProfileBody::decode`]); the body itself stays opaque.
#[must_use]
pub fn profile_body_payload(msg: &DigMessage) -> Option<ProfileBody> {
    if is_profile_body(msg.msg_type) {
        ProfileBody::decode(msg.data.as_ref())
    } else {
        None
    }
}

/// Build the outbound opcode-223 [`DigMessage`] that floods `root_ref` to every peer.
///
/// `id` is `None`: an announce is a fire-and-forget public flood, not a correlated
/// request/response. The caller broadcasts it through
/// [`GossipHandle::broadcast`](crate::service::gossip_handle::GossipHandle::broadcast).
#[must_use]
pub fn frame_profile_root_announce(root_ref: &ProfileRootRef) -> DigMessage {
    DigMessage::new(PROFILE_ROOT_ANNOUNCE, None, Bytes::new(root_ref.encode()))
}

/// Build the outbound opcode-224 [`DigMessage`] asking ONE peer for the body behind `root_ref`.
///
/// Directed, so the caller sends it to a single peer rather than broadcasting. `id` is `None`:
/// the exchange is correlated by `(store_id, root)`, which the 225 answer echoes back, not by a
/// transport-level id.
#[must_use]
pub fn frame_profile_body_request(root_ref: &ProfileRootRef) -> DigMessage {
    DigMessage::new(PROFILE_BODY_REQUEST, None, Bytes::new(root_ref.encode()))
}

/// Build the outbound opcode-225 [`DigMessage`] answering a request with `body`.
///
/// Returns `None` when the frame would exceed [`MAX_PROFILE_BODY_FRAME_BYTES`] — this crate
/// refuses to emit a frame the receiving gate would drop, so an over-large profile fails
/// visibly at the sender instead of silently on every receiver.
#[must_use]
pub fn frame_profile_body(body: &ProfileBody) -> Option<DigMessage> {
    if !body.fits_frame_cap() {
        return None;
    }
    Some(DigMessage::new(
        PROFILE_BODY,
        None,
        Bytes::new(body.encode()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// A deterministic 32-byte fixture derived from a label — never a hard-coded literal, so a
    /// second implementation reproduces the same vector.
    fn hash32(label: &str) -> Bytes32 {
        let digest: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        Bytes32::from(digest)
    }

    fn sample_ref() -> ProfileRootRef {
        ProfileRootRef {
            store_id: hash32("profile-sync/store-a"),
            root: hash32("profile-sync/root-a"),
        }
    }

    fn sample_body(len: usize) -> ProfileBody {
        ProfileBody {
            store_id: hash32("profile-sync/store-a"),
            root: hash32("profile-sync/root-a"),
            // A varied byte pattern, so a decoder that dropped or reordered bytes cannot pass by
            // producing an all-zero body of the right length.
            body: (0..len).map(|i| (i % 251) as u8).collect(),
        }
    }

    #[test]
    fn opcodes_are_the_canonical_223_224_225() {
        assert_eq!(PROFILE_ROOT_ANNOUNCE, 223);
        assert_eq!(PROFILE_BODY_REQUEST, 224);
        assert_eq!(PROFILE_BODY, 225);
    }

    #[test]
    fn root_ref_round_trips_byte_identically() {
        let original = sample_ref();
        let wire = original.encode();
        assert_eq!(wire.len(), ENCODED_LEN);
        let decoded = ProfileRootRef::decode(&wire).expect("a well-formed 64-byte ref decodes");
        assert_eq!(decoded, original);
        assert_eq!(
            decoded.encode(),
            wire,
            "encode→decode→encode must be byte-identical"
        );
    }

    /// The layout is `store_id ‖ root`, in that order and with no framing — pinned positionally
    /// so a field swap (which a round-trip alone cannot see) fails.
    #[test]
    fn root_ref_layout_is_store_id_then_root() {
        let r = sample_ref();
        let wire = r.encode();
        assert_eq!(&wire[0..32], r.store_id.as_ref());
        assert_eq!(&wire[32..64], r.root.as_ref());
        assert_ne!(
            r.store_id, r.root,
            "the fixture must use DIFFERENT hashes, or a field swap would be invisible"
        );
    }

    #[test]
    fn truncated_root_ref_is_refused() {
        let wire = sample_ref().encode();
        assert!(ProfileRootRef::decode(&wire[..ENCODED_LEN - 1]).is_none());
        assert!(ProfileRootRef::decode(&[]).is_none());
    }

    #[test]
    fn padded_root_ref_is_refused() {
        let mut wire = sample_ref().encode();
        wire.push(0);
        assert!(ProfileRootRef::decode(&wire).is_none());
    }

    #[test]
    fn body_round_trips_byte_identically() {
        let original = sample_body(4096);
        let wire = original.encode();
        assert_eq!(wire.len(), original.encoded_len());
        let decoded = ProfileBody::decode(&wire).expect("a well-formed body frame decodes");
        assert_eq!(decoded, original);
        assert_eq!(
            decoded.encode(),
            wire,
            "encode→decode→encode must be byte-identical"
        );
    }

    /// An empty body is a legal frame: the header alone, with `len = 0`.
    #[test]
    fn empty_body_round_trips() {
        let original = sample_body(0);
        let wire = original.encode();
        assert_eq!(wire.len(), BODY_FRAME_HEADER_LEN);
        assert_eq!(ProfileBody::decode(&wire).as_ref(), Some(&original));
    }

    #[test]
    fn body_layout_is_store_id_root_len_be_body() {
        let b = sample_body(3);
        let wire = b.encode();
        assert_eq!(&wire[0..32], b.store_id.as_ref());
        assert_eq!(&wire[32..64], b.root.as_ref());
        assert_eq!(
            &wire[64..68],
            &3u32.to_be_bytes(),
            "length prefix is BIG-endian u32"
        );
        assert_eq!(&wire[68..], &b.body[..]);
    }

    #[test]
    fn truncated_body_frame_is_refused() {
        let wire = sample_body(64).encode();
        // Cut inside the body: the declared length now exceeds what is present.
        assert!(ProfileBody::decode(&wire[..wire.len() - 1]).is_none());
        // Cut inside the fixed header: not even the length prefix is complete.
        assert!(ProfileBody::decode(&wire[..BODY_FRAME_HEADER_LEN - 1]).is_none());
        assert!(ProfileBody::decode(&[]).is_none());
    }

    /// A frame whose declared length disagrees with the bytes actually carried is refused in
    /// BOTH directions — a short read (declared > actual) and trailing garbage (declared <
    /// actual). A decoder that merely sliced `[68..68+declared]` would accept the second.
    #[test]
    fn body_frame_with_disagreeing_declared_length_is_refused() {
        let honest = sample_body(64);
        let wire = honest.encode();

        let mut over_declared = wire.clone();
        over_declared[64..68].copy_from_slice(&65u32.to_be_bytes());
        assert!(
            ProfileBody::decode(&over_declared).is_none(),
            "declared 65 with 64 bytes present must be refused"
        );

        let mut under_declared = wire.clone();
        under_declared[64..68].copy_from_slice(&63u32.to_be_bytes());
        assert!(
            ProfileBody::decode(&under_declared).is_none(),
            "declared 63 with 64 bytes present (trailing garbage) must be refused"
        );

        // Control: the untouched frame DOES decode, so the two refusals above are attributable
        // to the length disagreement and not to the fixture being malformed.
        assert!(ProfileBody::decode(&wire).is_some());
    }

    /// A hostile `len` prefix cannot cause a panic or an over-read, however extreme.
    #[test]
    fn body_frame_with_absurd_declared_length_is_refused_without_panicking() {
        let mut wire = sample_body(8).encode();
        wire[64..68].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(ProfileBody::decode(&wire).is_none());
    }

    /// The frame cap is pinned from BOTH sides: exactly at the cap decodes, one byte over is
    /// refused. A bound tested only from below can only confirm itself.
    #[test]
    fn body_frame_cap_is_enforced_at_the_boundary() {
        let at_cap = sample_body(MAX_PROFILE_BODY_BYTES);
        let wire = at_cap.encode();
        assert_eq!(wire.len(), MAX_PROFILE_BODY_FRAME_BYTES);
        assert!(
            ProfileBody::decode(&wire).is_some(),
            "a frame of exactly MAX_PROFILE_BODY_FRAME_BYTES must be accepted"
        );

        let over_cap = sample_body(MAX_PROFILE_BODY_BYTES + 1);
        let over_wire = over_cap.encode();
        assert_eq!(over_wire.len(), MAX_PROFILE_BODY_FRAME_BYTES + 1);
        assert!(
            ProfileBody::decode(&over_wire).is_none(),
            "a frame one byte over the cap must be refused"
        );
    }

    #[test]
    fn frame_profile_body_refuses_an_over_cap_body_and_builds_an_at_cap_one() {
        assert!(frame_profile_body(&sample_body(MAX_PROFILE_BODY_BYTES + 1)).is_none());
        let framed = frame_profile_body(&sample_body(MAX_PROFILE_BODY_BYTES))
            .expect("an at-cap body frames");
        assert_eq!(framed.data.len(), MAX_PROFILE_BODY_FRAME_BYTES);
    }

    #[test]
    fn framing_sets_the_right_opcode_and_no_correlation_id() {
        let r = sample_ref();

        let announce = frame_profile_root_announce(&r);
        assert_eq!(announce.msg_type, PROFILE_ROOT_ANNOUNCE);
        assert_eq!(announce.id, None);
        assert_eq!(announce.data.len(), ENCODED_LEN);

        let request = frame_profile_body_request(&r);
        assert_eq!(request.msg_type, PROFILE_BODY_REQUEST);
        assert_eq!(request.id, None);
        assert_eq!(request.data.len(), ENCODED_LEN);

        let body = frame_profile_body(&sample_body(16)).expect("a small body frames");
        assert_eq!(body.msg_type, PROFILE_BODY);
        assert_eq!(body.id, None);
    }

    /// The payload lifters are opcode-scoped: each accepts only its own opcode, so a 223 payload
    /// can never be lifted out of a 224 frame (or vice versa) despite the identical layout.
    #[test]
    fn payload_lifters_are_opcode_scoped() {
        let r = sample_ref();
        let announce = frame_profile_root_announce(&r);
        let request = frame_profile_body_request(&r);
        let body = frame_profile_body(&sample_body(8)).expect("frames");

        assert_eq!(profile_root_announce_payload(&announce), Some(r));
        assert_eq!(profile_root_announce_payload(&request), None);
        assert_eq!(profile_body_request_payload(&request), Some(r));
        assert_eq!(profile_body_request_payload(&announce), None);
        assert!(profile_body_payload(&body).is_some());
        assert!(profile_body_payload(&announce).is_none());
    }

    /// 223 floods to everyone at Bulk priority; 224 and 225 are directed, so neither may be
    /// classified as a broadcast — a profile body sent to every peer instead of the one that
    /// asked for it would be a 1 MiB amplification.
    #[test]
    fn announce_floods_and_the_directed_pair_does_not() {
        use crate::gossip::broadcaster::{classify_broadcast, BroadcastStrategy};
        use crate::gossip::priority::MessagePriority;

        assert_eq!(
            classify_broadcast(PROFILE_ROOT_ANNOUNCE, false),
            BroadcastStrategy::Plumtree
        );
        assert_eq!(
            classify_broadcast(PROFILE_BODY_REQUEST, false),
            BroadcastStrategy::Unicast
        );
        assert_eq!(
            classify_broadcast(PROFILE_BODY, false),
            BroadcastStrategy::Unicast
        );

        // Only the raw-opcode path can classify the DIG band: upstream `ProtocolMessageTypes` is
        // a closed enum with no variant for these opcodes.
        assert_eq!(
            MessagePriority::from_dig_type(PROFILE_ROOT_ANNOUNCE),
            MessagePriority::Bulk
        );
        // A directed body request is a user waiting on an answer — it must NOT be demoted to the
        // bulk lane behind the flood traffic.
        assert_eq!(
            MessagePriority::from_dig_type(PROFILE_BODY_REQUEST),
            MessagePriority::Normal
        );
    }

    /// 223 is UNSIGNED by design: its payload is exactly the two hashes and nothing else, so
    /// there is no field a receiver could demand a signature in. Pinning `ENCODED_LEN == 64`
    /// against the announce frame is what makes "a signature was quietly appended" fail here.
    #[test]
    fn announce_carries_no_signature_field() {
        let announce = frame_profile_root_announce(&sample_ref());
        assert_eq!(
            announce.data.len(),
            ENCODED_LEN,
            "a 223 announce is exactly store_id ‖ root — no signature, no room for one"
        );
    }
}
