//! store-melted broadcast wire message — opcode 221 (`STORE_MELTED`).
//!
//! # What this is
//!
//! When a dig-store's on-chain coin is melted (the store-lifecycle "delete"), the
//! melting node floods a `store-melted` announcement so every peer stops hosting the
//! store's `.dig` content and reclaims disk. This module defines that wire message:
//! the opcode constant, the [`StoreMeltedAnnounce`] payload with byte-exact encode/
//! decode, the sign/verify helpers, and the [`Message`] framing. It is piece #1 of
//! epic #1316 (store-melt propagation) — the wire dig-node consumes to build the
//! receive → on-chain-verify → delete → rebroadcast handler (#3).
//!
//! # It is a PUBLIC broadcast — §5.4-EXEMPT (NOT recipient-sealed)
//!
//! A store deletion is public-by-nature and addressed to *everyone*, exactly like L2
//! consensus gossip (blocks/txs/attestations). So `store-melted` is **mTLS-authenticated
//! + signed**, NOT end-to-end recipient-sealed — it carries no recipient-specific
//! content, so §5.4's "every directed message is e2e-encrypted to the recipient" does
//! not apply (same carve-out the normative contract grants public all-peers broadcasts).
//! A future reviewer should read this as a deliberate, documented exemption, not a gap.
//!
//! # The signature is attribution/anti-spam, NOT load-bearing
//!
//! The signature attributes an announcement to a peer identity and lets peers rate-limit
//! spam. It is **not** the authority to delete anyone's data — that authority is the
//! on-chain melt proof, which the receiver (dig-node #3) checks via the singleton-lineage
//! walk before deleting anything (NC-9, fail-closed). A forged or replayed `store-melted`
//! for a live store therefore deletes nothing: the on-chain check is the gate. `melt_height`
//! is likewise an ADVISORY hint (a starting point for the chain lookup), never trusted on
//! its face.
//!
//! # Wire layout
//!
//! A `store-melted` frame is a stock [`Message`](dig_peer_protocol::Message) with
//! `msg_type = 221` ([`STORE_MELTED`]) whose `data` is the fixed-length big-endian
//! encoding of [`StoreMeltedAnnounce`] (see [`StoreMeltedAnnounce::encode`]).
//!
//! # Routing
//!
//! `store-melted` is a **broadcast flood** (Plumtree eager/lazy push, like the other
//! announce messages) at **Bulk** priority — it is small and infrequent, never
//! consensus-critical. See [`classify_broadcast`](crate::gossip::broadcaster::classify_broadcast)
//! and [`MessagePriority`](crate::gossip::priority::MessagePriority).

use dig_peer_protocol::{Bytes, Bytes32, Message, ProtocolMessageTypes};
use dig_tls::bls::{sign_message, verify_signature, SecretKey};
use sha2::{Digest, Sha256};

/// Wire opcode for a `store-melted` broadcast.
///
/// Canonical value **221** — the second opcode of the 220-255 "free" band, after
/// [`DIG_MESSAGE`](crate::service::dig_message::DIG_MESSAGE)`= 220`. Mirrors
/// [`ProtocolMessageTypes::StoreMelted`]. This value is a cross-repo canonical
/// constant (dig-node pins it to decode the broadcast) — it MUST NOT drift.
pub const STORE_MELTED: u8 = ProtocolMessageTypes::StoreMelted as u8;

/// Domain-separation tag for the `store-melted` signature preimage.
///
/// Prefixed before the signed fields so a `store-melted` signature can never be
/// replayed as a signature over any other DIG message. Versioned (`:v1`) so a future
/// preimage change is an explicit, distinguishable domain rather than a silent break.
const SIG_DOMAIN_TAG: &[u8] = b"dig:store-melted:v1";

/// Fixed on-wire size of an encoded [`StoreMeltedAnnounce`], in bytes.
///
/// `store_id` (32) + `melt_height` (4, big-endian) + `sender_peer_id` (32) +
/// `signature` (96) = 164. The encoding is fixed-length, so decode rejects any frame
/// of a different size.
pub const ENCODED_LEN: usize = 32 + 4 + 32 + 96;

/// A signed announcement that a dig-store's on-chain coin has been melted.
///
/// Flooded to all peers so they stop hosting the store's `.dig` content. The receiver
/// MUST verify the melt on-chain before acting (NC-9) — this message is the trigger,
/// never the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreMeltedAnnounce {
    /// The melted store's id (the singleton launcher id the on-chain check resolves).
    pub store_id: Bytes32,
    /// Advisory hint: the block height at which the melt was observed. A starting point
    /// for the receiver's on-chain lookup — never trusted on its face.
    pub melt_height: u32,
    /// The announcing peer's `peer_id` (`SHA-256(TLS SPKI DER)`), for attribution/dedup.
    ///
    /// This is NOT the BLS verification key: [`verify`](Self::verify) takes the signer's
    /// 48-byte BLS G1 identity key separately (the receiver learns it from the peer's
    /// mTLS cert binding), because `peer_id` is a 32-byte hash, not a public key.
    pub sender_peer_id: Bytes32,
    /// BLS AugScheme (G2) signature over [`sig_preimage`], 96 bytes compressed.
    pub signature: [u8; 96],
}

/// The 32-byte SHA-256 digest that a `store-melted` signature is computed over.
///
/// `SHA-256(SIG_DOMAIN_TAG ‖ store_id ‖ melt_height_be)` where `melt_height_be` is the
/// big-endian 4-byte encoding of `melt_height`. Both signer and verifier derive the
/// preimage the same way so the signature binds exactly the store id and height.
#[must_use]
pub fn sig_preimage(store_id: Bytes32, melt_height: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SIG_DOMAIN_TAG);
    hasher.update(store_id.as_ref());
    hasher.update(melt_height.to_be_bytes());
    hasher.finalize().into()
}

/// Sign the `store-melted` preimage for `(store_id, melt_height)` with an identity key.
///
/// Returns the 96-byte compressed BLS AugScheme signature — the originator (dig-node,
/// after its melt spend) puts this in [`StoreMeltedAnnounce::signature`]. Uses the
/// crate's existing `dig_tls::bls` primitive; no new cryptography is introduced.
#[must_use]
pub fn sign(sk: &SecretKey, store_id: Bytes32, melt_height: u32) -> [u8; 96] {
    sign_message(sk, &sig_preimage(store_id, melt_height))
}

impl StoreMeltedAnnounce {
    /// Build a signed announcement in one step.
    ///
    /// Convenience for the originator: derives the signature over `(store_id,
    /// melt_height)` and assembles the struct.
    #[must_use]
    pub fn new_signed(
        sk: &SecretKey,
        store_id: Bytes32,
        melt_height: u32,
        sender_peer_id: Bytes32,
    ) -> Self {
        Self {
            store_id,
            melt_height,
            sender_peer_id,
            signature: sign(sk, store_id, melt_height),
        }
    }

    /// Verify the signature against the signer's 48-byte BLS G1 identity key.
    ///
    /// Recomputes the preimage from this announcement's `store_id` and `melt_height`
    /// and checks [`signature`](Self::signature). Returns `false` on any malformed
    /// key/signature or a non-verifying signature (fail-closed). The caller supplies
    /// `signer_pk_g1` from the peer's mTLS cert binding — it is NOT carried in the
    /// message (`sender_peer_id` is a hash, not a key).
    ///
    /// A `true` result attributes the announcement to `signer_pk_g1`; it is NOT
    /// authority to delete data — the on-chain melt check (NC-9) is that gate.
    #[must_use]
    pub fn verify(&self, signer_pk_g1: &[u8; 48]) -> bool {
        verify_signature(
            signer_pk_g1,
            &sig_preimage(self.store_id, self.melt_height),
            &self.signature,
        )
    }

    /// Encode to the fixed-length ([`ENCODED_LEN`]) big-endian wire bytes.
    ///
    /// Layout: `store_id[32] ‖ melt_height_be[4] ‖ sender_peer_id[32] ‖ signature[96]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ENCODED_LEN);
        buf.extend_from_slice(self.store_id.as_ref());
        buf.extend_from_slice(&self.melt_height.to_be_bytes());
        buf.extend_from_slice(self.sender_peer_id.as_ref());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Decode from the fixed-length wire bytes produced by [`encode`](Self::encode).
    ///
    /// Returns `None` unless `bytes` is exactly [`ENCODED_LEN`] long — a truncated,
    /// padded, or otherwise malformed frame is rejected, never panics.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ENCODED_LEN {
            return None;
        }
        let store_id = Bytes32::from(<[u8; 32]>::try_from(&bytes[0..32]).ok()?);
        let melt_height = u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[32..36]).ok()?);
        let sender_peer_id = Bytes32::from(<[u8; 32]>::try_from(&bytes[36..68]).ok()?);
        let signature = <[u8; 96]>::try_from(&bytes[68..164]).ok()?;
        Some(Self {
            store_id,
            melt_height,
            sender_peer_id,
            signature,
        })
    }
}

/// True iff `msg_type` is the `store-melted` opcode ([`STORE_MELTED`]).
///
/// Inbound dispatch calls this on `Message.msg_type as u8` to route opcode-221
/// frames to the store-melted handler seam (dig-node #3).
#[must_use]
pub fn is_store_melted(msg_type: u8) -> bool {
    msg_type == STORE_MELTED
}

/// Lift and decode a [`StoreMeltedAnnounce`] from an inbound [`Message`].
///
/// Returns `Some(announce)` iff `msg` is an opcode-221 frame whose `data` decodes
/// ([`StoreMeltedAnnounce::decode`]), else `None`.
#[must_use]
pub fn store_melted_payload(msg: &Message) -> Option<StoreMeltedAnnounce> {
    if is_store_melted(msg.msg_type as u8) {
        StoreMeltedAnnounce::decode(msg.data.as_ref())
    } else {
        None
    }
}

/// Build the outbound opcode-221 [`Message`] that floods `announce` to peers.
///
/// `id` is `None`: a `store-melted` broadcast is fire-and-forget, not a correlated
/// request/response. The caller broadcasts the returned message through
/// [`GossipHandle::broadcast`](crate::service::gossip_handle::GossipHandle).
#[must_use]
pub fn frame_store_melted(announce: &StoreMeltedAnnounce) -> Message {
    Message {
        msg_type: ProtocolMessageTypes::StoreMelted,
        id: None,
        data: Bytes::new(announce.encode()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic test identity key derived from a label — never a hard-coded
    /// literal, so a second implementation reproduces the same vector and CodeQL does
    /// not flag a hard-coded cryptographic value.
    fn identity_sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        SecretKey::from_seed(&seed)
    }

    /// A deterministic 32-byte fixture derived from a label (store id / peer id).
    fn bytes32(label: &str) -> Bytes32 {
        Bytes32::from(<[u8; 32]>::from(Sha256::digest(label.as_bytes())))
    }

    fn sample() -> StoreMeltedAnnounce {
        let sk = identity_sk("store-melted/signer");
        StoreMeltedAnnounce::new_signed(
            &sk,
            bytes32("store-melted/store"),
            123_456,
            bytes32("store-melted/peer"),
        )
    }

    #[test]
    fn opcode_is_221() {
        assert_eq!(STORE_MELTED, 221);
        assert!(is_store_melted(221));
        assert!(!is_store_melted(220));
    }

    #[test]
    fn encode_has_fixed_length() {
        assert_eq!(sample().encode().len(), ENCODED_LEN);
        assert_eq!(ENCODED_LEN, 164);
    }

    #[test]
    fn encode_decode_round_trips_byte_identically() {
        let announce = sample();
        let bytes = announce.encode();
        let decoded = StoreMeltedAnnounce::decode(&bytes).expect("decode");
        assert_eq!(decoded, announce);
        // Re-encoding the decoded value yields identical bytes (byte-identity).
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let mut bytes = sample().encode();
        assert!(StoreMeltedAnnounce::decode(&bytes[..bytes.len() - 1]).is_none());
        bytes.push(0);
        assert!(StoreMeltedAnnounce::decode(&bytes).is_none());
        assert!(StoreMeltedAnnounce::decode(&[]).is_none());
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let sk = identity_sk("store-melted/rt");
        let pk = dig_tls::bls::public_key_bytes(&sk);
        let announce =
            StoreMeltedAnnounce::new_signed(&sk, bytes32("rt/store"), 42, bytes32("rt/peer"));
        assert!(announce.verify(&pk));
    }

    #[test]
    fn verify_rejects_wrong_signer_key() {
        let sk = identity_sk("store-melted/signer");
        let other = dig_tls::bls::public_key_bytes(&identity_sk("store-melted/other"));
        let announce =
            StoreMeltedAnnounce::new_signed(&sk, bytes32("wk/store"), 7, bytes32("wk/peer"));
        assert!(!announce.verify(&other));
    }

    #[test]
    fn verify_rejects_tampered_fields() {
        let sk = identity_sk("store-melted/tamper");
        let pk = dig_tls::bls::public_key_bytes(&sk);
        let mut announce = StoreMeltedAnnounce::new_signed(
            &sk,
            bytes32("tamper/store"),
            10,
            bytes32("tamper/peer"),
        );
        // Flipping the signed height invalidates the signature.
        announce.melt_height = 11;
        assert!(!announce.verify(&pk));
    }

    #[test]
    fn verify_rejects_malformed_signature() {
        let sk = identity_sk("store-melted/malformed");
        let pk = dig_tls::bls::public_key_bytes(&sk);
        let mut announce = sample();
        announce.signature = [0xFF; 96];
        // A garbage (non-canonical) signature fails, never panics.
        assert!(!announce.verify(&pk));
        let _ = sk;
    }

    #[test]
    fn frame_and_lift_round_trip() {
        let announce = sample();
        let msg = frame_store_melted(&announce);
        assert_eq!(msg.msg_type as u8, STORE_MELTED);
        assert_eq!(msg.id, None);
        assert_eq!(store_melted_payload(&msg), Some(announce));
    }

    #[test]
    fn payload_ignores_other_opcodes() {
        let msg = crate::service::dig_message::frame_envelope(&[1, 2, 3], None);
        assert!(store_melted_payload(&msg).is_none());
    }

    #[test]
    fn routed_as_bulk_flood_broadcast() {
        use crate::gossip::broadcaster::{classify_broadcast, BroadcastStrategy};
        use crate::gossip::priority::MessagePriority;

        // Public all-peers flood at bulk priority — never unicast, never consensus-critical.
        assert_eq!(
            classify_broadcast(ProtocolMessageTypes::StoreMelted, false),
            BroadcastStrategy::Plumtree
        );
        assert_eq!(
            MessagePriority::from_chia_type(ProtocolMessageTypes::StoreMelted),
            MessagePriority::Bulk
        );
        // The u8 path agrees with the enum path so both classifications route identically.
        assert_eq!(
            MessagePriority::from_dig_type(STORE_MELTED),
            MessagePriority::Bulk
        );
    }

    #[test]
    fn preimage_is_domain_separated_and_height_sensitive() {
        let store = bytes32("preimage/store");
        assert_ne!(sig_preimage(store, 1), sig_preimage(store, 2));
        assert_ne!(sig_preimage(store, 1), sig_preimage(bytes32("other"), 1));
    }
}
