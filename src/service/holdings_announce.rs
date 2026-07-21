//! holdings-announce broadcast wire message — opcode 222 (`HOLDINGS_ANNOUNCE`).
//!
//! # What this is
//!
//! A provider (a dig-node hosting `.dig` content) periodically floods a signed
//! *holdings announcement*: a batch of add/remove deltas telling every peer which
//! content keys it now serves, and at which addresses. dig-node verifies each
//! announcement (see [`verify_holdings_announce`]) before feeding the deltas into
//! dig-dht's holder set, so a malicious peer cannot forge holdings or poison the DHT.
//! This module is the decider-locked wire (spec #1394, epic #1428): the opcode
//! constant, the [`HoldingsAnnounce`] payload with byte-exact encode/decode, the
//! domain-separated digest, the pluggable [`HoldingsSigner`] / [`HoldingsVerifier`]
//! abstractions, the fail-closed [`verify_holdings_announce`] gate, and the framing.
//!
//! # It is a PUBLIC broadcast — §5.4-EXEMPT (NOT recipient-sealed)
//!
//! A holdings announcement is public discovery data, addressed to *everyone* (exactly
//! like L2 consensus gossip: blocks/txs/attestations). It is **mTLS-authenticated +
//! signed**, NOT end-to-end recipient-sealed — it carries no recipient-specific
//! content, so §5.4's "every directed message is e2e-encrypted to the recipient" does
//! not apply. This is the same deliberate carve-out the normative contract (NC-1)
//! grants public all-peers broadcasts, not a gap.
//!
//! # The signature is the DHT-poisoning gate
//!
//! Unlike a store-melt (whose authority is an on-chain proof), a holdings announcement's
//! signature IS load-bearing: it binds the batch of `(content_key, addresses)` deltas to
//! the provider identity so no third party can advertise content on the provider's
//! behalf or point resolvers at attacker-controlled addresses. [`verify_holdings_announce`]
//! therefore checks the signature over the exact digest, the `SHA-256(pubkey) == peer_id`
//! binding, and the change-count cap — fail-closed on any mismatch.
//!
//! # Pluggable signer (unblocked from dig-tls #1422)
//!
//! Signing is abstracted behind [`HoldingsSigner`] so this wire does not block on the
//! holder-TLS-key export hook (#1422). The v1 pinned signature scheme is BLS-G1 (the
//! node's non-fund-moving identity key — the same primitive `store_melted` uses),
//! provided by [`BlsHoldingsSigner`] / [`BlsHoldingsVerifier`]; the eventual TLS-key
//! signer plugs in via the same trait without any wire change. `provider_pubkey` is the
//! signer's published key material and `provider_peer_id == hex(SHA-256(provider_pubkey))`
//! regardless of key type.

use dig_peer_protocol::{Bytes, Message, ProtocolMessageTypes};
use dig_tls::bls::{public_key_bytes, sign_message, verify_signature, SecretKey};
use sha2::{Digest, Sha256};

/// Wire opcode for a `holdings-announce` broadcast.
///
/// Canonical value **222** — the third opcode of the 220-255 "free" band, after
/// [`DIG_MESSAGE`](crate::service::dig_message::DIG_MESSAGE)`= 220` and
/// [`STORE_MELTED`](crate::service::store_melted::STORE_MELTED)`= 221`. Mirrors
/// [`ProtocolMessageTypes::HoldingsAnnounce`]. This value is a cross-repo canonical
/// constant (dig-node pins it to decode the broadcast) — it MUST NOT drift.
pub const HOLDINGS_ANNOUNCE: u8 = ProtocolMessageTypes::HoldingsAnnounce as u8;

/// Domain-separation tag for the `holdings-announce` signature preimage.
///
/// Prefixed before the signed fields so a holdings signature can never be replayed as a
/// signature over any other DIG message. Versioned (`:v1`) so a future preimage change
/// is an explicit, distinguishable domain rather than a silent break. This exact byte
/// string is a cross-repo canonical contract — dig-node's verify recomputes it.
pub const SIG_DOMAIN_TAG: &[u8] = b"dig:holdings:v1";

/// Maximum number of [`HoldingsDelta`] entries a single announcement may carry.
///
/// Bounds the signed batch so one frame cannot be used to flood a peer's DHT ingest or
/// force unbounded work in [`verify_holdings_announce`]. Both the builder
/// ([`HoldingsAnnounce::new_signed`]) and the verifier reject a batch larger than this.
pub const MAX_CHANGES: usize = 256;

/// Length of a hex-encoded `provider_peer_id` (32 bytes → 64 hex chars).
const PEER_ID_HEX_LEN: usize = 64;

/// The kind-tag byte prefixing an [`HoldingsDelta::Add`] in the canonical encoding.
const KIND_ADD: u8 = 0x01;
/// The kind-tag byte prefixing an [`HoldingsDelta::Remove`] in the canonical encoding.
const KIND_REMOVE: u8 = 0x02;

/// A network address at which a provider serves a content key.
///
/// `host` is an IP literal or hostname (IPv6-first per §5.2; a v6 literal fits the
/// string) and `port` the P2P/serve port. Addresses are carried inside the signed digest
/// (see [`canonical_encode`]) so a peer cannot rewrite where a resolver is pointed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateAddr {
    /// IP literal or hostname (IPv6-first).
    pub host: String,
    /// P2P/serve port.
    pub port: u16,
}

/// One holdings change: start serving a content key, or stop serving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldingsDelta {
    /// The provider now serves `content_key` at `addresses` until `expires_at`.
    Add {
        /// The 32-byte content key now served.
        content_key: [u8; 32],
        /// Where the provider serves it (signed — see [`canonical_encode`]).
        addresses: Vec<CandidateAddr>,
        /// Unix-seconds expiry after which the advertisement is stale.
        expires_at: u64,
    },
    /// The provider no longer serves `content_key`.
    Remove {
        /// The 32-byte content key no longer served.
        content_key: [u8; 32],
    },
}

/// A signed, batched announcement of the content a provider holds.
///
/// Flooded to all peers; each receiver MUST [`verify_holdings_announce`] before feeding
/// the deltas into its DHT holder set. See the module docs for the §5.4 exemption and the
/// signature's role as the DHT-poisoning gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldingsAnnounce {
    /// The provider's `peer_id` as 64 lowercase hex chars (`SHA-256(provider_pubkey)`).
    pub provider_peer_id: String,
    /// The provider's published key material (holder TLS SPKI DER, or the v1 BLS-G1
    /// identity key). Invariant: `SHA-256(provider_pubkey) == provider_peer_id` (32 bytes).
    pub provider_pubkey: Vec<u8>,
    /// Monotonic sequence number — a later announcement supersedes an earlier one.
    pub seq: u64,
    /// Unix-seconds timestamp the announcement was produced.
    pub announced_at: u64,
    /// The batch of add/remove deltas (at most [`MAX_CHANGES`]).
    pub changes: Vec<HoldingsDelta>,
    /// The provider's signature over [`digest`](Self::digest).
    pub signature: Vec<u8>,
}

/// Why building or verifying a [`HoldingsAnnounce`] failed. Fail-closed — every variant
/// means the announcement is rejected and its deltas are NOT ingested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldingsError {
    /// The batch carried more than [`MAX_CHANGES`] deltas.
    TooManyChanges {
        /// The rejected count.
        count: usize,
    },
    /// `provider_peer_id` was not 64 lowercase hex characters.
    BadPeerIdHex,
    /// `SHA-256(provider_pubkey)` did not equal `provider_peer_id`.
    PeerIdMismatch,
    /// The signature did not verify over the digest (or was malformed).
    InvalidSignature,
}

impl std::fmt::Display for HoldingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyChanges { count } => {
                write!(
                    f,
                    "holdings announce has {count} changes (max {MAX_CHANGES})"
                )
            }
            Self::BadPeerIdHex => write!(f, "provider_peer_id is not 64 hex chars"),
            Self::PeerIdMismatch => write!(f, "SHA-256(provider_pubkey) != provider_peer_id"),
            Self::InvalidSignature => write!(f, "holdings announce signature did not verify"),
        }
    }
}

impl std::error::Error for HoldingsError {}

/// Signs a `holdings-announce` digest with a provider identity key.
///
/// Abstracted so the wire does not depend on the dig-tls holder-key export hook (#1422):
/// the v1 scheme is [`BlsHoldingsSigner`] today; a TLS-key signer plugs in later via this
/// same trait. [`public_key`](Self::public_key) returns the material carried in
/// [`HoldingsAnnounce::provider_pubkey`], whose SHA-256 is the `provider_peer_id`.
pub trait HoldingsSigner {
    /// Sign the 32-byte announcement digest, returning the raw signature bytes.
    fn sign(&self, digest: &[u8; 32]) -> Vec<u8>;
    /// The signer's published public key material.
    fn public_key(&self) -> Vec<u8>;
}

/// Verifies a `holdings-announce` signature. The companion of [`HoldingsSigner`]; the
/// scheme MUST match the signer that produced the signature.
pub trait HoldingsVerifier {
    /// Return `true` iff `signature` is a valid signature by `public_key` over `digest`.
    /// MUST be fail-closed: any malformed key/signature returns `false`, never panics.
    fn verify(&self, public_key: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool;
}

/// The v1 pinned signer: a BLS-G1 identity key (the node's non-fund-moving key).
///
/// Produces a 96-byte AugScheme signature and publishes the 48-byte compressed G1 key as
/// `provider_pubkey`. Uses the crate's existing `dig_tls::bls` primitive; no new
/// cryptography is introduced.
pub struct BlsHoldingsSigner {
    sk: SecretKey,
}

impl BlsHoldingsSigner {
    /// Wrap a BLS secret key as a holdings signer.
    #[must_use]
    pub fn new(sk: SecretKey) -> Self {
        Self { sk }
    }
}

impl HoldingsSigner for BlsHoldingsSigner {
    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        sign_message(&self.sk, digest).to_vec()
    }

    fn public_key(&self) -> Vec<u8> {
        public_key_bytes(&self.sk).to_vec()
    }
}

/// The v1 pinned verifier: BLS-G1 AugScheme (companion of [`BlsHoldingsSigner`]).
///
/// The default verifier used by [`verify_holdings_announce`].
#[derive(Debug, Clone, Copy, Default)]
pub struct BlsHoldingsVerifier;

impl HoldingsVerifier for BlsHoldingsVerifier {
    fn verify(&self, public_key: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool {
        let Ok(pk) = <[u8; 48]>::try_from(public_key) else {
            return false;
        };
        let Ok(sig) = <[u8; 96]>::try_from(signature) else {
            return false;
        };
        verify_signature(&pk, digest, &sig)
    }
}

/// Encode the signed portion of a delta batch — the bytes hashed into the digest.
///
/// Per delta: a kind-tag byte ([`KIND_ADD`]/[`KIND_REMOVE`]), the 32-byte `content_key`,
/// and — for `Add` — the `addresses` and `expires_at` (so addresses are signed, not just
/// carried). Layout, all integers big-endian:
///
/// - `Add`: `0x01 ‖ content_key[32] ‖ addr_count(u16) ‖ (host_len(u16) ‖ host ‖ port(u16))* ‖ expires_at(u64)`
/// - `Remove`: `0x02 ‖ content_key[32]`
///
/// This exact layout is a cross-repo canonical contract — dig-node recomputes it to
/// verify. It is deterministic (no maps/sets), so signer and verifier agree byte-for-byte.
#[must_use]
pub fn canonical_encode(changes: &[HoldingsDelta]) -> Vec<u8> {
    let mut buf = Vec::new();
    for delta in changes {
        match delta {
            HoldingsDelta::Add {
                content_key,
                addresses,
                expires_at,
            } => {
                buf.push(KIND_ADD);
                buf.extend_from_slice(content_key);
                // addr_count fits u16: the batch is capped at MAX_CHANGES deltas and a
                // real advertisement lists a handful of addresses.
                buf.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
                for addr in addresses {
                    let host = addr.host.as_bytes();
                    buf.extend_from_slice(&(host.len() as u16).to_be_bytes());
                    buf.extend_from_slice(host);
                    buf.extend_from_slice(&addr.port.to_be_bytes());
                }
                buf.extend_from_slice(&expires_at.to_be_bytes());
            }
            HoldingsDelta::Remove { content_key } => {
                buf.push(KIND_REMOVE);
                buf.extend_from_slice(content_key);
            }
        }
    }
    buf
}

/// The 32-byte digest a `holdings-announce` signature is computed over.
///
/// `SHA-256( SIG_DOMAIN_TAG ‖ provider_peer_id(32B) ‖ seq_be ‖ announced_at_be ‖ canonical_encode(changes) )`,
/// all `u64`s big-endian. Both signer and verifier derive it identically so the signature
/// binds the peer id, sequence, timestamp, and every delta (including Add addresses).
#[must_use]
pub fn digest(
    provider_peer_id: &[u8; 32],
    seq: u64,
    announced_at: u64,
    changes: &[HoldingsDelta],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SIG_DOMAIN_TAG);
    hasher.update(provider_peer_id);
    hasher.update(seq.to_be_bytes());
    hasher.update(announced_at.to_be_bytes());
    hasher.update(canonical_encode(changes));
    hasher.finalize().into()
}

/// Lowercase-hex encode a 32-byte peer id.
fn peer_id_hex(peer_id: &[u8; 32]) -> String {
    hex::encode(peer_id)
}

/// Decode a 64-char lowercase-hex `provider_peer_id` string to its 32 bytes.
fn decode_peer_id(hex_id: &str) -> Result<[u8; 32], HoldingsError> {
    if hex_id.len() != PEER_ID_HEX_LEN {
        return Err(HoldingsError::BadPeerIdHex);
    }
    let bytes = hex::decode(hex_id).map_err(|_| HoldingsError::BadPeerIdHex)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| HoldingsError::BadPeerIdHex)
}

impl HoldingsAnnounce {
    /// Build a signed announcement from a batch of changes.
    ///
    /// Derives `provider_pubkey` and `provider_peer_id` from `signer`, computes the digest
    /// over `(peer_id, seq, announced_at, changes)`, and signs it.
    ///
    /// # Errors
    ///
    /// [`HoldingsError::TooManyChanges`] if `changes.len() > `[`MAX_CHANGES`] — the batch
    /// is refused rather than truncated, so a caller cannot silently drop deltas.
    pub fn new_signed<S: HoldingsSigner + ?Sized>(
        signer: &S,
        seq: u64,
        announced_at: u64,
        changes: Vec<HoldingsDelta>,
    ) -> Result<Self, HoldingsError> {
        if changes.len() > MAX_CHANGES {
            return Err(HoldingsError::TooManyChanges {
                count: changes.len(),
            });
        }
        let provider_pubkey = signer.public_key();
        let peer_id: [u8; 32] = Sha256::digest(&provider_pubkey).into();
        let signature = signer.sign(&digest(&peer_id, seq, announced_at, &changes));
        Ok(Self {
            provider_peer_id: peer_id_hex(&peer_id),
            provider_pubkey,
            seq,
            announced_at,
            changes,
            signature,
        })
    }

    /// The digest this announcement's signature must cover.
    ///
    /// # Errors
    ///
    /// [`HoldingsError::BadPeerIdHex`] if `provider_peer_id` is not 64 hex chars.
    pub fn digest(&self) -> Result<[u8; 32], HoldingsError> {
        let peer_id = decode_peer_id(&self.provider_peer_id)?;
        Ok(digest(&peer_id, self.seq, self.announced_at, &self.changes))
    }
}

/// Verify an announcement with the default v1 verifier ([`BlsHoldingsVerifier`]).
///
/// The gate dig-node calls before dig-dht ingest. Checks, fail-closed: (1) the change
/// count is `<= `[`MAX_CHANGES`], (2) `SHA-256(provider_pubkey) == provider_peer_id`, and
/// (3) the signature verifies over [`digest`](HoldingsAnnounce::digest). Any mismatch
/// returns `Err` and the deltas MUST NOT be ingested.
///
/// # Errors
///
/// [`HoldingsError`] describing the first failing check.
pub fn verify_holdings_announce(announce: &HoldingsAnnounce) -> Result<(), HoldingsError> {
    verify_holdings_announce_with(announce, &BlsHoldingsVerifier)
}

/// Verify an announcement with an explicit [`HoldingsVerifier`] (pluggable scheme).
///
/// Same checks and fail-closed contract as [`verify_holdings_announce`]; used when the
/// signature scheme is not the v1 BLS default (e.g. a future holder-TLS-key signer).
///
/// # Errors
///
/// [`HoldingsError`] describing the first failing check.
pub fn verify_holdings_announce_with<V: HoldingsVerifier + ?Sized>(
    announce: &HoldingsAnnounce,
    verifier: &V,
) -> Result<(), HoldingsError> {
    if announce.changes.len() > MAX_CHANGES {
        return Err(HoldingsError::TooManyChanges {
            count: announce.changes.len(),
        });
    }
    let peer_id = decode_peer_id(&announce.provider_peer_id)?;
    let derived: [u8; 32] = Sha256::digest(&announce.provider_pubkey).into();
    if derived != peer_id {
        return Err(HoldingsError::PeerIdMismatch);
    }
    let digest = digest(
        &peer_id,
        announce.seq,
        announce.announced_at,
        &announce.changes,
    );
    if !verifier.verify(&announce.provider_pubkey, &digest, &announce.signature) {
        return Err(HoldingsError::InvalidSignature);
    }
    Ok(())
}

// ============================================================================
// Wire encoding
// ============================================================================

/// Append a length-prefixed (`u16` big-endian) byte string to `buf`.
fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Read a `u16`-length-prefixed byte string from `bytes` at `*pos`, advancing `*pos`.
fn take_bytes<'a>(bytes: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = u16::from_be_bytes(bytes.get(*pos..*pos + 2)?.try_into().ok()?) as usize;
    *pos += 2;
    let out = bytes.get(*pos..*pos + len)?;
    *pos += len;
    Some(out)
}

/// Read a big-endian `u16` at `*pos`, advancing `*pos`.
fn take_u16(bytes: &[u8], pos: &mut usize) -> Option<u16> {
    let v = u16::from_be_bytes(bytes.get(*pos..*pos + 2)?.try_into().ok()?);
    *pos += 2;
    Some(v)
}

/// Read a big-endian `u64` at `*pos`, advancing `*pos`.
fn take_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let v = u64::from_be_bytes(bytes.get(*pos..*pos + 8)?.try_into().ok()?);
    *pos += 8;
    Some(v)
}

/// Read a fixed 32-byte array at `*pos`, advancing `*pos`.
fn take_32(bytes: &[u8], pos: &mut usize) -> Option<[u8; 32]> {
    let v: [u8; 32] = bytes.get(*pos..*pos + 32)?.try_into().ok()?;
    *pos += 32;
    Some(v)
}

impl HoldingsAnnounce {
    /// Encode to the variable-length wire bytes.
    ///
    /// Layout, all integers big-endian: `peer_id(len-prefixed) ‖ pubkey(len-prefixed) ‖
    /// seq(u64) ‖ announced_at(u64) ‖ change_count(u16) ‖ canonical_encode(changes) ‖
    /// signature(len-prefixed)`. The changes are encoded identically to
    /// [`canonical_encode`] so the signed bytes and the wire bytes never diverge.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_bytes(&mut buf, self.provider_peer_id.as_bytes());
        put_bytes(&mut buf, &self.provider_pubkey);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.announced_at.to_be_bytes());
        buf.extend_from_slice(&(self.changes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&canonical_encode(&self.changes));
        put_bytes(&mut buf, &self.signature);
        buf
    }

    /// Decode from the wire bytes produced by [`encode`](Self::encode).
    ///
    /// Returns `None` on any truncated/malformed frame — never panics. Rejects a
    /// change-count over [`MAX_CHANGES`] and any trailing bytes.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0usize;
        let provider_peer_id = String::from_utf8(take_bytes(bytes, &mut pos)?.to_vec()).ok()?;
        let provider_pubkey = take_bytes(bytes, &mut pos)?.to_vec();
        let seq = take_u64(bytes, &mut pos)?;
        let announced_at = take_u64(bytes, &mut pos)?;
        let change_count = take_u16(bytes, &mut pos)? as usize;
        if change_count > MAX_CHANGES {
            return None;
        }
        let mut changes = Vec::with_capacity(change_count);
        for _ in 0..change_count {
            changes.push(decode_delta(bytes, &mut pos)?);
        }
        let signature = take_bytes(bytes, &mut pos)?.to_vec();
        if pos != bytes.len() {
            return None; // trailing bytes — reject rather than silently ignore
        }
        Some(Self {
            provider_peer_id,
            provider_pubkey,
            seq,
            announced_at,
            changes,
            signature,
        })
    }
}

/// Decode one [`HoldingsDelta`] at `*pos`, advancing `*pos`. `None` on malformed input.
fn decode_delta(bytes: &[u8], pos: &mut usize) -> Option<HoldingsDelta> {
    let kind = *bytes.get(*pos)?;
    *pos += 1;
    let content_key = take_32(bytes, pos)?;
    match kind {
        KIND_ADD => {
            let addr_count = take_u16(bytes, pos)? as usize;
            let mut addresses = Vec::with_capacity(addr_count);
            for _ in 0..addr_count {
                let host = String::from_utf8(take_bytes(bytes, pos)?.to_vec()).ok()?;
                let port = take_u16(bytes, pos)?;
                addresses.push(CandidateAddr { host, port });
            }
            let expires_at = take_u64(bytes, pos)?;
            Some(HoldingsDelta::Add {
                content_key,
                addresses,
                expires_at,
            })
        }
        KIND_REMOVE => Some(HoldingsDelta::Remove { content_key }),
        _ => None,
    }
}

/// True iff `msg_type` is the `holdings-announce` opcode ([`HOLDINGS_ANNOUNCE`]).
#[must_use]
pub fn is_holdings_announce(msg_type: u8) -> bool {
    msg_type == HOLDINGS_ANNOUNCE
}

/// Lift and decode a [`HoldingsAnnounce`] from an inbound [`Message`].
///
/// Returns `Some(announce)` iff `msg` is an opcode-222 frame whose `data` decodes, else
/// `None`. The caller MUST still [`verify_holdings_announce`] before ingesting the deltas.
#[must_use]
pub fn holdings_announce_payload(msg: &Message) -> Option<HoldingsAnnounce> {
    if is_holdings_announce(msg.msg_type as u8) {
        HoldingsAnnounce::decode(msg.data.as_ref())
    } else {
        None
    }
}

/// Build the outbound opcode-222 [`Message`] that floods `announce` to peers.
///
/// `id` is `None`: a holdings announcement is a fire-and-forget flood broadcast, not a
/// correlated request/response.
#[must_use]
pub fn frame_holdings_announce(announce: &HoldingsAnnounce) -> Message {
    Message {
        msg_type: ProtocolMessageTypes::HoldingsAnnounce,
        id: None,
        data: Bytes::new(announce.encode()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic test identity key derived from a label — never a hard-coded
    /// literal, so a second implementation reproduces the same vector and CodeQL does not
    /// flag a hard-coded cryptographic value (see #917/#950).
    fn signer(label: &str) -> BlsHoldingsSigner {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        BlsHoldingsSigner::new(SecretKey::from_seed(&seed))
    }

    /// A deterministic 32-byte content key derived from a label.
    fn content_key(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    fn sample_changes() -> Vec<HoldingsDelta> {
        vec![
            HoldingsDelta::Add {
                content_key: content_key("holdings/ck-a"),
                addresses: vec![
                    CandidateAddr {
                        host: "2001:db8::1".to_string(),
                        port: 9256,
                    },
                    CandidateAddr {
                        host: "example.dig".to_string(),
                        port: 443,
                    },
                ],
                expires_at: 1_800_000_000,
            },
            HoldingsDelta::Remove {
                content_key: content_key("holdings/ck-b"),
            },
        ]
    }

    fn sample() -> HoldingsAnnounce {
        HoldingsAnnounce::new_signed(
            &signer("holdings/provider"),
            7,
            1_700_000_000,
            sample_changes(),
        )
        .expect("within MAX_CHANGES")
    }

    #[test]
    fn opcode_is_222() {
        assert_eq!(HOLDINGS_ANNOUNCE, 222);
        assert!(is_holdings_announce(222));
        assert!(!is_holdings_announce(221));
    }

    #[test]
    fn peer_id_binds_to_pubkey() {
        let a = sample();
        let derived: [u8; 32] = Sha256::digest(&a.provider_pubkey).into();
        assert_eq!(a.provider_peer_id, hex::encode(derived));
        assert_eq!(a.provider_peer_id.len(), 64);
    }

    #[test]
    fn encode_decode_round_trips_byte_identically() {
        let a = sample();
        let bytes = a.encode();
        let decoded = HoldingsAnnounce::decode(&bytes).expect("decode");
        assert_eq!(decoded, a);
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn decode_rejects_truncated_and_trailing() {
        let bytes = sample().encode();
        assert!(HoldingsAnnounce::decode(&bytes[..bytes.len() - 1]).is_none());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(HoldingsAnnounce::decode(&extra).is_none());
        assert!(HoldingsAnnounce::decode(&[]).is_none());
    }

    #[test]
    fn verify_accepts_valid() {
        assert_eq!(verify_holdings_announce(&sample()), Ok(()));
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let mut a = sample();
        a.signature = vec![0xFF; 96];
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_peer_id_not_hash_of_pubkey() {
        let mut a = sample();
        // A different (valid) pubkey whose hash no longer matches provider_peer_id.
        a.provider_pubkey = signer("holdings/other").public_key();
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::PeerIdMismatch)
        );
    }

    #[test]
    fn verify_rejects_tampered_address() {
        let mut a = sample();
        if let HoldingsDelta::Add { addresses, .. } = &mut a.changes[0] {
            addresses[0].port = 1; // an address is signed — tampering breaks the digest
        }
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_change() {
        let mut a = sample();
        if let HoldingsDelta::Add { expires_at, .. } = &mut a.changes[0] {
            *expires_at += 1;
        }
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_seq() {
        let mut a = sample();
        a.seq += 1;
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::InvalidSignature)
        );
    }

    #[test]
    fn build_and_verify_reject_over_max_changes() {
        let too_many: Vec<HoldingsDelta> = (0..=MAX_CHANGES)
            .map(|i| HoldingsDelta::Remove {
                content_key: content_key(&format!("ck-{i}")),
            })
            .collect();
        assert_eq!(too_many.len(), MAX_CHANGES + 1);
        assert_eq!(
            HoldingsAnnounce::new_signed(&signer("cap"), 1, 1, too_many.clone()),
            Err(HoldingsError::TooManyChanges {
                count: MAX_CHANGES + 1
            })
        );
        // A hand-built oversized struct is rejected by verify too (fail-closed).
        let mut a = sample();
        a.changes = too_many;
        assert!(matches!(
            verify_holdings_announce(&a),
            Err(HoldingsError::TooManyChanges { .. })
        ));
    }

    #[test]
    fn verify_rejects_bad_peer_id_hex() {
        let mut a = sample();
        a.provider_peer_id = "not-hex".to_string();
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::BadPeerIdHex)
        );
    }

    #[test]
    fn max_changes_batch_round_trips_and_verifies() {
        let changes: Vec<HoldingsDelta> = (0..MAX_CHANGES)
            .map(|i| HoldingsDelta::Remove {
                content_key: content_key(&format!("ck-{i}")),
            })
            .collect();
        let a = HoldingsAnnounce::new_signed(&signer("full"), 1, 2, changes).expect("at cap");
        assert_eq!(HoldingsAnnounce::decode(&a.encode()), Some(a.clone()));
        assert_eq!(verify_holdings_announce(&a), Ok(()));
    }

    #[test]
    fn frame_and_lift_round_trip() {
        let a = sample();
        let msg = frame_holdings_announce(&a);
        assert_eq!(msg.msg_type as u8, HOLDINGS_ANNOUNCE);
        assert_eq!(msg.id, None);
        assert_eq!(holdings_announce_payload(&msg), Some(a));
    }

    #[test]
    fn payload_ignores_other_opcodes() {
        let msg = crate::service::dig_message::frame_envelope(&[1, 2, 3], None);
        assert!(holdings_announce_payload(&msg).is_none());
    }

    #[test]
    fn routed_as_bulk_flood_broadcast() {
        use crate::gossip::broadcaster::{classify_broadcast, BroadcastStrategy};
        use crate::gossip::priority::MessagePriority;

        // Public all-peers flood at bulk priority — never unicast, never consensus-critical.
        assert_eq!(
            classify_broadcast(ProtocolMessageTypes::HoldingsAnnounce, false),
            BroadcastStrategy::Plumtree
        );
        assert_eq!(
            MessagePriority::from_chia_type(ProtocolMessageTypes::HoldingsAnnounce),
            MessagePriority::Bulk
        );
        assert_eq!(
            MessagePriority::from_dig_type(HOLDINGS_ANNOUNCE),
            MessagePriority::Bulk
        );
    }

    #[test]
    fn canonical_encode_is_kind_tagged_and_deterministic() {
        let changes = sample_changes();
        let a = canonical_encode(&changes);
        let b = canonical_encode(&changes);
        assert_eq!(a, b);
        assert_eq!(a[0], KIND_ADD);
        // The Remove delta's kind tag appears after the Add block.
        assert!(a.contains(&KIND_REMOVE));
    }

    // ---- KAT golden vectors (CI-fail-on-drift) --------------------------------
    //
    // Fixed inputs → fixed digest + fixed signature under the deterministic test key
    // `signer("kat/holder")`. Pinned on first run; any digest/encoding/scheme drift in
    // this cross-repo wire+crypto contract FAILS the build. To regenerate intentionally
    // (a deliberate v2), print the hex below and update both constants in the same commit.

    /// Deterministic KAT inputs: one Add (two addresses) + one Remove, fixed seq/time.
    fn kat_announce() -> HoldingsAnnounce {
        let changes = vec![
            HoldingsDelta::Add {
                content_key: [0x11; 32],
                addresses: vec![CandidateAddr {
                    host: "2001:db8::dig".to_string(),
                    port: 9256,
                }],
                expires_at: 0x0000_0000_5000_0000,
            },
            HoldingsDelta::Remove {
                content_key: [0x22; 32],
            },
        ];
        HoldingsAnnounce::new_signed(&signer("kat/holder"), 0x0102_0304, 0x0A0B_0C0D, changes)
            .expect("within cap")
    }

    #[test]
    fn kat_digest_is_pinned() {
        let a = kat_announce();
        // Pinned digest — recompute-and-compare guards the domain tag + byte layout.
        const KAT_DIGEST_HEX: &str =
            "89858fb24c708510786cf43308387d467dcd537c9373f7529a014c97f259180c";
        let got = hex::encode(a.digest().expect("hex peer id"));
        assert_eq!(got, KAT_DIGEST_HEX);
    }

    #[test]
    fn kat_signature_verifies_and_is_pinned() {
        let a = kat_announce();
        // The KAT must verify under the v1 BLS scheme.
        assert_eq!(verify_holdings_announce(&a), Ok(()));
        // Pinned signature (deterministic BLS AugScheme over the pinned digest).
        const KAT_SIG_HEX: &str = "a8aa90c16b6e55c9359ccab1b9201d9c1d75714e65ec32ee432a588b75b1694ea81328056c7aad7762a84c835347433c12dc33705baf52733f46ae5ba839edc355ba6985b963d4f1cd392d5732eeb97112614aff5e28cdb570fd596c81743f20";
        let got = hex::encode(&a.signature);
        assert_eq!(got, KAT_SIG_HEX);
    }
}
