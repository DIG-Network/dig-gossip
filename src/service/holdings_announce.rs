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
//! domain-separated signing message, the [`HoldingsSigner`] builder abstraction, the
//! fail-closed [`verify_holdings_announce`] gate, and the framing.
//!
//! # The leaf-key wire is sound standalone (decider-locked, #1428)
//!
//! An announcement carries the provider's **TLS leaf `SubjectPublicKeyInfo` DER**
//! ([`HoldingsAnnounce::provider_spki`]) and is signed by that leaf key (ECDSA-P256). The
//! SPKI is BOTH the thing the `peer_id` hashes (`peer_id = SHA-256(SPKI DER)`, the §5.2
//! identity) AND the key that verifies the signature. This is self-contained and
//! unforgeable standalone:
//!
//! - `peer_id ≡ SHA-256(provider_spki)`, verified on receive — the peer id is never trusted.
//! - Only the holder of the leaf **private** key can produce a valid ECDSA signature over
//!   the message, and that private key corresponds to exactly the `provider_spki` whose
//!   hash is the `peer_id`. No handshake, proof-of-possession, or CA chain is needed.
//!
//! This deliberately REPLACES the earlier BLS-G1 "inline cert + #1204 binding" draft, which
//! the decider found **forgeable**: because the DigNetwork CA key is public, an attacker
//! could graft a self-consistent BLS binding onto a *copied* victim SPKI and produce an
//! announce that verified under the victim's peer_id. Signing with the leaf key itself —
//! the key the peer_id already commits to — closes that gap: there is no separate binding
//! to graft, and possession of the leaf private key IS the authority.
//!
//! # It is a PUBLIC broadcast — §5.4-EXEMPT (NOT recipient-sealed)
//!
//! A holdings announcement is public discovery data, addressed to *everyone* (exactly
//! like L2 consensus gossip: blocks/txs/attestations) and flooded, never unicast to one
//! recipient. It is **mTLS-authenticated + signed**, NOT end-to-end recipient-sealed — it
//! carries no recipient-specific content, so §5.4's "every directed message is e2e-encrypted
//! to the recipient" does not apply. This is the same deliberate carve-out the normative
//! contract (NC-1) grants public all-peers broadcasts, not a gap.
//!
//! # The signature is the DHT-poisoning gate
//!
//! Unlike a store-melt (whose authority is an on-chain proof), a holdings announcement's
//! signature IS load-bearing: it binds the batch of `(content_key, addresses)` deltas to
//! the provider identity so no third party can advertise content on the provider's
//! behalf or point resolvers at attacker-controlled addresses. [`verify_holdings_announce`]
//! therefore checks the SPKI→peer_id binding, that the SPKI is a P-256 key, the ECDSA
//! signature over the exact message, and the change-count cap — fail-closed on any mismatch.

use dig_peer_protocol::{Bytes, Message, ProtocolMessageTypes};
use dig_tls::peer_id_from_tls_spki_der;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use sha2::{Digest, Sha256};
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY};
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo};

/// Wire opcode for a `holdings-announce` broadcast.
///
/// Canonical value **222** — the third opcode of the 220-255 "free" band, after
/// [`DIG_MESSAGE`](crate::service::dig_message::DIG_MESSAGE)`= 220` and
/// [`STORE_MELTED`](crate::service::store_melted::STORE_MELTED)`= 221`. Mirrors
/// [`ProtocolMessageTypes::HoldingsAnnounce`]. This value is a cross-repo canonical
/// constant (dig-node pins it to decode the broadcast) — it MUST NOT drift.
pub const HOLDINGS_ANNOUNCE: u8 = ProtocolMessageTypes::HoldingsAnnounce as u8;

/// Domain-separation tag for the `holdings-announce` signing message.
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
/// string) and `port` the P2P/serve port. Addresses are carried inside the signed message
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
/// the deltas into its DHT holder set. See the module docs for the leaf-key model, the
/// §5.4 exemption, and the signature's role as the DHT-poisoning gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldingsAnnounce {
    /// The provider's `peer_id` as 64 lowercase hex chars.
    ///
    /// Its value equals `SHA-256(provider_spki)` (the §5.2 peer_id). It is VERIFIED against
    /// [`provider_spki`](Self::provider_spki) on the receive path, never trusted — see
    /// [`verify_holdings_announce`].
    pub provider_peer_id: String,
    /// The provider's TLS leaf `SubjectPublicKeyInfo` DER (algorithm id + subjectPublicKey
    /// bit string).
    ///
    /// This is BOTH what `provider_peer_id` hashes AND the P-256 public key that verifies
    /// [`signature`](Self::signature). No full certificate and no binding extension are on
    /// the wire — the SPKI is the whole root of trust. A P-256 SPKI is ~91 bytes.
    pub provider_spki: Vec<u8>,
    /// Monotonic sequence number — a later announcement supersedes an earlier one.
    pub seq: u64,
    /// Unix-seconds timestamp the announcement was produced.
    pub announced_at: u64,
    /// The batch of add/remove deltas (at most [`MAX_CHANGES`]).
    pub changes: Vec<HoldingsDelta>,
    /// The provider's ECDSA-P256 (ASN.1 DER) signature over
    /// [`holdings_signing_message`], produced by the leaf private key whose SPKI is
    /// [`provider_spki`](Self::provider_spki). Variable length (~70-72 bytes).
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
    /// `provider_spki` could not be parsed as a P-256 `SubjectPublicKeyInfo`.
    BadSpki,
    /// `SHA-256(provider_spki)` did not equal `provider_peer_id`.
    PeerIdMismatch,
    /// The signature did not verify over the message (or was malformed).
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
            Self::BadSpki => {
                write!(
                    f,
                    "provider_spki is not a parseable P-256 SubjectPublicKeyInfo"
                )
            }
            Self::PeerIdMismatch => write!(f, "SHA-256(provider_spki) != provider_peer_id"),
            Self::InvalidSignature => write!(f, "holdings announce signature did not verify"),
        }
    }
}

impl std::error::Error for HoldingsError {}

/// Supplies the provider's leaf SPKI and an ECDSA-P256 signature to
/// [`HoldingsAnnounce::new_signed`].
///
/// The signing key is fixed by the wire (it must be the leaf key whose SPKI is carried and
/// whose hash is the peer_id), so this trait exposes the SPKI and a raw signer over the
/// message. The v1 concrete implementation is [`EcdsaHoldingsSigner`]; dig-node (#1429)
/// constructs one from its `NodeCert` — `spki_der()` from the cert and an
/// `EcdsaKeyPair::from_pkcs8` over the leaf private key
/// (`NodeCert`'s `rustls_private_key().secret_der()`).
pub trait HoldingsSigner {
    /// Sign the domain-separated signing message, returning the ECDSA-P256 ASN.1-DER sig.
    fn sign(&self, signing_message: &[u8]) -> Vec<u8>;
    /// The provider's TLS leaf `SubjectPublicKeyInfo` DER (carried as `provider_spki`).
    fn spki_der(&self) -> Vec<u8>;
}

/// The v1 signer: an ECDSA-P256 leaf key paired with its `SubjectPublicKeyInfo` DER.
///
/// Signs the `dig:holdings:v1` message with `key_pair` (ECDSA-P256, SHA-256, ASN.1 sig)
/// and carries `spki_der`, the very key that verifies it — so the `peer_id`
/// (`SHA-256(spki_der)`) commits to the signing key with no separate binding.
pub struct EcdsaHoldingsSigner {
    key_pair: ring::signature::EcdsaKeyPair,
    spki_der: Vec<u8>,
    rng: ring::rand::SystemRandom,
}

impl EcdsaHoldingsSigner {
    /// Wrap an ECDSA-P256 key pair and its leaf SPKI DER as a holdings signer.
    ///
    /// `spki_der` MUST be the `SubjectPublicKeyInfo` of `key_pair`'s public key (i.e. the
    /// leaf whose peer_id is `SHA-256(spki_der)`), or the resulting announcement will fail
    /// [`verify_holdings_announce`].
    #[must_use]
    pub fn new(key_pair: ring::signature::EcdsaKeyPair, spki_der: Vec<u8>) -> Self {
        Self {
            key_pair,
            spki_der,
            rng: ring::rand::SystemRandom::new(),
        }
    }
}

impl HoldingsSigner for EcdsaHoldingsSigner {
    fn sign(&self, signing_message: &[u8]) -> Vec<u8> {
        self.key_pair
            .sign(&self.rng, signing_message)
            .expect("ECDSA-P256 signing over an in-memory message does not fail")
            .as_ref()
            .to_vec()
    }

    fn spki_der(&self) -> Vec<u8> {
        self.spki_der.clone()
    }
}

/// Encode the signed portion of a delta batch — the bytes hashed into the signing message.
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

/// The domain-separated message a `holdings-announce` signature is computed over.
///
/// `SIG_DOMAIN_TAG ‖ provider_peer_id(32B) ‖ seq_be ‖ announced_at_be ‖ canonical_encode(changes)`,
/// all `u64`s big-endian. `provider_peer_id` here is the raw 32-byte peer id
/// (`SHA-256(SPKI DER)`). Both signer and verifier build it identically. The ECDSA-P256
/// signer/verifier hash this message internally (SHA-256) — it is signed/verified as the
/// full preimage, NOT pre-hashed to 32 bytes.
#[must_use]
pub fn holdings_signing_message(
    provider_peer_id: &[u8; 32],
    seq: u64,
    announced_at: u64,
    changes: &[HoldingsDelta],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(SIG_DOMAIN_TAG);
    msg.extend_from_slice(provider_peer_id);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(&announced_at.to_be_bytes());
    msg.extend_from_slice(&canonical_encode(changes));
    msg
}

/// The 32-byte SHA-256 fingerprint of [`holdings_signing_message`].
///
/// NOT what is signed (ECDSA hashes the message itself); it exists only as a stable,
/// compact KAT fingerprint of the signing-message byte layout, so a cross-repo drift in
/// the domain tag / `canonical_encode` / field order fails CI deterministically.
#[must_use]
pub fn signing_message_digest(
    provider_peer_id: &[u8; 32],
    seq: u64,
    announced_at: u64,
    changes: &[HoldingsDelta],
) -> [u8; 32] {
    Sha256::digest(holdings_signing_message(
        provider_peer_id,
        seq,
        announced_at,
        changes,
    ))
    .into()
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

/// Extract the raw P-256 EC point from a `provider_spki`, confirming it is an
/// `id-ecPublicKey` / `prime256v1` key. Returns the uncompressed point bytes
/// (`0x04 ‖ X ‖ Y`) that [`ECDSA_P256_SHA256_ASN1`] verifies against.
fn p256_point_from_spki(spki: &[u8]) -> Result<Vec<u8>, HoldingsError> {
    let (_, info) = SubjectPublicKeyInfo::from_der(spki).map_err(|_| HoldingsError::BadSpki)?;
    if info.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return Err(HoldingsError::BadSpki);
    }
    let curve = info
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .ok_or(HoldingsError::BadSpki)?;
    if curve != OID_EC_P256 {
        return Err(HoldingsError::BadSpki);
    }
    Ok(info.subject_public_key.data.to_vec())
}

impl HoldingsAnnounce {
    /// Build a signed announcement from a batch of changes.
    ///
    /// Takes the leaf SPKI from `signer`, derives `provider_peer_id` from it, builds the
    /// signing message over `(peer_id, seq, announced_at, changes)`, and signs it with the
    /// leaf key.
    ///
    /// # Errors
    ///
    /// [`HoldingsError::TooManyChanges`] if `changes.len() > `[`MAX_CHANGES`] — the batch is
    /// refused rather than truncated, so a caller cannot silently drop deltas.
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
        let provider_spki = signer.spki_der();
        let peer_id = *peer_id_from_tls_spki_der(&provider_spki).as_bytes();
        let message = holdings_signing_message(&peer_id, seq, announced_at, &changes);
        let signature = signer.sign(&message);
        Ok(Self {
            provider_peer_id: peer_id_hex(&peer_id),
            provider_spki,
            seq,
            announced_at,
            changes,
            signature,
        })
    }

    /// The SHA-256 fingerprint of this announcement's signing message (KAT/layout helper).
    ///
    /// # Errors
    ///
    /// [`HoldingsError::BadPeerIdHex`] if `provider_peer_id` is not 64 hex chars.
    pub fn signing_message_digest(&self) -> Result<[u8; 32], HoldingsError> {
        let peer_id = decode_peer_id(&self.provider_peer_id)?;
        Ok(signing_message_digest(
            &peer_id,
            self.seq,
            self.announced_at,
            &self.changes,
        ))
    }
}

/// Verify an announcement, fail-closed — the gate dig-node calls before dig-dht ingest.
///
/// The five checks, in order (the first failure is returned):
/// 1. `changes.len() <= `[`MAX_CHANGES`] — else [`HoldingsError::TooManyChanges`].
/// 2. `provider_peer_id` decodes as 64-hex → `[u8; 32]` — else [`HoldingsError::BadPeerIdHex`].
/// 3. `SHA-256(provider_spki)` equals the carried peer id — else
///    [`HoldingsError::PeerIdMismatch`] (the peer id is verified against the SPKI, never trusted).
/// 4. `provider_spki` parses as an `id-ecPublicKey` / `prime256v1` key — else
///    [`HoldingsError::BadSpki`].
/// 5. the ECDSA-P256 signature verifies over [`holdings_signing_message`] under that key —
///    else [`HoldingsError::InvalidSignature`].
///
/// Any `Err` means the deltas MUST NOT be ingested.
///
/// # Errors
///
/// [`HoldingsError`] describing the first failing check.
pub fn verify_holdings_announce(announce: &HoldingsAnnounce) -> Result<(), HoldingsError> {
    // 1. change-count cap.
    if announce.changes.len() > MAX_CHANGES {
        return Err(HoldingsError::TooManyChanges {
            count: announce.changes.len(),
        });
    }
    // 2. peer_id hex → 32 bytes.
    let peer_id = decode_peer_id(&announce.provider_peer_id)?;
    // 3. SHA-256(SPKI) == peer_id, VERIFIED against the carried value.
    let spki_peer_id = *peer_id_from_tls_spki_der(&announce.provider_spki).as_bytes();
    if spki_peer_id != peer_id {
        return Err(HoldingsError::PeerIdMismatch);
    }
    // 4. SPKI is a P-256 key — recover the EC point.
    let ec_point = p256_point_from_spki(&announce.provider_spki)?;
    // 5. ECDSA-P256 verify over the domain-separated message (ring hashes it internally).
    let message = holdings_signing_message(
        &peer_id,
        announce.seq,
        announce.announced_at,
        &announce.changes,
    );
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, ec_point)
        .verify(&message, &announce.signature)
        .map_err(|_| HoldingsError::InvalidSignature)
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
    /// Layout, all integers big-endian: `peer_id(len-prefixed) ‖ spki(len-prefixed) ‖
    /// seq(u64) ‖ announced_at(u64) ‖ change_count(u16) ‖ canonical_encode(changes) ‖
    /// signature(len-prefixed)`. The changes are encoded identically to
    /// [`canonical_encode`] so the signed bytes and the wire bytes never diverge.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_bytes(&mut buf, self.provider_peer_id.as_bytes());
        put_bytes(&mut buf, &self.provider_spki);
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
        let provider_spki = take_bytes(bytes, &mut pos)?.to_vec();
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
            provider_spki,
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
    use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    /// A self-contained P-256 test signer: rcgen generates a key pair (its `public_key_der`
    /// IS the leaf SPKI DER), and ring signs over the PKCS#8 serialization of the same key.
    /// The seed is process-random, so the leaf SPKI + signature are NOT byte-stable across
    /// runs — only behavioural assertions use it (see the layout KAT for the pinned bytes).
    fn ecdsa_signer() -> (EcdsaHoldingsSigner, Vec<u8>) {
        let kp = rcgen::KeyPair::generate().expect("generate P-256 key pair");
        let spki = kp.public_key_der();
        let rng = ring::rand::SystemRandom::new();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &kp.serialize_der(), &rng)
                .expect("ring accepts the rcgen PKCS#8 P-256 key");
        (EcdsaHoldingsSigner::new(key_pair, spki.clone()), spki)
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
        let (signer, _) = ecdsa_signer();
        HoldingsAnnounce::new_signed(&signer, 7, 1_700_000_000, sample_changes())
            .expect("within MAX_CHANGES")
    }

    #[test]
    fn opcode_is_222() {
        assert_eq!(HOLDINGS_ANNOUNCE, 222);
        assert!(is_holdings_announce(222));
        assert!(!is_holdings_announce(221));
    }

    #[test]
    fn peer_id_binds_to_spki() {
        let a = sample();
        let derived = peer_id_from_tls_spki_der(&a.provider_spki);
        assert_eq!(a.provider_peer_id, derived.to_hex());
        assert_eq!(
            a.provider_peer_id,
            hex::encode(Sha256::digest(&a.provider_spki))
        );
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
    fn verify_rejects_forged_signature() {
        let mut a = sample();
        a.signature = vec![0xFF; 72];
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::InvalidSignature)
        );
    }

    /// REGRESSION TEST for the decider's forgery: sign the message with key B but present
    /// key A's SPKI + A's peer_id. Because the SPKI (and thus peer_id) commits to key A, a
    /// signature by B's key MUST NOT verify — the "grafted key" attack is dead.
    #[test]
    fn verify_rejects_foreign_key_signature() {
        // Victim identity A — its SPKI + peer_id go on the wire.
        let (_, spki_a) = ecdsa_signer();
        let peer_id_a = peer_id_from_tls_spki_der(&spki_a);
        // Attacker key B signs a well-formed message for A's identity.
        let (signer_b, _) = ecdsa_signer();
        let message = holdings_signing_message(peer_id_a.as_bytes(), 7, 1, &sample_changes());
        let forged = HoldingsAnnounce {
            provider_peer_id: peer_id_a.to_hex(),
            provider_spki: spki_a,
            seq: 7,
            announced_at: 1,
            changes: sample_changes(),
            signature: signer_b.sign(&message),
        };
        assert_eq!(
            verify_holdings_announce(&forged),
            Err(HoldingsError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_wrong_peer_id() {
        let mut a = sample();
        // A different (valid 64-hex) peer id that no longer matches the SPKI hash.
        a.provider_peer_id = hex::encode([0xAB; 32]);
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::PeerIdMismatch)
        );
    }

    #[test]
    fn verify_rejects_mutated_spki() {
        let mut a = sample();
        // Flip a byte in the SPKI so its hash no longer equals the carried peer_id.
        let last = a.provider_spki.len() - 1;
        a.provider_spki[last] ^= 0x01;
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::PeerIdMismatch)
        );
    }

    #[test]
    fn verify_rejects_malformed_spki() {
        // A non-P256 / unparseable SPKI: point peer_id at its hash so we reach the SPKI
        // parse check (not PeerIdMismatch first).
        let spki = vec![1u8, 2, 3];
        let peer_id = peer_id_from_tls_spki_der(&spki);
        let a = HoldingsAnnounce {
            provider_peer_id: peer_id.to_hex(),
            provider_spki: spki,
            seq: 1,
            announced_at: 2,
            changes: sample_changes(),
            signature: vec![0u8; 72],
        };
        assert_eq!(verify_holdings_announce(&a), Err(HoldingsError::BadSpki));
    }

    #[test]
    fn verify_rejects_tampered_address() {
        let mut a = sample();
        if let HoldingsDelta::Add { addresses, .. } = &mut a.changes[0] {
            addresses[0].port = 1; // an address is signed — tampering breaks the message
        }
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_expires() {
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
    fn verify_rejects_tampered_content_key() {
        let mut a = sample();
        if let HoldingsDelta::Remove { content_key } = &mut a.changes[1] {
            content_key[0] ^= 0xFF;
        }
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
        let (signer, _) = ecdsa_signer();
        assert_eq!(
            HoldingsAnnounce::new_signed(&signer, 1, 1, too_many.clone()),
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
        let (signer, _) = ecdsa_signer();
        let a = HoldingsAnnounce::new_signed(&signer, 1, 2, changes).expect("at cap");
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

    // ---- KAT golden vector (CI-fail-on-drift) ---------------------------------
    //
    // The ECDSA-P256 signature is randomized, so it is NOT hex-pinnable; only the
    // signing-MESSAGE byte layout is pinned (via its SHA-256 fingerprint) under a fixed
    // literal peer id + fixed changes. This guards the domain tag + canonical_encode + field
    // order of this cross-repo wire contract. To regenerate intentionally (a deliberate v2),
    // print the hex below and update the constant.

    /// Deterministic KAT changes: one Add (one address) + one Remove, fixed content/expiry.
    fn kat_changes() -> Vec<HoldingsDelta> {
        vec![
            HoldingsDelta::Add {
                content_key: [0x33; 32],
                addresses: vec![CandidateAddr {
                    host: "2001:db8::dig".to_string(),
                    port: 9256,
                }],
                expires_at: 0x0000_0000_5000_0000,
            },
            HoldingsDelta::Remove {
                content_key: [0x44; 32],
            },
        ]
    }

    const KAT_SEQ: u64 = 0x0102_0304;
    const KAT_ANNOUNCED_AT: u64 = 0x0A0B_0C0D;
    /// A fixed, PUBLIC peer id literal — an identifier, NOT a secret (CodeQL-safe).
    const KAT_PEER_ID: [u8; 32] = [0x11; 32];

    #[test]
    fn kat_signing_message_layout_is_pinned() {
        const KAT_LAYOUT_HEX: &str =
            "c129496af9ec982d11b366901f4fc64f1bfac2991295dbb69f18edbd18bb8164";
        let got = hex::encode(signing_message_digest(
            &KAT_PEER_ID,
            KAT_SEQ,
            KAT_ANNOUNCED_AT,
            &kat_changes(),
        ));
        assert_eq!(got, KAT_LAYOUT_HEX, "KAT_LAYOUT_HEX drift: got {got}");
    }

    #[test]
    fn ecdsa_signature_verifies_over_message_not_prehash() {
        // Confirm sign/verify operate over the full preimage (ring hashes internally): a
        // freshly built announce verifies, and its digest helper is the SHA-256 of the same
        // message (a distinct, non-signed fingerprint).
        let a = sample();
        assert_eq!(verify_holdings_announce(&a), Ok(()));
        let peer_id = decode_peer_id(&a.provider_peer_id).unwrap();
        let expected = Sha256::digest(holdings_signing_message(
            &peer_id,
            a.seq,
            a.announced_at,
            &a.changes,
        ));
        assert_eq!(a.signing_message_digest().unwrap(), expected.as_slice());
    }
}
