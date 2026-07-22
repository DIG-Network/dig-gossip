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
//! domain-separated digest, the [`HoldingsSigner`] builder abstraction, the fail-closed
//! [`verify_holdings_announce`] gate, and the framing.
//!
//! # The inline leaf-cert wire (decider-locked, #1428)
//!
//! An announcement carries the provider's **full mTLS leaf certificate DER**
//! ([`HoldingsAnnounce::provider_cert`]), NOT a bare public key. That single cert is the
//! self-contained root of trust for the whole message:
//!
//! - Its **SPKI** yields the §5.2 `peer_id` (`SHA-256(SPKI DER)`), which MUST equal the
//!   carried [`provider_peer_id`](HoldingsAnnounce::provider_peer_id) — the peer_id is
//!   VERIFIED against the cert, never trusted.
//! - Its **#1204 BLS-G1 binding extension** (OID `1.3.6.1.4.1.58968.1.1`) supplies the
//!   BLS verify key that the signature is checked under. The binding is MANDATORY here
//!   (the sig key comes from it), so an absent or invalid binding is a hard reject.
//!
//! Because the cert is self-contained, dig-dht (#1424) and dig-warden (#1449) can
//! re-verify an announcement standalone, with no side channel to fetch a provider key.
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
//! therefore checks the cert→peer_id binding, the cert's BLS binding, the signature over
//! the exact digest, and the change-count cap — fail-closed on any mismatch.

use dig_peer_protocol::{Bytes, Message, ProtocolMessageTypes};
use dig_tls::binding::{verify_binding_from_leaf_cert, BindingOutcome};
use dig_tls::bls::{sign_message, verify_signature, SecretKey};
use dig_tls::peer_id_from_leaf_cert_der;
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
/// the deltas into its DHT holder set. See the module docs for the inline leaf-cert model,
/// the §5.4 exemption, and the signature's role as the DHT-poisoning gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldingsAnnounce {
    /// The provider's `peer_id` as 64 lowercase hex chars.
    ///
    /// Its value equals `SHA-256(SPKI DER of provider_cert)` (the §5.2 peer_id). It is
    /// VERIFIED against [`provider_cert`](Self::provider_cert) on the receive path, never
    /// trusted — see [`verify_holdings_announce`].
    pub provider_peer_id: String,
    /// The provider's FULL mTLS leaf certificate DER.
    ///
    /// Carries the SPKI (→ [`provider_peer_id`](Self::provider_peer_id)) and the #1204
    /// BLS-G1 binding extension (OID `1.3.6.1.4.1.58968.1.1`). The BLS verify key is NOT a
    /// separate wire field — it is obtained from this cert's binding. A leaf cert is
    /// ~600-900 bytes, far under the 64 KiB length-prefix limit.
    pub provider_cert: Vec<u8>,
    /// Monotonic sequence number — a later announcement supersedes an earlier one.
    pub seq: u64,
    /// Unix-seconds timestamp the announcement was produced.
    pub announced_at: u64,
    /// The batch of add/remove deltas (at most [`MAX_CHANGES`]).
    pub changes: Vec<HoldingsDelta>,
    /// The provider's 96-byte BLS-G2 AugScheme signature over [`digest`](Self::digest).
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
    /// `provider_cert` could not be parsed as an X.509 leaf, so no peer_id was derivable.
    BadCert,
    /// `SHA-256(SPKI of provider_cert)` did not equal `provider_peer_id`.
    PeerIdMismatch,
    /// `provider_cert` carries no #1204 BLS-G1 binding extension (required here).
    BindingAbsent,
    /// `provider_cert`'s binding extension is present but did not verify.
    BindingInvalid(&'static str),
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
            Self::BadCert => write!(f, "provider_cert is not a parseable X.509 leaf"),
            Self::PeerIdMismatch => {
                write!(f, "SHA-256(SPKI of provider_cert) != provider_peer_id")
            }
            Self::BindingAbsent => {
                write!(f, "provider_cert carries no BLS-G1 binding extension")
            }
            Self::BindingInvalid(reason) => {
                write!(f, "provider_cert BLS-G1 binding is invalid: {reason}")
            }
            Self::InvalidSignature => write!(f, "holdings announce signature did not verify"),
        }
    }
}

impl std::error::Error for HoldingsError {}

/// Supplies the provider's leaf cert and BLS signature to [`HoldingsAnnounce::new_signed`].
///
/// The signing key source is fixed by the wire (the leaf cert's #1204 binding), so this
/// trait exposes the cert and a raw signer rather than a pluggable scheme. The v1 concrete
/// implementation is [`BlsHoldingsSigner`]; dig-node (#1429) constructs one from its
/// `NodeCert` + node BLS secret key.
pub trait HoldingsSigner {
    /// Sign the 32-byte announcement digest, returning the 96-byte BLS-G2 AugScheme sig.
    fn sign(&self, digest: &[u8; 32]) -> Vec<u8>;
    /// The provider's bound mTLS leaf certificate DER (carried as `provider_cert`).
    fn leaf_cert_der(&self) -> Vec<u8>;
}

/// The v1 signer: a BLS-G1 identity key paired with its bound mTLS leaf certificate.
///
/// Produces a 96-byte AugScheme signature under `bls_sk` and carries `cert_der`, whose
/// #1204 binding extension binds the cert's peer_id to `bls_sk`'s public key. Uses the
/// crate's existing `dig_tls::bls` primitive; no new cryptography is introduced.
pub struct BlsHoldingsSigner {
    bls_sk: SecretKey,
    cert_der: Vec<u8>,
}

impl BlsHoldingsSigner {
    /// Wrap a BLS secret key and its bound leaf certificate DER as a holdings signer.
    ///
    /// `cert_der`'s #1204 binding MUST be for `bls_sk` (i.e. the cert was generated via
    /// [`NodeCert::generate_signed`](dig_tls::NodeCert::generate_signed)`(&bls_sk)`), or the
    /// resulting announcement will fail [`verify_holdings_announce`].
    #[must_use]
    pub fn new(bls_sk: SecretKey, cert_der: Vec<u8>) -> Self {
        Self { bls_sk, cert_der }
    }
}

impl HoldingsSigner for BlsHoldingsSigner {
    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        sign_message(&self.bls_sk, digest).to_vec()
    }

    fn leaf_cert_der(&self) -> Vec<u8> {
        self.cert_der.clone()
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
/// all `u64`s big-endian. The `provider_peer_id` here is the raw 32-byte peer id
/// (`SHA-256(SPKI DER)`). Both signer and verifier derive it identically so the signature
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
    /// Takes the leaf cert from `signer`, derives `provider_peer_id` from its SPKI, computes
    /// the digest over `(peer_id, seq, announced_at, changes)`, and signs it.
    ///
    /// # Errors
    ///
    /// - [`HoldingsError::TooManyChanges`] if `changes.len() > `[`MAX_CHANGES`] — the batch
    ///   is refused rather than truncated, so a caller cannot silently drop deltas.
    /// - [`HoldingsError::BadCert`] if the signer's leaf cert DER is not parseable as X.509.
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
        let provider_cert = signer.leaf_cert_der();
        let peer_id = peer_id_from_leaf_cert_der(&provider_cert).ok_or(HoldingsError::BadCert)?;
        let peer_id_bytes = *peer_id.as_bytes();
        let signature = signer.sign(&digest(&peer_id_bytes, seq, announced_at, &changes));
        Ok(Self {
            provider_peer_id: peer_id_hex(&peer_id_bytes),
            provider_cert,
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

/// Verify an announcement, fail-closed — the gate dig-node calls before dig-dht ingest.
///
/// The six checks, in order (the first failure is returned):
/// 1. `changes.len() <= `[`MAX_CHANGES`] — else [`HoldingsError::TooManyChanges`].
/// 2. `provider_peer_id` decodes as 64-hex → `[u8; 32]` — else [`HoldingsError::BadPeerIdHex`].
/// 3. `peer_id_from_leaf_cert_der(provider_cert)` succeeds ([`HoldingsError::BadCert`] else)
///    AND equals the carried peer id ([`HoldingsError::PeerIdMismatch`] else) — the peer id
///    is verified against the cert SPKI, never trusted.
/// 4. the cert's #1204 BLS-G1 binding is [`Bound`](BindingOutcome::Bound)
///    ([`HoldingsError::BindingAbsent`] / [`HoldingsError::BindingInvalid`] otherwise) — the
///    binding is MANDATORY (the signature key comes from it).
/// 5. the 96-byte signature verifies over [`digest`](HoldingsAnnounce::digest) under the
///    bound key — else [`HoldingsError::InvalidSignature`].
/// 6. `Ok(())`.
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
    // 3. cert → peer_id, VERIFIED against the carried value.
    let cert_peer_id =
        peer_id_from_leaf_cert_der(&announce.provider_cert).ok_or(HoldingsError::BadCert)?;
    if cert_peer_id.as_bytes() != &peer_id {
        return Err(HoldingsError::PeerIdMismatch);
    }
    // 4. mandatory #1204 BLS-G1 binding — the signature key source.
    let bls_pub = match verify_binding_from_leaf_cert(&announce.provider_cert) {
        BindingOutcome::Bound { bls_pub } => bls_pub,
        BindingOutcome::Absent => return Err(HoldingsError::BindingAbsent),
        BindingOutcome::Invalid(reason) => return Err(HoldingsError::BindingInvalid(reason)),
    };
    // 5. signature over the digest under the bound key.
    let sig96 = <[u8; 96]>::try_from(announce.signature.as_slice())
        .map_err(|_| HoldingsError::InvalidSignature)?;
    let digest = digest(
        &peer_id,
        announce.seq,
        announce.announced_at,
        &announce.changes,
    );
    if !verify_signature(&bls_pub, &digest, &sig96) {
        return Err(HoldingsError::InvalidSignature);
    }
    // 6. all checks passed.
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
    /// Layout, all integers big-endian: `peer_id(len-prefixed) ‖ cert(len-prefixed) ‖
    /// seq(u64) ‖ announced_at(u64) ‖ change_count(u16) ‖ canonical_encode(changes) ‖
    /// signature(len-prefixed)`. The changes are encoded identically to
    /// [`canonical_encode`] so the signed bytes and the wire bytes never diverge.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_bytes(&mut buf, self.provider_peer_id.as_bytes());
        put_bytes(&mut buf, &self.provider_cert);
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
        let provider_cert = take_bytes(bytes, &mut pos)?.to_vec();
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
            provider_cert,
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
    use dig_tls::NodeCert;

    /// A deterministic BLS identity key derived from a label — never a hard-coded literal,
    /// so a second implementation reproduces the same vector and CodeQL does not flag a
    /// hard-coded cryptographic value (see #917/#950).
    fn bls_sk(label: &str) -> SecretKey {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        SecretKey::from_seed(&seed)
    }

    /// A deterministic bound signer: a fresh CA-signed leaf whose #1204 binding is for the
    /// derived key. The leaf DER is NOT byte-stable across runs (fresh serial/validity), so
    /// only behavioural (not hex-pinned) assertions use it.
    fn signer(label: &str) -> BlsHoldingsSigner {
        let sk = bls_sk(label);
        let node = NodeCert::generate_signed(&sk).expect("generate bound leaf");
        BlsHoldingsSigner::new(sk, node.cert_der().to_vec())
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
    fn peer_id_binds_to_cert_spki() {
        let sk = bls_sk("holdings/provider2");
        let node = NodeCert::generate_signed(&sk).expect("leaf");
        let a = HoldingsAnnounce::new_signed(
            &BlsHoldingsSigner::new(sk, node.cert_der().to_vec()),
            1,
            2,
            sample_changes(),
        )
        .expect("within cap");
        assert_eq!(a.provider_peer_id, node.peer_id().to_hex());
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
        a.signature = vec![0xFF; 96];
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_wrong_peer_id() {
        let mut a = sample();
        // A different (valid 64-hex) peer id that no longer matches the cert SPKI.
        a.provider_peer_id = hex::encode([0xAB; 32]);
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::PeerIdMismatch)
        );
    }

    #[test]
    fn verify_rejects_binding_absent() {
        // A plain self-signed leaf with NO #1204 binding extension.
        let cert = rcgen::generate_simple_self_signed(vec!["peer.dig".to_string()])
            .expect("self-signed")
            .cert
            .der()
            .to_vec();
        // Sign with a key + point provider_peer_id at THIS cert's SPKI so we reach the
        // binding check (not PeerIdMismatch first).
        let peer_id = peer_id_from_leaf_cert_der(&cert).expect("parseable leaf");
        let sk = bls_sk("holdings/nobinding");
        let dig = digest(peer_id.as_bytes(), 1, 2, &sample_changes());
        let a = HoldingsAnnounce {
            provider_peer_id: peer_id.to_hex(),
            provider_cert: cert,
            seq: 1,
            announced_at: 2,
            changes: sample_changes(),
            signature: sign_message(&sk, &dig).to_vec(),
        };
        assert_eq!(
            verify_holdings_announce(&a),
            Err(HoldingsError::BindingAbsent)
        );
    }

    #[test]
    fn verify_rejects_unparseable_cert() {
        let mut a = sample();
        a.provider_cert = vec![1, 2, 3];
        assert_eq!(verify_holdings_announce(&a), Err(HoldingsError::BadCert));
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
    // Cert-INDEPENDENT vectors: a leaf cert DER is not byte-stable across runs, so we pin
    // the digest + BLS signature (which depend only on a fixed literal peer_id + fixed
    // changes + a deterministic key) rather than any full-announce bytes. Any drift in the
    // domain tag, canonical_encode byte layout, or BLS scheme FAILS the build. To regenerate
    // intentionally (a deliberate v2), print the hex below and update the constant.

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
    fn kat_digest_is_pinned() {
        // Recompute-and-compare guards the domain tag + canonical_encode + digest layout.
        const KAT_DIGEST_HEX: &str =
            "c129496af9ec982d11b366901f4fc64f1bfac2991295dbb69f18edbd18bb8164";
        let got = hex::encode(digest(
            &KAT_PEER_ID,
            KAT_SEQ,
            KAT_ANNOUNCED_AT,
            &kat_changes(),
        ));
        assert_eq!(got, KAT_DIGEST_HEX, "KAT_DIGEST_HEX drift: got {got}");
    }

    #[test]
    fn kat_bls_signature_is_pinned() {
        let dig = digest(&KAT_PEER_ID, KAT_SEQ, KAT_ANNOUNCED_AT, &kat_changes());
        let sk = bls_sk("kat/holder");
        let sig = sign_message(&sk, &dig);
        let pubkey = dig_tls::bls::public_key_bytes(&sk);
        // Cert-independent: signs the pinned digest under a deterministic key.
        const KAT_SIG_HEX: &str = "83c932836ebf9d2acbdf9833f8efec711df8e99a2208fb5eef3b8a02b75f8e3fd08a72a8501a21ab1716f0662f1e14fc0e9378e77eb88a3b8ff939295f73fab4452c364fa6e4fb96a2a1db30d7b366fb390eecb6917b2ee7584df20b37063483";
        let got = hex::encode(sig);
        assert!(
            verify_signature(&pubkey, &dig, &sig),
            "KAT signature must verify under its own key"
        );
        assert_eq!(got, KAT_SIG_HEX, "KAT_SIG_HEX drift: got {got}");
    }
}
