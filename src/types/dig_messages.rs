//! DIG-specific protocol message type IDs (**200+**), disjoint from Chia’s [`ProtocolMessageTypes`].
//!
//! ## Why DIG needs extension message types
//!
//! Chia’s [`ProtocolMessageTypes`] enum covers the base L1 protocol: block propagation,
//! peer exchange, wallet sync, etc. DIG’s L2 overlay adds several new message
//! categories that have no Chia equivalent:
//!
//! - **Attestation gossip** — validator attestations for finality (domain: CBK).
//! - **Checkpoint protocol** — proposal, signature collection, aggregated submission
//!   (domain: CBK).
//! - **Compact block relay** — request/respond for missing transactions to reduce
//!   bandwidth (domain: CBK, SPEC §8.2).
//! - **ERLAY reconciliation** — set-reconciliation sketches for efficient transaction
//!   relay (domain: ERL, SPEC §8.3).
//! - **Dandelion++ stem** — privacy-preserving transaction origination (domain: PRV,
//!   SPEC §1.9.1).
//! - **Plumtree** — epidemic broadcast tree messages for optimized gossip (domain: PLT,
//!   SPEC §8.1).
//! - **Validator directory** — announcements for the validator discovery protocol.
//! - **Status exchange** — chain-tip negotiation between peers on connect.
//!
//! ## The 200+ range convention
//!
//! Chia’s [`ProtocolMessageTypes`] currently uses discriminants in the **0-99** range
//! for full-node messages. By starting DIG discriminants at **200**, we maintain a
//! 100-value gap that protects against future Chia additions colliding with DIG
//! payloads. Both share the same [`Message`](chia_protocol::Message) framing — the
//! `msg_type` field is an untyped integer on the wire, so the receiver dispatches on
//! numeric value, routing < 200 to the Chia handler and >= 200 to the DIG handler.
//!
//! ## Requirements
//!
//! - **API-009:** [`docs/requirements/domains/crate_api/specs/API-009.md`](../../../docs/requirements/domains/crate_api/specs/API-009.md)
//! - **NORMATIVE:** [`docs/requirements/domains/crate_api/NORMATIVE.md`](../../../docs/requirements/domains/crate_api/NORMATIVE.md) (API-009)
//! - **SPEC:** [`docs/resources/SPEC.md`](../../../docs/resources/SPEC.md) §2.3
//!
//! ## Serialization
//!
//! [`Serialize`] / [`Deserialize`] encode this enum as its **numeric wire value** (single `u8`), not
//! the Rust variant name — matching how values will be embedded in `Message.msg_type` and binary
//! traces. Human-readable JSON therefore uses integers (e.g. `200`), which is intentional.
//!
//! ## Wire protocol mapping
//!
//! On the wire, a DIG message is wrapped in a Chia [`Message`](chia_protocol::Message)
//! whose `msg_type` is set to `DigMessageType as u8`. The `data` field contains the
//! serialized DIG payload. Conversion back from wire bytes uses [`TryFrom<u8>`] which
//! returns [`UnknownDigMessageType`] for any value outside the assigned 200..=217 band
//! — this allows the receiver to cleanly reject unknown or corrupt discriminants
//! without panicking.

use std::convert::TryFrom;
use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Error returned by [`TryFrom<u8>`] for [`DigMessageType`] when the wire value does
/// not correspond to any assigned DIG discriminant.
///
/// Wraps the offending `u8` so that error messages and logs can report the exact
/// numeric value that was rejected. This is important for debugging version-skew
/// scenarios where a newer peer sends a discriminant that this build does not
/// recognize.
///
/// Implements [`std::error::Error`] so it can be used with `?` and error-chaining
/// crates (`anyhow`, `thiserror`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownDigMessageType(pub u8);

impl fmt::Display for UnknownDigMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown DigMessageType discriminant: {}", self.0)
    }
}

impl std::error::Error for UnknownDigMessageType {}

/// DIG L2 wire discriminants (`200..=217`) extending Chia’s protocol namespace.
///
/// Each variant maps 1:1 to a `u8` wire value via `#[repr(u8)]`. The discriminant is
/// written directly into [`chia_protocol::Message::msg_type`] on send and parsed back
/// via [`TryFrom<u8>`] on receive.
///
/// # Variant grouping by gossip strategy
///
/// | Strategy | Variants | Description |
/// |----------|----------|-------------|
/// | **Plumtree eager push** | `NewAttestation`, `NewCheckpointProposal`, `NewCheckpointSignature`, `NewCheckpointSubmission` | Latency-critical data sent eagerly to tree neighbors (SPEC §8.1). |
/// | **Plumtree lazy announce** | `PlumtreeLazyAnnounce` | Hash-only announcement sent to non-tree peers; they graft if they need the full payload. |
/// | **Plumtree control** | `PlumtreePrune`, `PlumtreeGraft`, `PlumtreeRequestByHash` | Tree maintenance messages (domain: PLT). |
/// | **ERLAY reconciliation** | `ReconciliationSketch`, `ReconciliationResponse` | Set-reconciliation for bandwidth-efficient tx relay (domain: ERL, SPEC §8.3). |
/// | **Dandelion++ stem** | `StemTransaction` | Privacy-preserving tx origination — forwarded along a stem path before fluffing (domain: PRV, SPEC §1.9.1). |
/// | **Compact block** | `RequestBlockTransactions`, `RespondBlockTransactions` | Request/response pair for missing txs in compact blocks (domain: CBK, SPEC §8.2). |
/// | **Unicast request/response** | `RequestCheckpointSignatures`/`RespondCheckpointSignatures`, `RequestStatus`/`RespondStatus` | Point-to-point exchanges, no gossip fan-out. |
/// | **Broadcast announce** | `ValidatorAnnounce` | Flooded to all peers for validator directory updates. |
///
/// # Requirement domains
///
/// - **PLT** (Plumtree): `PlumtreeLazyAnnounce`, `PlumtreePrune`, `PlumtreeGraft`, `PlumtreeRequestByHash`
/// - **CBK** (Checkpoint/Block): `NewAttestation`, `NewCheckpointProposal`, `NewCheckpointSignature`,
///   `RequestCheckpointSignatures`, `RespondCheckpointSignatures`, `NewCheckpointSubmission`,
///   `RequestBlockTransactions`, `RespondBlockTransactions`
/// - **ERL** (ERLAY): `ReconciliationSketch`, `ReconciliationResponse`
/// - **PRV** (Privacy): `StemTransaction`
/// - **CNC** (Connection): `RequestStatus`, `RespondStatus`, `ValidatorAnnounce`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DigMessageType {
    /// Validator attestation for a block.
    ///
    /// Carries a signed attestation payload. Gossip strategy: **Plumtree eager push**
    /// to tree neighbors for low-latency propagation. Domain: CBK.
    NewAttestation = 200,

    /// Checkpoint proposal from the epoch proposer.
    ///
    /// Carries the proposed checkpoint header and metadata. Gossip strategy:
    /// **Plumtree eager push**. Domain: CBK.
    NewCheckpointProposal = 201,

    /// BLS signature fragment for checkpoint aggregation.
    ///
    /// Each validator produces one signature over the checkpoint proposal; these are
    /// collected and aggregated into a single BLS aggregate. Gossip strategy:
    /// **Plumtree eager push**. Domain: CBK.
    NewCheckpointSignature = 202,

    /// Request checkpoint signatures from a specific peer (unicast).
    ///
    /// Used when a node needs to fill in missing signature fragments before the
    /// aggregation deadline. Gossip strategy: **unicast request/response**.
    /// Domain: CBK.
    RequestCheckpointSignatures = 203,

    /// Response carrying the requested checkpoint signatures (unicast).
    ///
    /// Paired with [`RequestCheckpointSignatures`](Self::RequestCheckpointSignatures).
    /// Domain: CBK.
    RespondCheckpointSignatures = 204,

    /// Request the peer’s current chain status (chain tip, height, epoch).
    ///
    /// Sent during connection setup and periodically to detect forks. Gossip
    /// strategy: **unicast request/response**. Domain: CNC.
    RequestStatus = 205,

    /// Response with chain status (paired with [`RequestStatus`](Self::RequestStatus)).
    ///
    /// Domain: CNC.
    RespondStatus = 206,

    /// Final aggregated checkpoint after BLS signature aggregation.
    ///
    /// Broadcast once the proposer (or any validator that collected enough fragments)
    /// has a complete aggregate signature. Gossip strategy: **Plumtree eager push**.
    /// Domain: CBK.
    NewCheckpointSubmission = 207,

    /// Validator directory announcement.
    ///
    /// A validator publishes its identity and network address so peers can locate
    /// it for direct communication (e.g., checkpoint signature requests). Gossip
    /// strategy: **broadcast flood** to all connected peers. Domain: CNC.
    ValidatorAnnounce = 208,

    /// Compact block relay: request missing transactions by short ID
    /// ([`SPEC.md`](../../../docs/resources/SPEC.md) §8.2).
    ///
    /// Sent when a peer receives a compact block but lacks some transactions in its
    /// mempool. Gossip strategy: **unicast request/response**. Domain: CBK.
    RequestBlockTransactions = 209,

    /// Compact block relay: respond with the full transactions requested
    /// (§8.2).
    ///
    /// Paired with [`RequestBlockTransactions`](Self::RequestBlockTransactions).
    /// Domain: CBK.
    RespondBlockTransactions = 210,

    /// ERLAY reconciliation sketch (§8.3).
    ///
    /// Carries a minisketch of the sender’s transaction set for bandwidth-efficient
    /// set-difference computation. Gossip strategy: **unicast** (per reconciliation
    /// interval). Domain: ERL.
    ReconciliationSketch = 211,

    /// ERLAY reconciliation response with the set of tx_ids the peer is missing
    /// (§8.3).
    ///
    /// Paired with [`ReconciliationSketch`](Self::ReconciliationSketch). Domain: ERL.
    ReconciliationResponse = 212,

    /// Dandelion++ stem-phase transaction
    /// ([`SPEC.md`](../../../docs/resources/SPEC.md) §1.9.1).
    ///
    /// A transaction in the "stem" phase is forwarded along a single random path
    /// (the stem) before being "fluffed" into normal broadcast. This hides the
    /// originator’s identity. Gossip strategy: **stem forwarding** (one hop to
    /// the next stem peer). Domain: PRV.
    StemTransaction = 213,

    /// Plumtree lazy hash-only announcement (§8.1 / PLT-009).
    ///
    /// Sent to peers that are *not* in the sender’s eager-push tree. Contains only
    /// the message hash; if the receiver has not already seen the full message, it
    /// sends a [`PlumtreeGraft`](Self::PlumtreeGraft) to request it. Domain: PLT.
    PlumtreeLazyAnnounce = 214,

    /// Plumtree prune — ask the sender to demote this receiver to lazy (§8.1).
    ///
    /// Sent when a peer receives a duplicate eager-push message, indicating that
    /// the sender’s eager link is redundant. Domain: PLT.
    PlumtreePrune = 215,

    /// Plumtree graft — ask the sender to promote this receiver to eager (§8.1).
    ///
    /// Sent after receiving a [`PlumtreeLazyAnnounce`](Self::PlumtreeLazyAnnounce)
    /// for a message not yet seen via eager push. Domain: PLT.
    PlumtreeGraft = 216,

    /// Plumtree request full payload by hash (§8.1).
    ///
    /// Explicit pull request when a peer needs the full message content identified
    /// by the hash from a lazy announcement. Domain: PLT.
    PlumtreeRequestByHash = 217,
}

impl DigMessageType {
    /// Upper bound (inclusive) of the assigned DIG band in this API revision.
    ///
    /// Used by tests and validators to confirm that no discriminant exceeds the
    /// allocated range. Future DIG message types should be assigned values above
    /// this constant (i.e., 218+).
    pub const MAX_ASSIGNED: u8 = Self::PlumtreeRequestByHash as u8;

    /// All 18 defined variants in stable declaration order.
    ///
    /// Useful for exhaustive iteration in tests, serialization round-trip checks,
    /// and registry construction. The order matches the enum definition and will
    /// not change for existing variants (new variants are appended).
    pub const ALL: [Self; 18] = [
        Self::NewAttestation,
        Self::NewCheckpointProposal,
        Self::NewCheckpointSignature,
        Self::RequestCheckpointSignatures,
        Self::RespondCheckpointSignatures,
        Self::RequestStatus,
        Self::RespondStatus,
        Self::NewCheckpointSubmission,
        Self::ValidatorAnnounce,
        Self::RequestBlockTransactions,
        Self::RespondBlockTransactions,
        Self::ReconciliationSketch,
        Self::ReconciliationResponse,
        Self::StemTransaction,
        Self::PlumtreeLazyAnnounce,
        Self::PlumtreePrune,
        Self::PlumtreeGraft,
        Self::PlumtreeRequestByHash,
    ];
}

/// Convert a raw `u8` wire value back into a [`DigMessageType`].
///
/// # Why `TryFrom` instead of `From`
///
/// The DIG band occupies only 200..=217 out of the full 0..=255 `u8` range.
/// Values outside that band are not valid DIG discriminants and must be
/// rejected rather than silently misinterpreted. `TryFrom` makes this
/// fallibility explicit at the type level — callers are forced to handle the
/// `Err(UnknownDigMessageType)` case, which is the correct behavior for
/// untrusted wire input.
///
/// # Errors
///
/// Returns [`UnknownDigMessageType`] wrapping the offending byte if `value`
/// is not in the assigned 200..=217 range.
impl TryFrom<u8> for DigMessageType {
    type Error = UnknownDigMessageType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        // Exhaustive match on every assigned discriminant. A match rather than
        // arithmetic (value - 200 as index) avoids assuming contiguity if future
        // revisions leave gaps in the numbering.
        match value {
            200 => Ok(Self::NewAttestation),
            201 => Ok(Self::NewCheckpointProposal),
            202 => Ok(Self::NewCheckpointSignature),
            203 => Ok(Self::RequestCheckpointSignatures),
            204 => Ok(Self::RespondCheckpointSignatures),
            205 => Ok(Self::RequestStatus),
            206 => Ok(Self::RespondStatus),
            207 => Ok(Self::NewCheckpointSubmission),
            208 => Ok(Self::ValidatorAnnounce),
            209 => Ok(Self::RequestBlockTransactions),
            210 => Ok(Self::RespondBlockTransactions),
            211 => Ok(Self::ReconciliationSketch),
            212 => Ok(Self::ReconciliationResponse),
            213 => Ok(Self::StemTransaction),
            214 => Ok(Self::PlumtreeLazyAnnounce),
            215 => Ok(Self::PlumtreePrune),
            216 => Ok(Self::PlumtreeGraft),
            217 => Ok(Self::PlumtreeRequestByHash),
            other => Err(UnknownDigMessageType(other)),
        }
    }
}

/// Serialize as the raw `u8` discriminant, not the variant name.
///
/// This means JSON output is `200`, not `"NewAttestation"`. This is intentional:
/// the numeric value is what appears on the wire and in binary traces, so using
/// it in human-readable formats keeps representations consistent and avoids a
/// name-to-number mapping step during debugging.
impl Serialize for DigMessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

/// Serde visitor that accepts numeric representations of [`DigMessageType`].
///
/// Handles `u8`, `u64`, and `i64` because different serialization formats
/// (JSON, MessagePack, CBOR) may present the same integer through different
/// visitor methods. All paths narrow to `u8` first, then delegate to
/// [`TryFrom<u8>`] for validation.
struct DigMessageTypeSerdeVisitor;

impl Visitor<'_> for DigMessageTypeSerdeVisitor {
    type Value = DigMessageType;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("DigMessageType wire value (u8 in 200..=217)")
    }

    fn visit_u8<E: de::Error>(self, v: u8) -> Result<Self::Value, E> {
        DigMessageType::try_from(v).map_err(|e| E::custom(e.to_string()))
    }

    /// JSON integers arrive as `u64`; narrow to `u8` first.
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        let v = u8::try_from(v).map_err(|_| E::custom("DigMessageType value out of u8 range"))?;
        self.visit_u8(v)
    }

    /// Some formats (e.g., MessagePack) may deliver small positive integers as `i64`.
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        let v = u8::try_from(v).map_err(|_| E::custom("DigMessageType value out of u8 range"))?;
        self.visit_u8(v)
    }
}

/// Deserialize from the raw `u8` wire value.
///
/// Requests `u8` from the deserializer via [`Deserializer::deserialize_u8`], but the
/// visitor also accepts `u64`/`i64` for format compatibility. Unknown discriminants
/// produce a serde error wrapping [`UnknownDigMessageType`].
impl<'de> Deserialize<'de> for DigMessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u8(DigMessageTypeSerdeVisitor)
    }
}
