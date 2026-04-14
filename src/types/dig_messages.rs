//! DIG-specific protocol message type IDs (**200+**), disjoint from Chia’s [`ProtocolMessageTypes`].
//!
//! ## Requirements
//!
//! - **API-009:** [`docs/requirements/domains/crate_api/specs/API-009.md`](../../../docs/requirements/domains/crate_api/specs/API-009.md)
//! - **NORMATIVE:** [`docs/requirements/domains/crate_api/NORMATIVE.md`](../../../docs/requirements/domains/crate_api/NORMATIVE.md) (API-009)
//! - **SPEC:** [`docs/resources/SPEC.md`](../../../docs/resources/SPEC.md) §2.3
//!
//! ## Rationale
//!
//! Chia’s [`ProtocolMessageTypes`] occupies the low numeric band on the wire. DIG L2 extensions
//! (attestations, checkpoints, Plumtree, ERLAY, Dandelion stem, …) use **explicit `u8` discriminants
//! starting at 200** so new Chia core messages are unlikely to collide with DIG payloads when both
//! share a [`Message`](chia_protocol::Message) wrapper whose `msg_type` field is an untyped integer.
//!
//! ## Serialization
//!
//! [`Serialize`] / [`Deserialize`] encode this enum as its **numeric wire value** (single `u8`), not
//! the Rust variant name — matching how values will be embedded in `Message.msg_type` and binary
//! traces. Human-readable JSON therefore uses integers (e.g. `200`), which is intentional.

use std::convert::TryFrom;
use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Unknown `u8` received where a [`DigMessageType`] was expected (invalid wire value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownDigMessageType(pub u8);

impl fmt::Display for UnknownDigMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown DigMessageType discriminant: {}", self.0)
    }
}

impl std::error::Error for UnknownDigMessageType {}

/// DIG L2 wire discriminants (`200..=217`) extending Chia’s protocol namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DigMessageType {
    /// Validator attestation for a block.
    NewAttestation = 200,
    /// Checkpoint proposal from epoch proposer.
    NewCheckpointProposal = 201,
    /// BLS signature for checkpoint aggregation.
    NewCheckpointSignature = 202,
    /// Request checkpoint signatures from peers.
    RequestCheckpointSignatures = 203,
    /// Response with checkpoint signatures.
    RespondCheckpointSignatures = 204,
    /// Request peer chain status.
    RequestStatus = 205,
    /// Response with chain status.
    RespondStatus = 206,
    /// Final aggregated checkpoint submission.
    NewCheckpointSubmission = 207,
    /// Validator directory announcement.
    ValidatorAnnounce = 208,
    /// Compact block: request missing transactions ([`SPEC.md`](../../../docs/resources/SPEC.md) §8.2).
    RequestBlockTransactions = 209,
    /// Compact block: respond with missing transactions (§8.2).
    RespondBlockTransactions = 210,
    /// ERLAY reconciliation sketch (§8.3).
    ReconciliationSketch = 211,
    /// ERLAY reconciliation response (§8.3).
    ReconciliationResponse = 212,
    /// Dandelion++ stem-phase transaction ([`SPEC.md`](../../../docs/resources/SPEC.md) §1.9.1).
    StemTransaction = 213,
    /// Plumtree lazy hash-only announcement (§8.1 / PLT-009).
    PlumtreeLazyAnnounce = 214,
    /// Plumtree prune — demote sender to lazy (§8.1).
    PlumtreePrune = 215,
    /// Plumtree graft — promote sender to eager (§8.1).
    PlumtreeGraft = 216,
    /// Plumtree request full payload by hash (§8.1).
    PlumtreeRequestByHash = 217,
}

impl DigMessageType {
    /// Upper bound (inclusive) of the assigned DIG band in this API revision.
    pub const MAX_ASSIGNED: u8 = Self::PlumtreeRequestByHash as u8;

    /// Iterator over all defined variants (stable declaration order).
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

impl TryFrom<u8> for DigMessageType {
    type Error = UnknownDigMessageType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
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

impl Serialize for DigMessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

struct DigMessageTypeSerdeVisitor;

impl Visitor<'_> for DigMessageTypeSerdeVisitor {
    type Value = DigMessageType;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("DigMessageType wire value (u8 in 200..=217)")
    }

    fn visit_u8<E: de::Error>(self, v: u8) -> Result<Self::Value, E> {
        DigMessageType::try_from(v).map_err(|e| E::custom(e.to_string()))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        let v = u8::try_from(v).map_err(|_| E::custom("DigMessageType value out of u8 range"))?;
        self.visit_u8(v)
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        let v = u8::try_from(v).map_err(|_| E::custom("DigMessageType value out of u8 range"))?;
        self.visit_u8(v)
    }
}

impl<'de> Deserialize<'de> for DigMessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u8(DigMessageTypeSerdeVisitor)
    }
}
