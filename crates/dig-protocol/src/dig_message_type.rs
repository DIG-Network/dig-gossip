//! DIG-specific protocol message type IDs (**200+**), disjoint from Chia's `ProtocolMessageTypes`.
//!
//! ## The 200+ range convention
//!
//! Chia's `ProtocolMessageTypes` uses discriminants 0–107 for L1 messages. DIG starts at
//! **200**, leaving a 100-value gap against future Chia additions. Both share the same
//! `Message` framing — the `msg_type` field is an untyped `u8` on the wire, so the
//! receiver dispatches on numeric value: `< 200` → Chia handler, `>= 200` → DIG handler.
//!
//! ## Variant grouping by gossip strategy
//!
//! | Strategy | Variants | Description |
//! |----------|----------|-------------|
//! | **Plumtree eager push** | `NewAttestation`, `NewCheckpointProposal`, `NewCheckpointSignature`, `NewCheckpointSubmission` | Latency-critical data sent eagerly to tree neighbors. |
//! | **Plumtree lazy announce** | `PlumtreeLazyAnnounce` | Hash-only announcement sent to non-tree peers. |
//! | **Plumtree control** | `PlumtreePrune`, `PlumtreeGraft`, `PlumtreeRequestByHash` | Tree maintenance. |
//! | **ERLAY reconciliation** | `ReconciliationSketch`, `ReconciliationResponse` | Set-reconciliation for efficient tx relay. |
//! | **Dandelion++ stem** | `StemTransaction` | Privacy-preserving tx origination. |
//! | **Compact block** | `RequestBlockTransactions`, `RespondBlockTransactions` | Missing tx request/response. |
//! | **Unicast request/response** | `RequestCheckpointSignatures`/`Respond*`, `RequestStatus`/`RespondStatus` | Point-to-point. |
//! | **Broadcast announce** | `ValidatorAnnounce` | Flooded to all peers. |
//! | **Introducer** | `RegisterPeer`, `RegisterAck` | Introducer self-registration. |

use std::convert::TryFrom;
use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Error returned by `TryFrom<u8>` when the wire value is not a known DIG discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownDigMessageType(pub u8);

impl fmt::Display for UnknownDigMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown DigMessageType discriminant: {}", self.0)
    }
}

impl std::error::Error for UnknownDigMessageType {}

/// DIG L2 wire discriminants (`200..=219`) extending Chia's protocol namespace.
///
/// Each variant maps 1:1 to a `u8` wire value via `#[repr(u8)]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DigMessageType {
    /// Validator attestation. Plumtree eager push.
    NewAttestation = 200,
    /// Checkpoint proposal from epoch proposer. Plumtree eager push.
    NewCheckpointProposal = 201,
    /// BLS signature fragment for checkpoint aggregation. Plumtree eager push.
    NewCheckpointSignature = 202,
    /// Request checkpoint signatures (unicast).
    RequestCheckpointSignatures = 203,
    /// Response with checkpoint signatures (unicast).
    RespondCheckpointSignatures = 204,
    /// Request peer's chain status (unicast).
    RequestStatus = 205,
    /// Response with chain status (unicast).
    RespondStatus = 206,
    /// Aggregated checkpoint after BLS aggregation. Plumtree eager push.
    NewCheckpointSubmission = 207,
    /// Validator directory announcement. Broadcast flood.
    ValidatorAnnounce = 208,
    /// Compact block: request missing transactions by short ID.
    RequestBlockTransactions = 209,
    /// Compact block: respond with full transactions.
    RespondBlockTransactions = 210,
    /// ERLAY reconciliation sketch.
    ReconciliationSketch = 211,
    /// ERLAY reconciliation response.
    ReconciliationResponse = 212,
    /// Dandelion++ stem-phase transaction.
    StemTransaction = 213,
    /// Plumtree lazy hash-only announcement.
    PlumtreeLazyAnnounce = 214,
    /// Plumtree prune — demote sender to lazy.
    PlumtreePrune = 215,
    /// Plumtree graft — promote sender to eager.
    PlumtreeGraft = 216,
    /// Plumtree request full payload by hash.
    PlumtreeRequestByHash = 217,
    /// Introducer self-registration request (DSC-005).
    RegisterPeer = 218,
    /// Introducer registration acknowledgement (DSC-005).
    RegisterAck = 219,
}

impl DigMessageType {
    /// Upper bound (inclusive) of the assigned DIG band.
    pub const MAX_ASSIGNED: u8 = Self::RegisterAck as u8;

    /// All 20 defined variants in declaration order.
    pub const ALL: [Self; 20] = [
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
        Self::RegisterPeer,
        Self::RegisterAck,
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
            218 => Ok(Self::RegisterPeer),
            219 => Ok(Self::RegisterAck),
            other => Err(UnknownDigMessageType(other)),
        }
    }
}

impl fmt::Display for DigMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}({})", self, *self as u8)
    }
}

/// Serialize as raw `u8` discriminant (not variant name). Wire-consistent.
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
        formatter.write_str("DigMessageType wire value (u8 in 200..=219)")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_round_trip() {
        for variant in DigMessageType::ALL {
            let byte = variant as u8;
            let back = DigMessageType::try_from(byte).expect("round trip");
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn unknown_rejected() {
        assert!(DigMessageType::try_from(0).is_err());
        assert!(DigMessageType::try_from(107).is_err());
        assert!(DigMessageType::try_from(199).is_err());
        assert!(DigMessageType::try_from(220).is_err());
    }

    #[test]
    fn range_200_to_219() {
        assert_eq!(DigMessageType::NewAttestation as u8, 200);
        assert_eq!(DigMessageType::RegisterAck as u8, 219);
        assert_eq!(DigMessageType::MAX_ASSIGNED, 219);
    }

    #[test]
    fn serde_round_trip() {
        let val = DigMessageType::PlumtreeGraft;
        let json = serde_json::to_string(&val).unwrap();
        assert_eq!(json, "216");
        let back: DigMessageType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, val);
    }

    #[test]
    fn display_shows_name_and_value() {
        let s = format!("{}", DigMessageType::RegisterPeer);
        assert!(s.contains("RegisterPeer"));
        assert!(s.contains("218"));
    }
}
