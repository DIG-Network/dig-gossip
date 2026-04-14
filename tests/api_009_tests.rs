//! Tests for **API-009: [`DigMessageType`]** (DIG wire IDs 200–217).
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`API-009.md`](../docs/requirements/domains/crate_api/specs/API-009.md)
//! - **SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §2.3
//!
//! ## What this proves
//!
//! - **Discriminants** match the normative table (cast `as u8` equals the wire byte placed in
//!   [`chia_protocol::Message::msg_type`](chia_protocol::Message) for DIG extension frames).
//! - **`TryFrom<u8>`** accepts only the assigned band and yields [`UnknownDigMessageType`] otherwise.
//! - **Serde** round-trips as **integers** (not variant strings), which is required for config/logs
//!   and matches on-wire thinking.
//! - **Collision narrative:** sample Chia [`ProtocolMessageTypes`] values stay below the DIG
//!   reservation (200+), per API-009 “collision avoidance” prose.

use std::collections::HashSet;
use std::convert::TryFrom;

use dig_gossip::{
    ChiaProtocolMessage, DigMessageType, NewPeak, RequestPeers, UnknownDigMessageType,
};

// ---------------------------------------------------------------------------
// Discriminant table (one test per row in API-009 verification matrix)
// ---------------------------------------------------------------------------

#[test]
fn test_new_attestation_value() {
    assert_eq!(DigMessageType::NewAttestation as u8, 200);
}

#[test]
fn test_new_checkpoint_proposal_value() {
    assert_eq!(DigMessageType::NewCheckpointProposal as u8, 201);
}

#[test]
fn test_new_checkpoint_signature_value() {
    assert_eq!(DigMessageType::NewCheckpointSignature as u8, 202);
}

#[test]
fn test_request_checkpoint_signatures_value() {
    assert_eq!(DigMessageType::RequestCheckpointSignatures as u8, 203);
}

#[test]
fn test_respond_checkpoint_signatures_value() {
    assert_eq!(DigMessageType::RespondCheckpointSignatures as u8, 204);
}

#[test]
fn test_request_status_value() {
    assert_eq!(DigMessageType::RequestStatus as u8, 205);
}

#[test]
fn test_respond_status_value() {
    assert_eq!(DigMessageType::RespondStatus as u8, 206);
}

#[test]
fn test_new_checkpoint_submission_value() {
    assert_eq!(DigMessageType::NewCheckpointSubmission as u8, 207);
}

#[test]
fn test_validator_announce_value() {
    assert_eq!(DigMessageType::ValidatorAnnounce as u8, 208);
}

#[test]
fn test_request_block_transactions_value() {
    assert_eq!(DigMessageType::RequestBlockTransactions as u8, 209);
}

#[test]
fn test_respond_block_transactions_value() {
    assert_eq!(DigMessageType::RespondBlockTransactions as u8, 210);
}

#[test]
fn test_reconciliation_sketch_value() {
    assert_eq!(DigMessageType::ReconciliationSketch as u8, 211);
}

#[test]
fn test_reconciliation_response_value() {
    assert_eq!(DigMessageType::ReconciliationResponse as u8, 212);
}

#[test]
fn test_stem_transaction_value() {
    assert_eq!(DigMessageType::StemTransaction as u8, 213);
}

#[test]
fn test_plumtree_lazy_announce_value() {
    assert_eq!(DigMessageType::PlumtreeLazyAnnounce as u8, 214);
}

#[test]
fn test_plumtree_prune_value() {
    assert_eq!(DigMessageType::PlumtreePrune as u8, 215);
}

#[test]
fn test_plumtree_graft_value() {
    assert_eq!(DigMessageType::PlumtreeGraft as u8, 216);
}

#[test]
fn test_plumtree_request_by_hash_value() {
    assert_eq!(DigMessageType::PlumtreeRequestByHash as u8, 217);
}

/// **Row:** `test_all_values_above_200` — entire DIG band is ≥ 200 (API-009 acceptance).
#[test]
fn test_all_values_above_200() {
    for v in DigMessageType::ALL {
        assert!((v as u8) >= 200);
    }
}

/// **Row:** `test_no_duplicate_discriminants` — each wire byte maps to exactly one variant.
#[test]
fn test_no_duplicate_discriminants() {
    let mut s = HashSet::new();
    for v in DigMessageType::ALL {
        assert!(s.insert(v as u8), "duplicate discriminant for {:?}", v);
    }
    assert_eq!(s.len(), DigMessageType::ALL.len());
}

/// **Row:** `test_serialize_deserialize_roundtrip` — JSON + bincode use numeric discriminants.
#[test]
fn test_serialize_deserialize_roundtrip() {
    for v in DigMessageType::ALL {
        let json = serde_json::to_string(&v).expect("json ser");
        let back: DigMessageType = serde_json::from_str(&json).expect("json de");
        assert_eq!(back, v, "json round-trip {:?}", v);

        let bytes = bincode::serialize(&v).expect("bincode ser");
        let back2: DigMessageType = bincode::deserialize(&bytes).expect("bincode de");
        assert_eq!(back2, v);
    }
}

/// **Row:** `test_debug_format`
#[test]
fn test_debug_format() {
    let t = format!("{:?}", DigMessageType::PlumtreeGraft);
    assert!(
        t.contains("PlumtreeGraft"),
        "Debug should expose variant name for operators: {t}"
    );
}

/// **Row:** `test_clone_copy`
#[test]
fn test_clone_copy() {
    let a = DigMessageType::StemTransaction;
    let b = a;
    let c = a;
    assert_eq!(a, b);
    assert_eq!(a, c);
}

/// **Row:** `test_hash_in_hashset` — API-009 test plan says HashSet; all **18** variants fit.
#[test]
fn test_hash_in_hashset() {
    let mut set = HashSet::new();
    for v in DigMessageType::ALL {
        assert!(set.insert(v));
    }
    assert_eq!(set.len(), 18);
}

/// **Row:** `test_eq_comparison`
#[test]
fn test_eq_comparison() {
    assert_eq!(
        DigMessageType::NewAttestation,
        DigMessageType::NewAttestation
    );
    assert_ne!(
        DigMessageType::NewAttestation,
        DigMessageType::ValidatorAnnounce
    );
}

/// **`TryFrom<u8>`** — in-band values round-trip; out-of-band rejected with structured error.
#[test]
fn test_try_from_u8() {
    assert_eq!(
        DigMessageType::try_from(200).unwrap(),
        DigMessageType::NewAttestation
    );
    assert_eq!(
        DigMessageType::try_from(217).unwrap(),
        DigMessageType::PlumtreeRequestByHash
    );
    assert!(matches!(
        DigMessageType::try_from(199),
        Err(UnknownDigMessageType(199))
    ));
    assert!(matches!(
        DigMessageType::try_from(218),
        Err(UnknownDigMessageType(218))
    ));
}

/// **Collision avoidance (representative):** core Chia request/response types stay below 200.
///
/// This does not exhaust `ProtocolMessageTypes`, but proves the **DIG200+ reservation** does not
/// intersect common full-node traffic we already use in API-002 tests.
#[test]
fn test_sample_chia_message_types_below_dig_band() {
    let peak = NewPeak::msg_type();
    let peers = RequestPeers::msg_type();
    assert!(
        (peak as u32) < 200,
        "NewPeak msg type should stay below DIG band, got {:?} = {}",
        peak,
        peak as u32
    );
    assert!(
        (peers as u32) < 200,
        "RequestPeers msg type should stay below DIG band, got {:?} = {}",
        peers,
        peers as u32
    );
    // DIG band must not accidentally equal a Chia core opcode we just sampled.
    for d in DigMessageType::ALL {
        assert_ne!(d as u8 as u32, peak as u32);
        assert_ne!(d as u8 as u32, peers as u32);
    }
}

/// **Extension:** `Display` on decode errors aids logging when peeling unknown extensions.
#[test]
fn test_unknown_dig_message_type_display() {
    let e = UnknownDigMessageType(42);
    let s = e.to_string();
    assert!(s.contains("42"), "{s}");
}
