//! Tests for **PRI-001: MessagePriority Enum**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/priority/specs/PRI-001.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.4

use chia_protocol::ProtocolMessageTypes;
use dig_gossip::gossip::priority::MessagePriority;

/// **PRI-001: NewPeak is Critical.**
#[test]
fn test_new_peak_critical() {
    assert_eq!(
        MessagePriority::from_chia_type(ProtocolMessageTypes::NewPeak),
        MessagePriority::Critical
    );
}

/// **PRI-001: NewTransaction is Normal.**
#[test]
fn test_new_transaction_normal() {
    assert_eq!(
        MessagePriority::from_chia_type(ProtocolMessageTypes::NewTransaction),
        MessagePriority::Normal
    );
}

/// **PRI-001: RequestBlocks is Bulk.**
#[test]
fn test_request_blocks_bulk() {
    assert_eq!(
        MessagePriority::from_chia_type(ProtocolMessageTypes::RequestBlocks),
        MessagePriority::Bulk
    );
}

/// **PRI-001: DIG attestation (200) is Critical.**
#[test]
fn test_dig_attestation_critical() {
    assert_eq!(
        MessagePriority::from_dig_type(200),
        MessagePriority::Critical
    );
}
