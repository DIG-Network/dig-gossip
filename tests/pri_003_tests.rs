//! Tests for **PRI-003: Drain Order**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/priority/specs/PRI-003.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.4

use dig_gossip::gossip::priority::{MessagePriority, PriorityOutbound};
use dig_gossip::{DigMessage, ProtocolMessageTypes};

fn make_msg(msg_type: ProtocolMessageTypes) -> DigMessage {
    DigMessage {
        msg_type: msg_type as u8,
        id: None,
        data: vec![].into(),
    }
}

/// **PRI-003: drain order is critical -> normal -> bulk.**
#[test]
fn test_drain_order() {
    let mut q = PriorityOutbound::new();

    q.enqueue(
        make_msg(ProtocolMessageTypes::RequestBlocks),
        MessagePriority::Bulk,
    ); // RequestBlocks
    q.enqueue(
        make_msg(ProtocolMessageTypes::NewTransaction),
        MessagePriority::Normal,
    ); // NewTransaction
    q.enqueue(
        make_msg(ProtocolMessageTypes::NewPeak),
        MessagePriority::Critical,
    ); // NewPeak

    // Critical first
    let m1 = q.drain_next().unwrap();
    assert_eq!(m1.msg_type, ProtocolMessageTypes::NewPeak as u8);

    // Normal second
    let m2 = q.drain_next().unwrap();
    assert_eq!(m2.msg_type, ProtocolMessageTypes::NewTransaction as u8);

    // Bulk last
    let m3 = q.drain_next().unwrap();
    assert_eq!(m3.msg_type, ProtocolMessageTypes::RequestBlocks as u8);

    assert!(q.is_empty());
}
