//! Tests for **PRI-004: Starvation Prevention**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/priority/specs/PRI-004.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.4

use dig_gossip::{Message, ProtocolMessageTypes};
use dig_gossip::gossip::priority::{MessagePriority, PriorityOutbound};
use dig_gossip::PRIORITY_STARVATION_RATIO;

fn make_msg(msg_type: ProtocolMessageTypes) -> Message {
    Message {
        msg_type,
        id: None,
        data: vec![].into(),
    }
}

/// **PRI-004: starvation prevention -- bulk gets 1 per RATIO.**
#[test]
fn test_starvation_prevention() {
    let mut q = PriorityOutbound::new();

    // Fill with critical messages + one bulk
    for _ in 0..PRIORITY_STARVATION_RATIO + 1 {
        q.enqueue(
            make_msg(ProtocolMessageTypes::NewPeak),
            MessagePriority::Critical,
        );
    }
    q.enqueue(
        make_msg(ProtocolMessageTypes::RequestBlocks),
        MessagePriority::Bulk,
    );

    // Drain RATIO critical messages
    for _ in 0..PRIORITY_STARVATION_RATIO {
        let m = q.drain_next().unwrap();
        assert_eq!(m.msg_type, ProtocolMessageTypes::NewPeak);
    }

    // Next should be forced bulk (starvation prevention)
    let m = q.drain_next().unwrap();
    assert_eq!(
        m.msg_type,
        ProtocolMessageTypes::RequestBlocks,
        "after {} critical msgs, bulk must be forced",
        PRIORITY_STARVATION_RATIO
    );
}
