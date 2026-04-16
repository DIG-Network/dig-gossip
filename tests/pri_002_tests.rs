//! Tests for **PRI-002: PriorityOutbound Queue Structure**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/priority/specs/PRI-002.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.4

use chia_protocol::{Message, ProtocolMessageTypes};
use dig_gossip::gossip::priority::{MessagePriority, PriorityOutbound};

fn make_msg(msg_type: ProtocolMessageTypes) -> Message {
    Message {
        msg_type,
        id: None,
        data: vec![].into(),
    }
}

/// **PRI-002: total_len / lane_lengths correct.**
#[test]
fn test_queue_lengths() {
    let mut q = PriorityOutbound::new();
    q.enqueue(
        make_msg(ProtocolMessageTypes::NewPeak),
        MessagePriority::Critical,
    );
    q.enqueue(
        make_msg(ProtocolMessageTypes::NewTransaction),
        MessagePriority::Normal,
    );
    q.enqueue(
        make_msg(ProtocolMessageTypes::RequestBlocks),
        MessagePriority::Bulk,
    );

    assert_eq!(q.total_len(), 3);
    assert_eq!(q.lane_lengths(), (1, 1, 1));
}
