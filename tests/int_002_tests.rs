//! Tests for **INT-002: Broadcast via priority lanes (PriorityOutbound per connection)**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-002.md`
//! - **Master SPEC:** SS8.4
//!
//! INT-002 is satisfied when PriorityOutbound is available per connection and
//! MessagePriority classification works end-to-end.

use dig_gossip::gossip::priority::{MessagePriority, PriorityOutbound};

/// **INT-002: PriorityOutbound can be created per connection.**
#[test]
fn test_priority_outbound_per_connection() {
    let q = PriorityOutbound::new();
    assert!(q.is_empty());
    assert_eq!(q.total_len(), 0);
}

/// **INT-002: MessagePriority classifies Chia types correctly.**
#[test]
fn test_message_priority_classification_chia() {
    use chia_protocol::ProtocolMessageTypes;

    // Critical: NewPeak
    let p = MessagePriority::from_chia_type(ProtocolMessageTypes::NewPeak);
    assert_eq!(p, MessagePriority::Critical);

    // Normal: NewTransaction
    let p = MessagePriority::from_chia_type(ProtocolMessageTypes::NewTransaction);
    assert_eq!(p, MessagePriority::Normal);

    // Bulk: RequestBlocks
    let p = MessagePriority::from_chia_type(ProtocolMessageTypes::RequestBlocks);
    assert_eq!(p, MessagePriority::Bulk);
}

/// **INT-002: MessagePriority classifies DIG extension types correctly.**
#[test]
fn test_message_priority_classification_dig() {
    // NewAttestation (200) = Critical
    assert_eq!(
        MessagePriority::from_dig_type(200),
        MessagePriority::Critical
    );

    // Status (203) = Normal
    assert_eq!(MessagePriority::from_dig_type(203), MessagePriority::Normal);

    // ValidatorAnnounce (208) = Bulk
    assert_eq!(MessagePriority::from_dig_type(208), MessagePriority::Bulk);

    // Plumtree control (214) = Normal
    assert_eq!(MessagePriority::from_dig_type(214), MessagePriority::Normal);
}

/// **INT-002: PriorityOutbound drain order follows PRI-003 (critical > normal > bulk).**
#[test]
fn test_priority_outbound_drain_order() {
    use chia_protocol::{Bytes, Message, ProtocolMessageTypes};

    let mut q = PriorityOutbound::new();

    // Enqueue one of each priority in reverse order
    let bulk_msg = Message {
        msg_type: ProtocolMessageTypes::RequestBlocks,
        id: None,
        data: Bytes::from(vec![3u8]),
    };
    let normal_msg = Message {
        msg_type: ProtocolMessageTypes::NewTransaction,
        id: None,
        data: Bytes::from(vec![2u8]),
    };
    let critical_msg = Message {
        msg_type: ProtocolMessageTypes::NewPeak,
        id: None,
        data: Bytes::from(vec![1u8]),
    };

    q.enqueue(bulk_msg, MessagePriority::Bulk);
    q.enqueue(normal_msg, MessagePriority::Normal);
    q.enqueue(critical_msg, MessagePriority::Critical);

    assert_eq!(q.total_len(), 3);

    // Drain: critical first
    let m1 = q.drain_next().unwrap();
    assert_eq!(m1.data.as_ref(), &[1u8]);

    // Then normal
    let m2 = q.drain_next().unwrap();
    assert_eq!(m2.data.as_ref(), &[2u8]);

    // Then bulk
    let m3 = q.drain_next().unwrap();
    assert_eq!(m3.data.as_ref(), &[3u8]);

    // Empty
    assert!(q.drain_next().is_none());
}

/// **INT-002: lane_lengths returns correct per-lane counts.**
#[test]
fn test_priority_outbound_lane_lengths() {
    use chia_protocol::{Bytes, Message, ProtocolMessageTypes};

    let mut q = PriorityOutbound::new();
    let msg = || Message {
        msg_type: ProtocolMessageTypes::NewPeak,
        id: None,
        data: Bytes::from(vec![0u8]),
    };

    q.enqueue(msg(), MessagePriority::Critical);
    q.enqueue(msg(), MessagePriority::Critical);
    q.enqueue(msg(), MessagePriority::Normal);
    q.enqueue(msg(), MessagePriority::Bulk);
    q.enqueue(msg(), MessagePriority::Bulk);
    q.enqueue(msg(), MessagePriority::Bulk);

    let (c, n, b) = q.lane_lengths();
    assert_eq!(c, 2);
    assert_eq!(n, 1);
    assert_eq!(b, 3);
}
