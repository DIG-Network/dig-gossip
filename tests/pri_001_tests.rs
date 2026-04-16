//! Tests for **PRI-001 through PRI-008: Priority lanes & backpressure**.
//!
//! SPEC §8.4 (Priority Lanes), §8.5 (Adaptive Backpressure).

use chia_protocol::{Message, ProtocolMessageTypes};
use dig_gossip::gossip::backpressure::{BackpressureConfig, BackpressureLevel, BackpressureState};
use dig_gossip::gossip::priority::{MessagePriority, PriorityOutbound};
use dig_gossip::{
    Bytes32, BACKPRESSURE_BULK_DROP_THRESHOLD, BACKPRESSURE_NORMAL_DELAY_THRESHOLD,
    BACKPRESSURE_TX_DEDUP_THRESHOLD, PRIORITY_STARVATION_RATIO,
};

fn make_msg(msg_type: ProtocolMessageTypes) -> Message {
    Message {
        msg_type,
        id: None,
        data: vec![].into(),
    }
}

fn test_tx_id(n: u8) -> Bytes32 {
    let mut b = [0u8; 32];
    b[0] = n;
    Bytes32::from(b)
}

// ===================== PRI-001: MessagePriority =====================

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

// ===================== PRI-002/003: PriorityOutbound =====================

/// **PRI-003: drain order is critical → normal → bulk.**
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
    assert_eq!(m1.msg_type, ProtocolMessageTypes::NewPeak);

    // Normal second
    let m2 = q.drain_next().unwrap();
    assert_eq!(m2.msg_type, ProtocolMessageTypes::NewTransaction);

    // Bulk last
    let m3 = q.drain_next().unwrap();
    assert_eq!(m3.msg_type, ProtocolMessageTypes::RequestBlocks);

    assert!(q.is_empty());
}

/// **PRI-004: starvation prevention — bulk gets 1 per RATIO.**
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

// ===================== PRI-005: BackpressureConfig =====================

/// **PRI-005: default thresholds match SPEC.**
#[test]
fn test_backpressure_config_defaults() {
    let c = BackpressureConfig::default();
    assert_eq!(c.tx_dedup_threshold, BACKPRESSURE_TX_DEDUP_THRESHOLD);
    assert_eq!(c.bulk_drop_threshold, BACKPRESSURE_BULK_DROP_THRESHOLD);
    assert_eq!(
        c.normal_delay_threshold,
        BACKPRESSURE_NORMAL_DELAY_THRESHOLD
    );
}

/// **PRI-005: constants match SPEC.**
#[test]
fn test_backpressure_constants() {
    assert_eq!(BACKPRESSURE_TX_DEDUP_THRESHOLD, 25);
    assert_eq!(BACKPRESSURE_BULK_DROP_THRESHOLD, 50);
    assert_eq!(BACKPRESSURE_NORMAL_DELAY_THRESHOLD, 100);
    assert_eq!(PRIORITY_STARVATION_RATIO, 10);
}

// ===================== PRI-006/007/008: Backpressure levels =====================

/// **PRI-005: level transitions at correct thresholds.**
#[test]
fn test_backpressure_levels() {
    let config = BackpressureConfig::default();

    assert_eq!(
        BackpressureLevel::from_depth(0, &config),
        BackpressureLevel::Normal
    );
    assert_eq!(
        BackpressureLevel::from_depth(24, &config),
        BackpressureLevel::Normal
    );
    assert_eq!(
        BackpressureLevel::from_depth(25, &config),
        BackpressureLevel::TxDedup
    );
    assert_eq!(
        BackpressureLevel::from_depth(49, &config),
        BackpressureLevel::TxDedup
    );
    assert_eq!(
        BackpressureLevel::from_depth(50, &config),
        BackpressureLevel::BulkDrop
    );
    assert_eq!(
        BackpressureLevel::from_depth(99, &config),
        BackpressureLevel::BulkDrop
    );
    assert_eq!(
        BackpressureLevel::from_depth(100, &config),
        BackpressureLevel::NormalDelay
    );
    assert_eq!(
        BackpressureLevel::from_depth(1000, &config),
        BackpressureLevel::NormalDelay
    );
}

/// **PRI-006: tx dedup — first tx_id passes, duplicate suppressed.**
#[test]
fn test_tx_dedup() {
    let mut state = BackpressureState::new(BackpressureConfig::default());
    let tx = test_tx_id(1);

    // Below threshold: all pass
    assert!(state.should_send_tx(&tx, 10));
    assert!(state.should_send_tx(&tx, 10));

    // At threshold: first passes, duplicate suppressed
    assert!(state.should_send_tx(&test_tx_id(2), 30)); // new tx
    assert!(!state.should_send_tx(&test_tx_id(2), 30)); // duplicate
}

/// **PRI-007: bulk drop at threshold.**
#[test]
fn test_bulk_drop() {
    let state = BackpressureState::new(BackpressureConfig::default());

    assert!(!state.should_drop_bulk(49));
    assert!(state.should_drop_bulk(50));
    assert!(state.should_drop_bulk(100));
}

/// **PRI-008: normal delay at threshold.**
#[test]
fn test_normal_delay() {
    let state = BackpressureState::new(BackpressureConfig::default());

    assert!(!state.should_delay_normal(99));
    assert!(state.should_delay_normal(100));
    assert!(state.should_delay_normal(500));
}
