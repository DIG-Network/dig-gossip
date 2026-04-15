//! Integration-style tests for **CON-006: connection metrics tracking** on [`PeerConnection`]
//! and aggregation rules aligned with [`GossipStats`](dig_gossip::GossipStats).
//!
//! ## Traceability
//!
//! - **Spec:** [`CON-006.md`](../docs/requirements/domains/connection/specs/CON-006.md) —
//!   Acceptance criteria, §PeerConnection Metric Fields, §Aggregation into GossipStats, Test Plan table.
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/connection/NORMATIVE.md) §CON-006
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §2.4
//!
//! ## Proof strategy
//!
//! Most rows exercise [`PeerConnection::record_message_sent`] / [`PeerConnection::record_message_received`]
//! and [`message_wire_len`](dig_gossip::message_wire_len) directly — these are the primitives the
//! accept loop / [`GossipHandle`](dig_gossip::GossipHandle) use so behaviour stays consistent
//! without booting a full two-node TLS mesh. The aggregation row locks the **sum** contract from
//! CON-006’s `GossipStats` prose via [`aggregate_peer_connection_io`].

mod common;

use std::thread;
use std::time::Duration;

use chia_protocol::{Bytes, Message, ProtocolMessageTypes, RequestPeers};
use chia_traits::Streamable;

use dig_gossip::{aggregate_peer_connection_io, message_wire_len, metric_unix_timestamp_secs};

/// **Row:** `test_metrics_initialization` — new [`PeerConnection`] from the STR-005 harness has
/// counters at zero and timestamps near “now” (CON-006 §Initialization + acceptance checklist).
#[tokio::test]
async fn test_metrics_initialization() {
    let pc = common::mock_peer_connection(false).await;
    let now = metric_unix_timestamp_secs();
    assert_eq!(pc.bytes_read, 0);
    assert_eq!(pc.bytes_written, 0);
    assert_eq!(pc.messages_sent, 0);
    assert_eq!(pc.messages_received, 0);
    assert!(
        pc.creation_time.abs_diff(now) <= 2,
        "creation_time should be Unix seconds near wall clock"
    );
    assert!(
        pc.last_message_time.abs_diff(now) <= 2,
        "last_message_time initialized like creation_time per CON-006"
    );
}

/// **Row:** `test_bytes_written_increment` — three synthetic sends with known wire sizes
/// (CON-006 §Update on Message Send).
#[tokio::test]
async fn test_bytes_written_increment() {
    let mut pc = common::mock_peer_connection(true).await;
    let m = |payload: &[u8]| Message {
        msg_type: ProtocolMessageTypes::Handshake,
        id: None,
        data: Bytes::new(payload.to_vec()),
    };
    let w1 = message_wire_len(&m(&[1, 2, 3])).expect("wire len");
    let w2 = message_wire_len(&m(&[4; 50])).expect("wire len");
    let w3 = message_wire_len(&m(&[])).expect("wire len");
    pc.record_message_sent(w1);
    pc.record_message_sent(w2);
    pc.record_message_sent(w3);
    assert_eq!(pc.messages_sent, 3);
    assert_eq!(pc.bytes_written, w1 + w2 + w3);
}

/// **Row:** `test_messages_sent_increment` — five sends → `messages_sent == 5`.
#[tokio::test]
async fn test_messages_sent_increment() {
    let mut pc = common::mock_peer_connection(true).await;
    for i in 0u8..5 {
        let msg = Message {
            msg_type: ProtocolMessageTypes::Handshake,
            id: None,
            data: Bytes::new(vec![i]),
        };
        let w = message_wire_len(&msg).expect("wire len");
        pc.record_message_sent(w);
    }
    assert_eq!(pc.messages_sent, 5);
}

/// **Row:** `test_bytes_read_increment` — three receives with known sizes.
#[tokio::test]
async fn test_bytes_read_increment() {
    let mut pc = common::mock_peer_connection(false).await;
    let now = metric_unix_timestamp_secs();
    let m = Message {
        msg_type: ProtocolMessageTypes::RequestPeers,
        id: None,
        data: RequestPeers::new().to_bytes().unwrap().into(),
    };
    let w = message_wire_len(&m).expect("wire len");
    pc.record_message_received(w, now);
    pc.record_message_received(w, now);
    pc.record_message_received(w, now);
    assert_eq!(pc.messages_received, 3);
    assert_eq!(pc.bytes_read, w * 3);
}

/// **Row:** `test_messages_received_increment` — five receives.
#[tokio::test]
async fn test_messages_received_increment() {
    let mut pc = common::mock_peer_connection(false).await;
    let now = metric_unix_timestamp_secs();
    let w = 10u64;
    for _ in 0..5 {
        pc.record_message_received(w, now);
    }
    assert_eq!(pc.messages_received, 5);
    assert_eq!(pc.bytes_read, 50);
}

/// **Row:** `test_last_message_time_update` — receive bumps `last_message_time` to supplied “now”.
#[tokio::test]
async fn test_last_message_time_update() {
    let mut pc = common::mock_peer_connection(false).await;
    let t0 = pc.last_message_time;
    thread::sleep(Duration::from_millis(50));
    let now = metric_unix_timestamp_secs();
    pc.record_message_received(8, now);
    assert_eq!(pc.last_message_time, now);
    assert!(pc.last_message_time >= t0);
}

/// **Row:** `test_last_message_time_not_updated_on_send` — sends must not touch `last_message_time`.
#[tokio::test]
async fn test_last_message_time_not_updated_on_send() {
    let mut pc = common::mock_peer_connection(true).await;
    let t0 = pc.last_message_time;
    thread::sleep(Duration::from_millis(50));
    pc.record_message_sent(100);
    assert_eq!(
        pc.last_message_time, t0,
        "CON-006: last_message_time updates on receive only"
    );
}

/// **Row:** `test_creation_time_immutable` — `creation_time` unchanged after mutating counters.
#[tokio::test]
async fn test_creation_time_immutable() {
    let mut pc = common::mock_peer_connection(true).await;
    let c0 = pc.creation_time;
    thread::sleep(Duration::from_secs(1));
    pc.record_message_sent(5);
    pc.record_message_received(7, metric_unix_timestamp_secs());
    assert_eq!(pc.creation_time, c0);
}

/// **Row:** `test_gossip_stats_aggregation` — three synthetic [`PeerConnection`] snapshots sum like
/// CON-006’s `GossipStats` mapping (`bytes_sent` ← sum of `bytes_written`, etc.).
#[tokio::test]
async fn test_gossip_stats_aggregation() {
    let mut a = common::mock_peer_connection(true).await;
    let mut b = common::mock_peer_connection(false).await;
    let mut c = common::mock_peer_connection(true).await;
    a.record_message_sent(100);
    a.record_message_sent(200);
    b.record_message_received(50, 1);
    b.record_message_received(60, 2);
    c.record_message_sent(7);
    c.record_message_received(9, 3);
    let (ms, mr, bw_sum, br_sum) = aggregate_peer_connection_io(&[a, b, c]);
    assert_eq!(ms, 3, "2 sends on A + 1 send on C");
    assert_eq!(mr, 3, "2 recv on B + 1 recv on C");
    assert_eq!(bw_sum, 307, "100+200+7 bytes_written");
    assert_eq!(br_sum, 119, "50+60+9 bytes_read");
}
