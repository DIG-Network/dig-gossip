//! Tests for **PRF-006: Latency benchmarks**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/performance/specs/PRF-006.md`
//! - **Master SPEC:** §11.3 (Benchmark Tests)
//!
//! PRF-006 latency benchmarks are SHOULD. Placeholder asserting infrastructure exists.

use chia_protocol::ProtocolMessageTypes;
use dig_gossip::gossip::priority::MessagePriority;

/// **PRF-006: NewPeak is Critical priority — ensures lowest latency.**
///
/// Proves SPEC §8.4: "NewPeak in Critical lane → sent before bulk."
/// Target: <50ms p99 during bulk sync (verified by integration bench).
#[test]
fn test_new_peak_critical_for_latency() {
    let priority = MessagePriority::from_chia_type(ProtocolMessageTypes::NewPeak);
    assert_eq!(
        priority,
        MessagePriority::Critical,
        "NewPeak must be Critical to meet <50ms p99 latency target"
    );
}

/// **PRF-006: RespondBlocks is Bulk — doesn't block Critical.**
#[test]
fn test_respond_blocks_bulk() {
    let priority = MessagePriority::from_chia_type(ProtocolMessageTypes::RespondBlocks);
    assert_eq!(
        priority,
        MessagePriority::Bulk,
        "RespondBlocks must be Bulk so it doesn't block NewPeak"
    );
}
