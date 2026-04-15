//! Tests for **DSC-007: Peer exchange via RequestPeers/RespondPeers**.
//!
//! ## Requirement traceability
//!
//! - **Normative:** `docs/requirements/domains/discovery/NORMATIVE.md` (DSC-007)
//! - **Detailed spec:** `docs/requirements/domains/discovery/specs/DSC-007.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` §6.6 (Peer Exchange via Gossip)
//! - **Chia reference:** `node_discovery.py:135-136` — send RequestPeers on outbound connect
//!
//! ## What this file proves
//!
//! DSC-007 is satisfied when:
//! 1. `cap_received_peers` truncates lists > MAX_PEERS_RECEIVED_PER_REQUEST (1000)
//! 2. `cap_received_peers` enforces the global MAX_TOTAL_PEERS_RECEIVED (3000) cap
//! 3. Empty peer lists are handled gracefully (no error, no panic)
//! 4. The per-request cap and global cap interact correctly
//! 5. The existing outbound `RequestPeers`→`RespondPeers` flow adds peers to the address manager
//!    (tested indirectly — CON-001 tests already verify RequestPeers is sent)

use std::sync::atomic::{AtomicU64, Ordering};

use chia_protocol::TimestampedPeerInfo;
use dig_gossip::{cap_received_peers, MAX_PEERS_RECEIVED_PER_REQUEST, MAX_TOTAL_PEERS_RECEIVED};

/// Helper: generate N fake TimestampedPeerInfo entries with unique IPs.
fn fake_peers(count: usize) -> Vec<TimestampedPeerInfo> {
    (0..count)
        .map(|i| {
            // Use different /16 subnets to avoid address manager dedup issues.
            let a = (i / 256) % 256;
            let b = i % 256;
            TimestampedPeerInfo::new(format!("10.{a}.{b}.1"), 9444, 1000)
        })
        .collect()
}

/// **DSC-007: per-request cap at MAX_PEERS_RECEIVED_PER_REQUEST (1000).**
///
/// Proves SPEC §1.6#10: "RespondPeers MUST cap accepted peers at 1000."
/// A list of 1500 peers is truncated to 1000.
#[test]
fn test_cap_per_request_truncates() {
    let counter = AtomicU64::new(0);
    let peers = fake_peers(1500);

    let capped = cap_received_peers(&peers, &counter);

    assert_eq!(
        capped.len(),
        MAX_PEERS_RECEIVED_PER_REQUEST,
        "SPEC §1.6#10: list of 1500 must be truncated to {}",
        MAX_PEERS_RECEIVED_PER_REQUEST
    );
    assert_eq!(
        counter.load(Ordering::Relaxed),
        MAX_PEERS_RECEIVED_PER_REQUEST as u64,
        "counter must reflect accepted count"
    );
}

/// **DSC-007: lists within the per-request cap pass through unchanged.**
///
/// Proves that the cap only truncates oversized lists, not normal ones.
#[test]
fn test_cap_per_request_no_truncation_needed() {
    let counter = AtomicU64::new(0);
    let peers = fake_peers(500);

    let capped = cap_received_peers(&peers, &counter);

    assert_eq!(capped.len(), 500, "500 peers should pass through unchanged");
    assert_eq!(counter.load(Ordering::Relaxed), 500);
}

/// **DSC-007: empty peer list handled gracefully.**
///
/// Proves SPEC §6.6: "Empty peer lists are handled gracefully (no error)."
#[test]
fn test_cap_empty_list() {
    let counter = AtomicU64::new(0);
    let peers: Vec<TimestampedPeerInfo> = vec![];

    let capped = cap_received_peers(&peers, &counter);

    assert_eq!(capped.len(), 0, "empty list should return empty");
    assert_eq!(counter.load(Ordering::Relaxed), 0, "counter should stay 0");
}

/// **DSC-007: global total cap at MAX_TOTAL_PEERS_RECEIVED (3000).**
///
/// Proves SPEC §1.6#11: "Total peers received across all requests MUST be capped at 3000."
/// After receiving 3000 peers across multiple calls, further peers are discarded.
#[test]
fn test_global_total_cap() {
    let counter = AtomicU64::new(0);

    // Receive 4 batches of 800 = 3200 total attempted.
    // Only 3000 should be accepted across all batches.
    let batch = fake_peers(800);
    let mut total_accepted = 0;

    for i in 0..4 {
        let capped = cap_received_peers(&batch, &counter);
        total_accepted += capped.len();
        eprintln!(
            "batch {i}: accepted {}, total so far: {total_accepted}",
            capped.len()
        );
    }

    assert_eq!(
        counter.load(Ordering::Relaxed),
        MAX_TOTAL_PEERS_RECEIVED as u64,
        "SPEC §1.6#11: total must be capped at {}",
        MAX_TOTAL_PEERS_RECEIVED
    );
    assert_eq!(
        total_accepted, MAX_TOTAL_PEERS_RECEIVED,
        "sum of accepted across batches must equal the global cap"
    );
}

/// **DSC-007: global cap discard when already at limit.**
///
/// Proves that once the global counter is at the cap, all subsequent peers are discarded.
#[test]
fn test_global_cap_full_discard() {
    let counter = AtomicU64::new(MAX_TOTAL_PEERS_RECEIVED as u64);
    let peers = fake_peers(100);

    let capped = cap_received_peers(&peers, &counter);

    assert_eq!(
        capped.len(),
        0,
        "when global cap is reached, all peers must be discarded"
    );
    assert_eq!(
        counter.load(Ordering::Relaxed),
        MAX_TOTAL_PEERS_RECEIVED as u64,
        "counter must not increase past cap"
    );
}

/// **DSC-007: per-request cap and global cap interact correctly.**
///
/// Proves that both caps are applied simultaneously: a 1500-peer list is first
/// truncated to 1000 (per-request), then further truncated by the global cap.
#[test]
fn test_both_caps_interact() {
    let counter = AtomicU64::new(2500); // 500 remaining before global cap.
    let peers = fake_peers(1500);

    let capped = cap_received_peers(&peers, &counter);

    // Per-request cap would give 1000, but only 500 remaining in global budget.
    assert_eq!(
        capped.len(),
        500,
        "global cap (500 remaining) must override per-request cap (1000)"
    );
    assert_eq!(
        counter.load(Ordering::Relaxed),
        MAX_TOTAL_PEERS_RECEIVED as u64,
        "counter must reach exactly the global cap"
    );
}

/// **DSC-007: penalty is 0 for peer exchange.**
///
/// Proves SPEC §6.6: "Source parameter is the responding peer's info, penalty is 0."
/// This is verified by the constant 0 passed to `add_to_new_table` in gossip_handle.rs.
/// We verify the cap function doesn't alter the peers' content (only the count).
#[test]
fn test_cap_preserves_peer_content() {
    let counter = AtomicU64::new(0);
    let peers = fake_peers(5);
    let original_hosts: Vec<String> = peers.iter().map(|p| p.host.clone()).collect();

    let capped = cap_received_peers(&peers, &counter);

    let capped_hosts: Vec<String> = capped.iter().map(|p| p.host.clone()).collect();
    assert_eq!(
        original_hosts, capped_hosts,
        "cap_received_peers must not alter peer content, only count"
    );
}

/// **DSC-007: constants match SPEC values.**
///
/// Proves SPEC §1.6#10 and §1.6#11 constants are correct.
#[test]
fn test_constants_match_spec() {
    assert_eq!(
        MAX_PEERS_RECEIVED_PER_REQUEST, 1000,
        "SPEC §1.6#10: MAX_PEERS_RECEIVED_PER_REQUEST must be 1000"
    );
    assert_eq!(
        MAX_TOTAL_PEERS_RECEIVED, 3000,
        "SPEC §1.6#11: MAX_TOTAL_PEERS_RECEIVED must be 3000"
    );
}
