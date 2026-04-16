//! Tests for **DSC-012: IntroducerPeers/VettedPeer tracking (vetting state machine)**.
//!
//! ## Requirement traceability
//!
//! - **Normative:** `docs/requirements/domains/discovery/NORMATIVE.md` (DSC-012)
//! - **Spec:** `docs/requirements/domains/discovery/specs/DSC-012.md`
//! - **Master SPEC:** §2.8, §1.6#9
//! - **Chia:** `introducer_peers.py:12-77`
//!
//! ## What this file proves
//!
//! DSC-012 is satisfied when:
//! 1. IntroducerPeers tracks peers with add/remove
//! 2. VettedPeer vetting state: 0=unvetted, positive=success, negative=failure
//! 3. record_success increments (resets from negative to 1)
//! 4. record_failure decrements (resets from positive to -1)
//! 5. get_vetted_peers returns only vetted > 0
//! 6. Hash/Eq on (host, port) only — vetting state changes don't affect set membership

use dig_gossip::{IntroducerPeers, VettedPeer};

/// **DSC-012: add peer to set.**
#[test]
fn test_add_peer() {
    let mut peers = IntroducerPeers::new();
    assert!(peers.is_empty());

    let added = peers.add("10.0.0.1".to_string(), 9444);
    assert!(added, "first add should return true");
    assert_eq!(peers.len(), 1);
}

/// **DSC-012: add duplicate returns false.**
#[test]
fn test_add_duplicate() {
    let mut peers = IntroducerPeers::new();
    peers.add("10.0.0.1".to_string(), 9444);

    let added = peers.add("10.0.0.1".to_string(), 9444);
    assert!(!added, "duplicate add should return false");
    assert_eq!(peers.len(), 1);
}

/// **DSC-012: port 0 rejected.**
#[test]
fn test_add_port_zero_rejected() {
    let mut peers = IntroducerPeers::new();
    let added = peers.add("10.0.0.1".to_string(), 0);
    assert!(!added, "port 0 should be rejected");
    assert!(peers.is_empty());
}

/// **DSC-012: remove peer.**
#[test]
fn test_remove_peer() {
    let mut peers = IntroducerPeers::new();
    peers.add("10.0.0.1".to_string(), 9444);

    let removed = peers.remove("10.0.0.1", 9444);
    assert!(removed);
    assert!(peers.is_empty());
}

/// **DSC-012: remove nonexistent returns false.**
#[test]
fn test_remove_nonexistent() {
    let mut peers = IntroducerPeers::new();
    let removed = peers.remove("10.0.0.1", 9444);
    assert!(!removed);
}

/// **DSC-012: initial vetting state is 0 (unvetted).**
///
/// Proves SPEC §2.8: "0 = not yet vetted."
#[test]
fn test_initial_vetted_zero() {
    let mut peers = IntroducerPeers::new();
    peers.add("10.0.0.1".to_string(), 9444);

    let all = peers.all_peers();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].vetted, 0, "initial vetting must be 0 (unvetted)");
}

/// **DSC-012: record_success increments vetted.**
///
/// Proves SPEC §2.8: "positive = consecutive successful probe count."
#[test]
fn test_record_success_increments() {
    let mut peers = IntroducerPeers::new();
    peers.add("10.0.0.1".to_string(), 9444);

    peers.record_success("10.0.0.1", 9444);
    let all = peers.all_peers();
    assert_eq!(all[0].vetted, 1);

    peers.record_success("10.0.0.1", 9444);
    let all = peers.all_peers();
    assert_eq!(all[0].vetted, 2);
}

/// **DSC-012: record_failure decrements vetted.**
///
/// Proves SPEC §2.8: "negative = consecutive failures."
#[test]
fn test_record_failure_decrements() {
    let mut peers = IntroducerPeers::new();
    peers.add("10.0.0.1".to_string(), 9444);

    peers.record_failure("10.0.0.1", 9444);
    let all = peers.all_peers();
    assert_eq!(all[0].vetted, -1);

    peers.record_failure("10.0.0.1", 9444);
    let all = peers.all_peers();
    assert_eq!(all[0].vetted, -2);
}

/// **DSC-012: success after failure resets to 1.**
///
/// Proves state machine: negative → success resets to 1 (not increments from negative).
#[test]
fn test_success_after_failure_resets() {
    let mut peers = IntroducerPeers::new();
    peers.add("10.0.0.1".to_string(), 9444);

    peers.record_failure("10.0.0.1", 9444);
    peers.record_failure("10.0.0.1", 9444);
    // vetted = -2

    peers.record_success("10.0.0.1", 9444);
    let all = peers.all_peers();
    assert_eq!(all[0].vetted, 1, "success after failure must reset to 1");
}

/// **DSC-012: failure after success resets to -1.**
///
/// Proves state machine: positive → failure resets to -1.
#[test]
fn test_failure_after_success_resets() {
    let mut peers = IntroducerPeers::new();
    peers.add("10.0.0.1".to_string(), 9444);

    peers.record_success("10.0.0.1", 9444);
    peers.record_success("10.0.0.1", 9444);
    // vetted = 2

    peers.record_failure("10.0.0.1", 9444);
    let all = peers.all_peers();
    assert_eq!(all[0].vetted, -1, "failure after success must reset to -1");
}

/// **DSC-012: get_vetted_peers returns only positive.**
///
/// Proves only peers with vetted > 0 are shared with querying nodes.
#[test]
fn test_get_vetted_peers() {
    let mut peers = IntroducerPeers::new();
    peers.add("10.0.0.1".to_string(), 9444);
    peers.add("10.0.0.2".to_string(), 9444);
    peers.add("10.0.0.3".to_string(), 9444);

    peers.record_success("10.0.0.1", 9444); // vetted = 1 ✓
                                            // 10.0.0.2 stays 0 (unvetted) ✗
    peers.record_failure("10.0.0.3", 9444); // vetted = -1 ✗

    let vetted = peers.get_vetted_peers();
    assert_eq!(vetted.len(), 1);
    assert_eq!(vetted[0].host, "10.0.0.1");
}

/// **DSC-012: Hash/Eq by (host, port) — vetting state doesn't affect identity.**
///
/// Proves VettedPeer equality is by address only (Chia introducer_peers.py:29-30).
#[test]
fn test_vetted_peer_eq_by_address() {
    let a = VettedPeer {
        host: "10.0.0.1".to_string(),
        port: 9444,
        vetted: 5,
        vetted_timestamp: 100,
        last_attempt: 200,
        time_added: 50,
    };
    let b = VettedPeer {
        host: "10.0.0.1".to_string(),
        port: 9444,
        vetted: -3,          // different
        vetted_timestamp: 0, // different
        last_attempt: 0,     // different
        time_added: 0,       // different
    };
    assert_eq!(a, b, "VettedPeer equality must be by (host, port) only");
}
