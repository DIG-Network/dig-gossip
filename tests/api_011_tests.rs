//! Tests for **API-011: [`ExtendedPeerInfo`] and [`VettedPeer`]**.
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`API-011.md`](../docs/requirements/domains/crate_api/specs/API-011.md)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/crate_api/NORMATIVE.md) — API-011
//! - **SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §2.6 (address-manager row), §2.8 (introducer vetting)
//!
//! ## Proof strategy
//!
//! [`ExtendedPeerInfo`] is the Rust port of Chia `address_manager.py:43` — one row in tried/new
//! tables. Tests prove **every field** exists with the types NORMATIVE mandates, including
//! [`PeerInfo`] from **this** crate (API-007) rather than [`dig_gossip::TimestampedPeerInfo`].
//! State rows (new vs tried, `random_pos`, `last_success == 0`) match the semantics table so
//! DSC-001 can embed these structs without reinterpretation.
//!
//! [`VettedPeer`] mirrors `introducer_peers.py:12-28`. Tests prove **derive surface** (`Debug`,
//! `Clone`, `PartialEq`, `Eq`, `Hash`) and **signed `vetted`** so introducer logic can use
//! `HashSet`/`HashMap` keys and represent consecutive successes vs failures (DSC-012 builds on this).

use std::collections::HashSet;

use dig_gossip::{ExtendedPeerInfo, PeerInfo, VettedPeer};

/// Minimal [`PeerInfo`] for tests — host + port only; [`ExtendedPeerInfo::peer_info`] and
/// [`ExtendedPeerInfo::src`] are independent rows in the Python model.
fn peer(host: &str, port: u16) -> PeerInfo {
    PeerInfo {
        host: host.into(),
        port,
    }
}

/// **Row:** `test_extended_peer_info_all_fields` — full struct literal; proves acceptance checklist
/// field list and that values round-trip through public fields.
#[test]
fn test_extended_peer_info_all_fields() {
    let row = ExtendedPeerInfo {
        peer_info: peer("10.0.0.1", 9444),
        timestamp: 1_700_000_000,
        src: peer("10.0.0.2", 9444),
        random_pos: Some(7),
        is_tried: true,
        ref_count: 2,
        last_success: 1_700_000_100,
        last_try: 1_700_000_050,
        num_attempts: 3,
        last_count_attempt: 1_700_000_040,
    };
    assert_eq!(row.peer_info.host, "10.0.0.1");
    assert_eq!(row.peer_info.port, 9444);
    assert_eq!(row.timestamp, 1_700_000_000);
    assert_eq!(row.src.host, "10.0.0.2");
    assert_eq!(row.random_pos, Some(7));
    assert!(row.is_tried);
    assert_eq!(row.ref_count, 2);
    assert_eq!(row.last_success, 1_700_000_100);
    assert_eq!(row.last_try, 1_700_000_050);
    assert_eq!(row.num_attempts, 3);
    assert_eq!(row.last_count_attempt, 1_700_000_040);
}

/// **Row:** `test_extended_peer_info_initial_state` — `is_tried == false`, `ref_count == 0` is the
/// canonical **new-table** row before a successful dial (Python keeps `ref_count` for new buckets).
#[test]
fn test_extended_peer_info_initial_state() {
    let row = ExtendedPeerInfo {
        peer_info: peer("192.168.0.5", 9444),
        timestamp: 0,
        src: peer("192.168.0.1", 9444),
        random_pos: None,
        is_tried: false,
        ref_count: 0,
        last_success: 0,
        last_try: 0,
        num_attempts: 0,
        last_count_attempt: 0,
    };
    assert!(!row.is_tried);
    assert_eq!(row.ref_count, 0);
}

/// **Row:** `test_extended_peer_info_tried_state` — after promotion to tried, `ref_count` is **0**
/// (new-table references are cleared in Chia’s model).
#[test]
fn test_extended_peer_info_tried_state() {
    let row = ExtendedPeerInfo {
        peer_info: peer("203.0.113.10", 9444),
        timestamp: 100,
        src: peer("203.0.113.1", 9444),
        random_pos: Some(0),
        is_tried: true,
        ref_count: 0,
        last_success: 200,
        last_try: 200,
        num_attempts: 1,
        last_count_attempt: 200,
    };
    assert!(row.is_tried);
    assert_eq!(row.ref_count, 0);
}

/// **Row:** `test_extended_peer_info_last_success_zero` — `0` means **never** successfully connected
/// (staleness / eviction use this sentinel like Python).
#[test]
fn test_extended_peer_info_last_success_zero() {
    let row = ExtendedPeerInfo {
        peer_info: peer("198.51.100.7", 9444),
        timestamp: 1,
        src: peer("198.51.100.1", 9444),
        random_pos: None,
        is_tried: false,
        ref_count: 1,
        last_success: 0,
        last_try: 50,
        num_attempts: 2,
        last_count_attempt: 40,
    };
    assert_eq!(row.last_success, 0);
}

/// **Row:** `test_extended_peer_info_random_pos_none` — not yet placed in the O(1) random-order vector.
#[test]
fn test_extended_peer_info_random_pos_none() {
    let row = ExtendedPeerInfo {
        peer_info: peer("example.invalid", 9444),
        timestamp: 0,
        src: peer("10.1.1.1", 9444),
        random_pos: None,
        is_tried: false,
        ref_count: 0,
        last_success: 0,
        last_try: 0,
        num_attempts: 0,
        last_count_attempt: 0,
    };
    assert_eq!(row.random_pos, None);
}

/// **Row:** `test_extended_peer_info_random_pos_some` — index assigned after insertion into random table.
#[test]
fn test_extended_peer_info_random_pos_some() {
    let row = ExtendedPeerInfo {
        peer_info: peer("10.2.2.2", 9444),
        timestamp: 0,
        src: peer("10.3.3.3", 9444),
        random_pos: Some(42),
        is_tried: false,
        ref_count: 0,
        last_success: 0,
        last_try: 0,
        num_attempts: 0,
        last_count_attempt: 0,
    };
    assert_eq!(row.random_pos, Some(42));
}

/// **Row:** `test_extended_peer_info_num_attempts` — monotonic counter field is writable (backoff /
/// [`dig_gossip::MAX_RETRIES`] eviction in DSC-001).
#[test]
fn test_extended_peer_info_num_attempts() {
    let mut row = ExtendedPeerInfo {
        peer_info: peer("10.4.4.4", 9444),
        timestamp: 0,
        src: peer("10.5.5.5", 9444),
        random_pos: None,
        is_tried: false,
        ref_count: 0,
        last_success: 0,
        last_try: 0,
        num_attempts: 0,
        last_count_attempt: 0,
    };
    row.num_attempts += 1;
    row.last_try = 999;
    assert_eq!(row.num_attempts, 1);
    assert_eq!(row.last_try, 999);
}

/// **Proof:** `peer_info` / `src` use [`PeerInfo`] — if this compiled with
/// [`dig_gossip::TimestampedPeerInfo`], the struct literal would fail. Documents API-011 acceptance
/// “not `TimestampedPeerInfo`”.
#[test]
fn test_extended_peer_info_uses_crate_peer_info_not_timestamped() {
    let pi: PeerInfo = peer("127.0.0.1", 9444);
    let row = ExtendedPeerInfo {
        peer_info: pi.clone(),
        timestamp: 0,
        src: pi,
        random_pos: None,
        is_tried: false,
        ref_count: 0,
        last_success: 0,
        last_try: 0,
        num_attempts: 0,
        last_count_attempt: 0,
    };
    let _: PeerInfo = row.peer_info;
    let _: PeerInfo = row.src;
}

/// **Row:** `test_vetted_peer_all_fields`
#[test]
fn test_vetted_peer_all_fields() {
    let p = VettedPeer {
        host: "introducer-peer.example".into(),
        port: 9444,
        vetted: 1,
        vetted_timestamp: 1000,
        last_attempt: 900,
        time_added: 800,
    };
    assert_eq!(p.host, "introducer-peer.example");
    assert_eq!(p.port, 9444);
    assert_eq!(p.vetted, 1);
    assert_eq!(p.vetted_timestamp, 1000);
    assert_eq!(p.last_attempt, 900);
    assert_eq!(p.time_added, 800);
}

/// **Row:** `test_vetted_peer_debug` — `Debug` required for introducer logging (API-011 / STR-003 intent).
#[test]
fn test_vetted_peer_debug() {
    let p = VettedPeer {
        host: "h".into(),
        port: 1,
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    let s = format!("{p:?}");
    assert!(s.contains("VettedPeer"), "{s}");
}

/// **Row:** `test_vetted_peer_clone`
#[test]
fn test_vetted_peer_clone() {
    let a = VettedPeer {
        host: "a".into(),
        port: 9444,
        vetted: 2,
        vetted_timestamp: 1,
        last_attempt: 2,
        time_added: 3,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

/// **Row:** `test_vetted_peer_eq`
#[test]
fn test_vetted_peer_eq() {
    let a = VettedPeer {
        host: "same".into(),
        port: 9444,
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    let b = VettedPeer {
        host: "same".into(),
        port: 9444,
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    assert_eq!(a, b);
}

/// **Row:** `test_vetted_peer_hash` — `Hash` bound compiles and distinguishes keys.
#[test]
fn test_vetted_peer_hash() {
    let mut set = HashSet::new();
    let a = VettedPeer {
        host: "x".into(),
        port: 1,
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    let b = VettedPeer {
        host: "y".into(),
        port: 1,
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    assert!(set.insert(a));
    assert!(set.insert(b));
    assert_eq!(set.len(), 2);
}

/// **Row:** `test_vetted_peer_unvetted` — `vetted == 0`
#[test]
fn test_vetted_peer_unvetted() {
    let p = VettedPeer {
        host: "z".into(),
        port: 9444,
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    assert_eq!(p.vetted, 0);
}

/// **Row:** `test_vetted_peer_success` — positive streak
#[test]
fn test_vetted_peer_success() {
    let p = VettedPeer {
        host: "ok".into(),
        port: 9444,
        vetted: 3,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    assert_eq!(p.vetted, 3);
}

/// **Row:** `test_vetted_peer_failure` — negative streak (API-011: consecutive failures)
#[test]
fn test_vetted_peer_failure() {
    let p = VettedPeer {
        host: "bad".into(),
        port: 9444,
        vetted: -2,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    assert_eq!(p.vetted, -2);
}

/// **Row:** `test_vetted_peer_in_hashset` — multiple unique rows coexist in one set
#[test]
fn test_vetted_peer_in_hashset() {
    let mut set = HashSet::new();
    set.insert(VettedPeer {
        host: "a".into(),
        port: 1,
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    });
    set.insert(VettedPeer {
        host: "b".into(),
        port: 2,
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    });
    assert_eq!(set.len(), 2);
}

/// **Extra:** [`ExtendedPeerInfo`] derives `Debug` / `PartialEq` for test fixtures and logging.
#[test]
fn test_extended_peer_info_debug_and_eq() {
    let a = ExtendedPeerInfo {
        peer_info: peer("10.0.0.1", 9444),
        timestamp: 1,
        src: peer("10.0.0.2", 9444),
        random_pos: None,
        is_tried: false,
        ref_count: 0,
        last_success: 0,
        last_try: 0,
        num_attempts: 0,
        last_count_attempt: 0,
    };
    let b = a.clone();
    assert_eq!(a, b);
    let s = format!("{a:?}");
    assert!(s.contains("ExtendedPeerInfo"), "{s}");
}
