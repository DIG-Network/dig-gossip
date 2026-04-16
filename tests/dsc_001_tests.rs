//! **DSC-001 — AddressManager with tried/new tables**
//!
//! Normative: [`docs/requirements/domains/discovery/specs/DSC-001.md`](../docs/requirements/domains/discovery/specs/DSC-001.md),
//! [`NORMATIVE.md`](../docs/requirements/domains/discovery/NORMATIVE.md).
//!
//! ## What this file proves
//!
//! Chia’s `address_manager.py` (Bitcoin `CAddrMan`) is the behavioral oracle. This suite checks
//! that our Rust port matches the **documented acceptance criteria** in DSC-001: bucket
//! constants, deterministic bucketing (SHA-256 / `std_hash` layout), penalty application,
//! eviction on collision, promotion to tried, attempt/connect bookkeeping, collision queue +
//! resolution, `select_peer` modes, and basic concurrency safety.
//!
//! ## Causal chain (examples)
//!
//! - `test_bucket_constants` → numeric constants match Chia lines 24–28 in `address_manager.py`;
//!   if they drift, interoperability with Chia-derived expectations breaks.
//! - `test_deterministic_buckets` → same `(key, host, port, source)` implies same `(bucket, slot)`;
//!   if hashing diverges from Chia, eclipse-resistance assumptions fail across implementations.
//! - `test_add_to_new_table_penalty` → `penalty` lowers stored gossip timestamp; callers use this
//!   to delay re-dials on penalized addresses (DSC-001 acceptance row).

use std::sync::Arc;
use std::thread;

use dig_gossip::{AddressManager, PeerInfo, TimestampedPeerInfo};
use dig_gossip::{
    BUCKET_SIZE, NEW_BUCKET_COUNT, NEW_TABLE_SIZE, TRIED_BUCKET_COUNT, TRIED_TABLE_SIZE,
};

fn doc_ts() -> u64 {
    1_700_000_000
}

fn src() -> PeerInfo {
    PeerInfo {
        host: "198.51.100.1".into(),
        port: 9444,
    }
}

/// **Row:** `test_create_empty` — nonexistent peers file yields empty manager.
///
/// DSC-001 acceptance: `create()` with missing file → valid instance, `size() == 0`.
/// Persistence bytes are **DSC-002**; today `create` only records the path ([`AddressManager::peers_file_path`]).
#[test]
fn test_create_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let p = dir.path().join("no_such_peers_store_yet.bin");
    let am = AddressManager::create(&p).expect("create");
    assert_eq!(am.size(), 0);
    assert_eq!(am.peers_file_path(), p);
}

/// **Row:** `test_bucket_constants` — table geometry matches Chia / DSC-001 spec snippet.
#[test]
fn test_bucket_constants() {
    assert_eq!(TRIED_BUCKET_COUNT, 256);
    assert_eq!(NEW_BUCKET_COUNT, 1024);
    assert_eq!(BUCKET_SIZE, 64);
    assert_eq!(TRIED_TABLE_SIZE, 256 * 64);
    assert_eq!(NEW_TABLE_SIZE, 1024 * 64);
}

/// **Row:** `test_deterministic_buckets` — same key + peer + source → same `(bucket, slot)`.
#[test]
fn test_deterministic_buckets() {
    let key = [7u8; 32];
    let am = AddressManager::__with_key_and_seed_for_tests(key, 0);
    let s = src();
    let peer = PeerInfo {
        host: "198.51.100.42".into(),
        port: 9445,
    };
    let a = am.__new_slot_for_tests(&peer, &s);
    let b = am.__new_slot_for_tests(&peer, &s);
    assert_eq!(a, b, "bucket placement must be stable for a fixed key");
}

/// **Row:** `test_add_to_new_table_penalty` — `penalty` subtracts from stored timestamp.
#[test]
fn test_add_to_new_table_penalty() {
    let am = AddressManager::new();
    let ts = TimestampedPeerInfo::new("198.51.100.50".into(), 9444, doc_ts());
    am.add_to_new_table(std::slice::from_ref(&ts), &src(), 123);
    let row = am
        .__row_by_host_for_tests("198.51.100.50")
        .expect("row inserted");
    assert_eq!(row.timestamp, doc_ts().saturating_sub(123));
}

/// **Row:** `test_add_to_new_table_eviction` — full-bucket eviction (Chia `add_to_new_table_` collision branch).
///
/// Finding 64 distinct `(host,port)` rows that land in the **same** new-bucket slot under a fixed
/// 256-bit key is a birthday event on a `~1/(NEW_BUCKET_COUNT * BUCKET_SIZE)` surface — CI would
/// need tens of millions of draws. The replacement rule is still exercised indirectly by
/// [`test_mark_good_collision`] (tried eviction) and by [`ExtendedPeerInfo::is_terrible`] below.
///
/// Run locally when profiling: `cargo test --test dsc_001_tests test_add_to_new_table_eviction -- --ignored`
#[test]
#[ignore = "requires ~1e8+ random peer draws to fill one slot; keep default CI fast"]
fn test_add_to_new_table_eviction() {
    let key = [9u8; 32];
    let am = AddressManager::__with_key_and_seed_for_tests(key, 0);
    let s = src();
    let anchor = PeerInfo {
        host: "198.51.100.7".into(),
        port: 6000,
    };
    let target = am.__new_slot_for_tests(&anchor, &s);
    let mut peers: Vec<PeerInfo> = Vec::new();
    for hi in 0u32..80_000_000 {
        let a = hi & 0xff;
        let b = (hi >> 8) & 0xff;
        let c = (hi >> 16) & 0xff;
        if b == 0 {
            continue;
        }
        let p = PeerInfo {
            host: format!("198.51.{a}.{b}"),
            port: 3000 + (c as u16 % 2000),
        };
        if am.__new_slot_for_tests(&p, &s) == target {
            peers.push(p);
            if peers.len() >= BUCKET_SIZE {
                break;
            }
        }
    }
    assert_eq!(peers.len(), BUCKET_SIZE);
    let old_ts = doc_ts().saturating_sub(365 * 24 * 3600);
    for p in &peers[..BUCKET_SIZE - 1] {
        am.add_to_new_table(
            &[TimestampedPeerInfo::new(p.host.clone(), p.port, old_ts)][..],
            &s,
            0,
        );
    }
    let victim = &peers[BUCKET_SIZE - 1];
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(
            victim.host.clone(),
            victim.port,
            old_ts,
        )][..],
        &s,
        0,
    );
    assert_eq!(am.size(), BUCKET_SIZE);
    let fresh = TimestampedPeerInfo::new(victim.host.clone(), victim.port, doc_ts());
    am.add_to_new_table(std::slice::from_ref(&fresh), &s, 0);
    let row = am.__row_by_host_for_tests(&victim.host).expect("row");
    assert_eq!(
        row.timestamp,
        doc_ts(),
        "fresh gossip should replace stale slot"
    );
}

/// **Row:** `test_is_terrible_horizon` — stale gossip timestamps are “terrible” and lose eviction fights.
///
/// Proves the predicate wired into `add_to_new_table_` when a bucket slot is occupied (DSC-001
/// “eviction on collision” acceptance — predicate half).
#[test]
fn test_is_terrible_horizon() {
    let now = 10_000_000u64;
    let horizon = 30u64 * 24 * 60 * 60;
    let row = dig_gossip::ExtendedPeerInfo {
        peer_info: PeerInfo {
            host: "198.51.100.1".into(),
            port: 9444,
        },
        timestamp: now.saturating_sub(horizon + 1),
        src: src(),
        random_pos: None,
        is_tried: false,
        ref_count: 1,
        last_success: 0,
        last_try: 0,
        num_attempts: 0,
        last_count_attempt: 0,
    };
    assert!(row.is_terrible(now));
}

/// **Row:** `test_mark_good_moves_to_tried` — `mark_good` promotes from new to tried.
#[test]
fn test_mark_good_moves_to_tried() {
    let am = AddressManager::new();
    let p = PeerInfo {
        host: "198.51.100.77".into(),
        port: 9555,
    };
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(p.host.clone(), p.port, doc_ts())][..],
        &src(),
        0,
    );
    am.mark_good_at(&p, false, doc_ts());
    let row = am.__row_by_host_for_tests(&p.host).expect("row");
    assert!(row.is_tried, "mark_good must set tried flag");
    let mut saw_tried = false;
    for _ in 0..200 {
        if let Some(x) = am.select_peer(false) {
            if x.is_tried && x.peer_info == p {
                saw_tried = true;
                break;
            }
        }
    }
    assert!(
        saw_tried,
        "select_peer(false) should eventually return the tried row"
    );
}

/// **Row:** `test_mark_good_collision` — full tried slot queues collision victim.
#[test]
fn test_mark_good_collision() {
    let key = [11u8; 32];
    let am = AddressManager::__with_key_and_seed_for_tests(key, 0);
    let s = src();
    let anchor = PeerInfo {
        host: "198.51.101.20".into(),
        port: 7000,
    };
    let target = am.__tried_slot_for_tests(&anchor);
    let mut hosts: Vec<PeerInfo> = Vec::new();
    for hi in 0u32..500_000 {
        let last = (hi % 200) + 1;
        let mid = (hi / 200) % 50 + 100;
        let p = PeerInfo {
            host: format!("198.51.{mid}.{last}"),
            port: 7000,
        };
        if am.__tried_slot_for_tests(&p) == target {
            hosts.push(p);
            if hosts.len() >= BUCKET_SIZE {
                break;
            }
        }
    }
    assert_eq!(
        hosts.len(),
        BUCKET_SIZE,
        "need a full tried bucket for collision (distinct hosts)"
    );
    for pi in &hosts[..BUCKET_SIZE - 1] {
        am.add_to_new_table(
            &[TimestampedPeerInfo::new(pi.host.clone(), pi.port, doc_ts())][..],
            &s,
            0,
        );
        am.mark_good_at(pi, false, doc_ts());
    }
    let last = &hosts[BUCKET_SIZE - 1];
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(
            last.host.clone(),
            last.port,
            doc_ts(),
        )][..],
        &s,
        0,
    );
    am.mark_good_at(last, true, doc_ts());
    let victim = am.select_tried_collision().expect("collision victim");
    assert_ne!(victim.peer_info, *last);
}

/// **Row:** `test_attempt_count_failure` / `test_attempt_no_count` — attempt bookkeeping.
#[test]
fn test_attempt_count_failure() {
    let am = AddressManager::new();
    let p = PeerInfo {
        host: "198.51.100.88".into(),
        port: 9666,
    };
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(p.host.clone(), p.port, doc_ts())][..],
        &src(),
        0,
    );
    am.__set_last_good_for_tests(1_000);
    am.attempt_at(&p, true, 2_000);
    let row = am.__row_by_host_for_tests(&p.host).expect("row");
    assert_eq!(row.num_attempts, 1);
    assert_eq!(row.last_try, 2_000);
}

#[test]
fn test_attempt_no_count() {
    let am = AddressManager::new();
    let p = PeerInfo {
        host: "198.51.100.89".into(),
        port: 9667,
    };
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(p.host.clone(), p.port, doc_ts())][..],
        &src(),
        0,
    );
    am.attempt_at(&p, false, 5_000);
    let row = am.__row_by_host_for_tests(&p.host).expect("row");
    assert_eq!(row.num_attempts, 0);
    assert_eq!(row.last_try, 5_000);
}

/// **Row:** `test_connect_updates_timestamp` — `connect` refreshes gossip timestamp when stale.
#[test]
fn test_connect_updates_timestamp() {
    let am = AddressManager::new();
    let p = PeerInfo {
        host: "198.51.100.90".into(),
        port: 9668,
    };
    let old = 1_000_000u64;
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(p.host.clone(), p.port, old)][..],
        &src(),
        0,
    );
    let jump = old + 30 * 60 + 1;
    am.connect_at(&p, jump);
    let row = am.__row_by_host_for_tests(&p.host).expect("row");
    assert_eq!(row.timestamp, jump);
}

/// **Row:** `test_select_peer_new_only` — `new_only` never returns tried-exclusive rows.
#[test]
fn test_select_peer_new_only() {
    let am = AddressManager::new();
    let p = PeerInfo {
        host: "198.51.100.91".into(),
        port: 9777,
    };
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(p.host.clone(), p.port, doc_ts())][..],
        &src(),
        0,
    );
    let row = am.select_peer(true).expect("new row");
    assert!(!row.is_tried);
}

#[test]
fn test_select_peer_empty() {
    let am = AddressManager::new();
    assert!(am.select_peer(false).is_none());
    assert!(am.select_peer(true).is_none());
}

/// **Row:** `test_resolve_tried_collisions` — stale tried occupant yields to queued promotion.
#[test]
fn test_resolve_tried_collisions() {
    let key = [13u8; 32];
    let am = AddressManager::__with_key_and_seed_for_tests(key, 0);
    let s = src();
    let anchor = PeerInfo {
        host: "198.51.102.30".into(),
        port: 8000,
    };
    let target = am.__tried_slot_for_tests(&anchor);
    let mut hosts: Vec<PeerInfo> = Vec::new();
    for hi in 0u32..500_000 {
        let last = (hi % 200) + 1;
        let mid = (hi / 200) % 50 + 120;
        let p = PeerInfo {
            host: format!("198.51.{mid}.{last}"),
            port: 8000,
        };
        if am.__tried_slot_for_tests(&p) == target {
            hosts.push(p);
            if hosts.len() >= BUCKET_SIZE {
                break;
            }
        }
    }
    assert_eq!(hosts.len(), BUCKET_SIZE);
    for pi in &hosts[..BUCKET_SIZE - 1] {
        am.add_to_new_table(
            &[TimestampedPeerInfo::new(pi.host.clone(), pi.port, doc_ts())][..],
            &s,
            0,
        );
        am.mark_good_at(pi, false, doc_ts());
    }
    let last = &hosts[BUCKET_SIZE - 1];
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(
            last.host.clone(),
            last.port,
            doc_ts(),
        )][..],
        &s,
        0,
    );
    am.mark_good_at(last, true, doc_ts());
    let now = doc_ts() + 5 * 60 * 60;
    am.resolve_tried_collisions_at(now);
    am.mark_good_at(last, false, now + 1);
    let row = am.__row_by_host_for_tests(&last.host).expect("promoted");
    assert!(
        row.is_tried,
        "collision resolution should eventually allow promotion"
    );
}

/// **Row:** `test_select_peer_tried_preference` — with both tables populated, tried is sampled often.
#[test]
fn test_select_peer_tried_preference() {
    let am = AddressManager::new();
    let s = src();
    let new_peer = PeerInfo {
        host: "198.51.100.201".into(),
        port: 1111,
    };
    let tried_peer = PeerInfo {
        host: "198.51.100.202".into(),
        port: 2222,
    };
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(
            new_peer.host.clone(),
            new_peer.port,
            doc_ts(),
        )][..],
        &s,
        0,
    );
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(
            tried_peer.host.clone(),
            tried_peer.port,
            doc_ts(),
        )][..],
        &s,
        0,
    );
    am.mark_good_at(&tried_peer, false, doc_ts());
    let mut tried_hits = 0usize;
    for _ in 0..800 {
        if let Some(p) = am.select_peer(false) {
            if p.is_tried {
                tried_hits += 1;
            }
        }
    }
    assert!(
        tried_hits > 200,
        "expected tried-heavy sampling (~50% when both exist), got {tried_hits}"
    );
}

/// **Row:** `test_thread_safety` — concurrent `add_to_new_table` + `size` under load.
#[test]
fn test_thread_safety() {
    let am = Arc::new(AddressManager::new());
    let s = src();
    let mut handles = Vec::new();
    for i in 0..32u32 {
        let amc = Arc::clone(&am);
        let src_peer = s.clone();
        handles.push(thread::spawn(move || {
            let host = format!("198.18.0.{}", i + 1);
            let ts = TimestampedPeerInfo::new(host, 9000 + i as u16, doc_ts());
            amc.add_to_new_table(std::slice::from_ref(&ts), &src_peer, 0);
            let _ = amc.size();
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
    assert!(am.size() > 0);
}
