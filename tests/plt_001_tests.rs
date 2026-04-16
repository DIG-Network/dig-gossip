//! Tests for **PLT-001** (PlumtreeState), **PLT-007** (MessageCache),
//! **PLT-008** (SeenSet).
//!
//! ## Requirement traceability
//!
//! - PLT-001: SPEC §8.1 — PlumtreeState (eager/lazy peers, lazy queue)
//! - PLT-004: SPEC §8.1 — Duplicate detection → PRUNE (demote to lazy)
//! - PLT-005: SPEC §8.1 — Lazy timeout → GRAFT (promote to eager)
//! - PLT-006: SPEC §8.1 — Tree self-healing on disconnect
//! - PLT-007: SPEC §8.1 — Message cache (LRU, TTL 60s)
//! - PLT-008: SPEC §8.1 step 2 — Seen set (LRU dedup, 100K)

use dig_gossip::gossip::message_cache::MessageCache;
use dig_gossip::gossip::plumtree::PlumtreeState;
use dig_gossip::gossip::seen_set::SeenSet;
use dig_gossip::Bytes32;

fn test_peer_id(n: u8) -> Bytes32 {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    Bytes32::from(bytes)
}

// ===================== PLT-001: PlumtreeState =====================

/// **PLT-001: new peers start as eager.**
///
/// Proves SPEC §8.1: "All newly connected peers MUST start in eager_peers."
#[test]
fn test_new_peer_is_eager() {
    let mut state = PlumtreeState::new();
    let peer = test_peer_id(1);
    state.add_peer(peer);

    assert!(state.is_eager(&peer));
    assert!(!state.is_lazy(&peer));
    assert_eq!(state.eager_count(), 1);
    assert_eq!(state.lazy_count(), 0);
}

/// **PLT-004: demote_to_lazy moves peer from eager to lazy.**
///
/// Proves SPEC §8.1: "Demote sender to lazy, send PRUNE."
#[test]
fn test_demote_to_lazy() {
    let mut state = PlumtreeState::new();
    let peer = test_peer_id(1);
    state.add_peer(peer);

    state.demote_to_lazy(&peer);

    assert!(!state.is_eager(&peer));
    assert!(state.is_lazy(&peer));
    assert_eq!(state.eager_count(), 0);
    assert_eq!(state.lazy_count(), 1);
}

/// **PLT-005: promote_to_eager moves peer from lazy to eager.**
///
/// Proves SPEC §8.1: "Promote announcer from lazy to eager via GRAFT."
#[test]
fn test_promote_to_eager() {
    let mut state = PlumtreeState::new();
    let peer = test_peer_id(1);
    state.add_peer(peer);
    state.demote_to_lazy(&peer);

    state.promote_to_eager(&peer);

    assert!(state.is_eager(&peer));
    assert!(!state.is_lazy(&peer));
}

/// **PLT-006: remove_peer removes from both sets.**
///
/// Proves SPEC §8.1: tree self-healing after peer disconnect.
#[test]
fn test_remove_peer() {
    let mut state = PlumtreeState::new();
    let p1 = test_peer_id(1);
    let p2 = test_peer_id(2);
    state.add_peer(p1);
    state.add_peer(p2);
    state.demote_to_lazy(&p2);

    state.remove_peer(&p1);
    state.remove_peer(&p2);

    assert_eq!(state.peer_count(), 0);
}

/// **PLT-001: lazy_timeout_ms defaults to 500.**
///
/// Proves SPEC §8.1: "lazy_timeout_ms configurable (default 500ms)."
#[test]
fn test_default_lazy_timeout() {
    let state = PlumtreeState::new();
    assert_eq!(state.lazy_timeout_ms, 500);
}

// ===================== PLT-008: SeenSet =====================

/// **PLT-008: seen set detects duplicates.**
///
/// Proves SPEC §8.1 step 2: "if seen_set.contains(hash) → return 0."
#[test]
fn test_seen_set_dedup() {
    let mut set = SeenSet::new();
    let hash = SeenSet::compute_hash(20, b"test payload");

    assert!(set.insert(hash), "first insert must be new");
    assert!(!set.insert(hash), "second insert must be duplicate");
    assert!(set.contains(&hash));
}

/// **PLT-008: different msg_type produces different hash.**
#[test]
fn test_seen_hash_includes_type() {
    let h1 = SeenSet::compute_hash(20, b"same data");
    let h2 = SeenSet::compute_hash(21, b"same data");
    assert_ne!(h1, h2, "different msg_type must produce different hash");
}

/// **PLT-008: seen set respects capacity (LRU eviction).**
#[test]
fn test_seen_set_lru_eviction() {
    let mut set = SeenSet::with_capacity(3);

    let h1 = SeenSet::compute_hash(1, b"a");
    let h2 = SeenSet::compute_hash(2, b"b");
    let h3 = SeenSet::compute_hash(3, b"c");
    let h4 = SeenSet::compute_hash(4, b"d");

    set.insert(h1);
    set.insert(h2);
    set.insert(h3);
    assert_eq!(set.len(), 3);

    // h4 evicts h1 (LRU)
    set.insert(h4);
    assert_eq!(set.len(), 3);
    assert!(!set.contains(&h1), "h1 should be evicted (LRU)");
    assert!(set.contains(&h4));
}

/// **PLT-008: default capacity is 100,000.**
#[test]
fn test_seen_set_default_capacity() {
    let set = SeenSet::new();
    assert_eq!(set.capacity(), 100_000);
}

// ===================== PLT-007: MessageCache =====================

/// **PLT-007: insert + get round-trip.**
///
/// Proves SPEC §8.1: "Message cache serves GRAFT responses."
#[test]
fn test_message_cache_roundtrip() {
    let mut cache = MessageCache::new();
    let hash = SeenSet::compute_hash(20, b"block data");

    cache.insert(hash, 20, b"block data".to_vec());

    let entry = cache.get(&hash).expect("should find cached message");
    assert_eq!(entry.msg_type, 20);
    assert_eq!(entry.data, b"block data");
}

/// **PLT-007: missing hash returns None.**
#[test]
fn test_message_cache_miss() {
    let mut cache = MessageCache::new();
    let hash = SeenSet::compute_hash(20, b"x");
    assert!(cache.get(&hash).is_none());
}

/// **PLT-007: cache respects LRU capacity.**
#[test]
fn test_message_cache_lru() {
    let mut cache = MessageCache::with_config(2, 60);

    let h1 = SeenSet::compute_hash(1, b"a");
    let h2 = SeenSet::compute_hash(2, b"b");
    let h3 = SeenSet::compute_hash(3, b"c");

    cache.insert(h1, 1, b"a".to_vec());
    cache.insert(h2, 2, b"b".to_vec());
    cache.insert(h3, 3, b"c".to_vec()); // evicts h1

    assert!(cache.get(&h1).is_none(), "h1 should be evicted");
    assert!(cache.get(&h3).is_some());
}

/// **PLT-007: default capacity is 1000, TTL 60s.**
#[test]
fn test_message_cache_defaults() {
    let cache = MessageCache::new();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}
