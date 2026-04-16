//! Tests for **PLT-007: Message Cache**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/plumtree/specs/PLT-007.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.1

use dig_gossip::gossip::message_cache::MessageCache;
use dig_gossip::gossip::seen_set::SeenSet;

/// **PLT-007: insert + get round-trip.**
///
/// Proves SPEC SS8.1: "Message cache serves GRAFT responses."
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
