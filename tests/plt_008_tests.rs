//! Tests for **PLT-008: Seen Set**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/plumtree/specs/PLT-008.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.1

use dig_gossip::gossip::seen_set::SeenSet;

/// **PLT-008: seen set detects duplicates.**
///
/// Proves SPEC SS8.1 step 2: "if seen_set.contains(hash) -> return 0."
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
