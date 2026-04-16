//! LRU-based message deduplication (**PLT-008**).
//!
//! # Requirements
//!
//! - **PLT-008** — Seen set: LRU capacity 100,000. Already-seen messages dropped.
//!   hash = SHA256(msg_type_u8 || data). SPEC §8.1 step 2.
//!
//! # Design
//!
//! Wraps `lru::LruCache<Bytes32, ()>` with hash computation.
//! Hash includes msg_type (as single u8 byte) and data bytes to ensure
//! different message types with identical payloads produce different hashes.
//!
//! ## SPEC citations
//!
//! - SPEC §8.1 step 2: "if seen_set.contains(hash) → return 0 (already seen)."
//! - SPEC §8.1: "hash = SHA256(msg_type || data)."

use dig_protocol::Bytes32;
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;

use crate::constants::DEFAULT_MAX_SEEN_MESSAGES;

/// LRU message deduplication set (**PLT-008**).
///
/// SPEC §8.1 step 2: "if seen_set.contains(hash) → return 0 (already seen)."
/// Capacity: `DEFAULT_MAX_SEEN_MESSAGES` (100,000).
#[derive(Debug)]
pub struct SeenSet {
    set: LruCache<Bytes32, ()>,
}

impl SeenSet {
    /// Create with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_SEEN_MESSAGES)
    }

    /// Create with custom capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            set: LruCache::new(cap),
        }
    }

    /// Compute message hash: SHA256(msg_type_u8 || data).
    ///
    /// SPEC §8.1: "hash = SHA256(msg_type || data)."
    pub fn compute_hash(msg_type: u8, data: &[u8]) -> Bytes32 {
        let mut hasher = Sha256::new();
        hasher.update([msg_type]);
        hasher.update(data);
        let digest: [u8; 32] = hasher.finalize().into();
        Bytes32::from(digest)
    }

    /// Check if hash already seen (read-only, no LRU promotion).
    pub fn contains(&self, hash: &Bytes32) -> bool {
        self.set.contains(hash)
    }

    /// Insert hash. Returns true if new, false if duplicate.
    pub fn insert(&mut self, hash: Bytes32) -> bool {
        if self.set.contains(&hash) {
            false
        } else {
            self.set.put(hash, ());
            true
        }
    }

    /// Current tracked hash count.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Max capacity.
    pub fn capacity(&self) -> usize {
        self.set.cap().into()
    }
}

impl Default for SeenSet {
    fn default() -> Self {
        Self::new()
    }
}
