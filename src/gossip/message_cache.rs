//! LRU message cache for GRAFT responses (**PLT-007**).
//!
//! # Requirements
//!
//! - **PLT-007** — Message cache: LRU capacity 1000, TTL 60s.
//!   Serves messages in response to GRAFT requests.
//!   SPEC §8.1 `on_graft` handler.
//!
//! # Design
//!
//! Wraps `lru::LruCache<Bytes32, CacheEntry>` where each entry stores
//! the message bytes and insertion timestamp. `get()` checks TTL and
//! returns None for expired entries.

use chia_protocol::Bytes32;
use lru::LruCache;
use std::num::NonZeroUsize;

use crate::constants::{PLUMTREE_MESSAGE_CACHE_SIZE, PLUMTREE_MESSAGE_CACHE_TTL_SECS};
use crate::types::peer::metric_unix_timestamp_secs;

/// Cached message entry with insertion timestamp for TTL.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Serialized message bytes.
    pub data: Vec<u8>,
    /// Message type (u8 discriminant).
    pub msg_type: u8,
    /// Unix seconds when inserted.
    pub inserted_at: u64,
}

/// LRU message cache for GRAFT responses (**PLT-007**).
///
/// SPEC §8.1: "Message cache: LRU capacity 1000, TTL 60s."
#[derive(Debug)]
pub struct MessageCache {
    cache: LruCache<Bytes32, CacheEntry>,
    ttl_secs: u64,
}

impl MessageCache {
    /// Create with default capacity and TTL.
    pub fn new() -> Self {
        Self::with_config(PLUMTREE_MESSAGE_CACHE_SIZE, PLUMTREE_MESSAGE_CACHE_TTL_SECS)
    }

    /// Create with custom capacity and TTL.
    pub fn with_config(capacity: usize, ttl_secs: u64) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            cache: LruCache::new(cap),
            ttl_secs,
        }
    }

    /// Insert message into cache.
    pub fn insert(&mut self, hash: Bytes32, msg_type: u8, data: Vec<u8>) {
        self.cache.put(
            hash,
            CacheEntry {
                data,
                msg_type,
                inserted_at: metric_unix_timestamp_secs(),
            },
        );
    }

    /// Get message by hash. Returns None if missing or expired (TTL exceeded).
    ///
    /// SPEC §8.1 `on_graft`: "If we have the message, send it."
    /// Returns a clone to avoid borrow checker issues with LRU mutation.
    pub fn get(&mut self, hash: &Bytes32) -> Option<CacheEntry> {
        let now = metric_unix_timestamp_secs();
        // Peek without promoting in LRU (we'll pop if expired).
        let expired = self
            .cache
            .peek(hash)
            .map(|e| now.saturating_sub(e.inserted_at) > self.ttl_secs)
            .unwrap_or(true);

        if expired {
            self.cache.pop(hash);
            return None;
        }

        // Not expired — promote in LRU and return clone.
        self.cache.get(hash).cloned()
    }

    /// Current cache size.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for MessageCache {
    fn default() -> Self {
        Self::new()
    }
}
