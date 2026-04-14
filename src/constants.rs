//! DIG-wide constants and selected ports from Chia’s Python `address_manager` / node code.
//!
//! **Requirement:** STR-003 requires `pub use constants::*` from the crate root so
//! downstream crates see a single import surface — see
//! [`docs/requirements/domains/crate_structure/specs/STR-003.md`](../docs/requirements/domains/crate_structure/specs/STR-003.md)
//! and [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 10.2 (tail) + Section 6.x constant blocks.
//!
//! **Rationale:** Centralizing numbers here avoids magic literals scattered across discovery,
//! gossip, and connection code; names and values are kept aligned with the SPEC so reviews
//! can diff against the prose spec.

// -- Address manager (Chia `address_manager.py` lineage) --

pub const TRIED_BUCKETS_PER_GROUP: usize = 8;
pub const NEW_BUCKETS_PER_SOURCE_GROUP: usize = 64;
pub const TRIED_BUCKET_COUNT: usize = 256;
pub const NEW_BUCKET_COUNT: usize = 1024;
pub const BUCKET_SIZE: usize = 64;
pub const NEW_BUCKETS_PER_ADDRESS: usize = 8;
pub const HORIZON_DAYS: u32 = 30;
pub const MAX_RETRIES: u32 = 3;
pub const MIN_FAIL_DAYS: u32 = 7;
pub const MAX_FAILURES: u32 = 10;

// -- DIG defaults --

pub const DEFAULT_P2P_PORT: u16 = 9444;
pub const DEFAULT_RELAY_PORT: u16 = 9450;
pub const DEFAULT_INTRODUCER_PORT: u16 = 9448;
pub const DEFAULT_TARGET_OUTBOUND_COUNT: usize = 8;
pub const DEFAULT_MAX_SEEN_MESSAGES: usize = 100_000;
pub const PENALTY_BAN_THRESHOLD: u32 = 100;
pub const BAN_DURATION_SECS: u64 = 3600;
pub const PEER_TIMEOUT_SECS: u64 = 90;
pub const PING_INTERVAL_SECS: u64 = 30;

// -- Plumtree --

pub const PLUMTREE_LAZY_TIMEOUT_MS: u64 = 500;
pub const PLUMTREE_MESSAGE_CACHE_SIZE: usize = 1000;
pub const PLUMTREE_MESSAGE_CACHE_TTL_SECS: u64 = 60;

// -- Compact block relay --

pub const SHORT_TX_ID_BYTES: usize = 6;
pub const COMPACT_BLOCK_MAX_MISSING_TXS: usize = 5;

// -- ERLAY --

pub const ERLAY_FLOOD_PEER_COUNT: usize = 8;
pub const ERLAY_RECONCILIATION_INTERVAL_MS: u64 = 2000;
pub const ERLAY_SKETCH_CAPACITY: usize = 20;
pub const ERLAY_FLOOD_SET_ROTATION_SECS: u64 = 60;

// -- Priority / backpressure --

pub const BACKPRESSURE_TX_DEDUP_THRESHOLD: usize = 25;
pub const BACKPRESSURE_BULK_DROP_THRESHOLD: usize = 50;
pub const BACKPRESSURE_NORMAL_DELAY_THRESHOLD: usize = 100;
pub const PRIORITY_STARVATION_RATIO: usize = 10;

// -- Latency scoring --

pub const RTT_WINDOW_SIZE: usize = 10;
pub const RTT_PENALTY_THRESHOLD_MS: u64 = 5000;
