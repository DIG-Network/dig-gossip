//! Centralized numeric constants for the DIG gossip crate.
//!
//! Every magic number used across discovery, gossip, connection, and backpressure code
//! is defined here so that:
//!
//! 1. Reviews can diff constants against the prose SPEC in one place.
//! 2. Downstream crates import a single flat namespace via `pub use constants::*`
//!    (STR-003 -- [`docs/requirements/domains/crate_structure/specs/STR-003.md`]).
//!
//! # Organization
//!
//! | Group | Origin | SPEC section |
//! |-------|--------|--------------|
//! | Address manager | Chia Python `address_manager.py:24-36` | §6.3 |
//! | DIG defaults | DIG network design | §3, §5 |
//! | Plumtree | Leitao et al., 2007 | §8.1 |
//! | Compact block relay | Bitcoin BIP 152 | §8.2 |
//! | ERLAY | Naumenko et al., 2019 | §8.3 |
//! | Priority / backpressure | DIG improvement over Chia | §8.4, §8.5 |
//! | Latency scoring | DIG improvement (SPEC §1.8 #6) | §1.8 |
//!
//! # Requirement traceability
//!
//! * **STR-003** -- re-exported at crate root via `pub use constants::*`.
//! * **SPEC §10.2** -- lists `constants::*` in the public re-export block.

// ---------------------------------------------------------------------------
// Address manager constants
//
// Ported from Chia’s Python `address_manager.py` (itself a port of Bitcoin’s
// `CAddrMan`). Line references are from:
//   https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954ed/chia/server/address_manager.py
// See also SPEC §6.3 and [`crate::discovery::address_manager::AddressManager`].
// ---------------------------------------------------------------------------

/// Number of "tried" buckets each /16 source group maps to.
/// Chia Python: `address_manager.py:24` (`TRIED_BUCKETS_PER_GROUP = 8`).
pub const TRIED_BUCKETS_PER_GROUP: usize = 8;

/// Number of "new" buckets each source group maps to.
/// Chia Python: `address_manager.py:25` (`NEW_BUCKETS_PER_SOURCE_GROUP = 64`).
pub const NEW_BUCKETS_PER_SOURCE_GROUP: usize = 64;

/// Total number of tried-table buckets. Each bucket holds up to [`BUCKET_SIZE`] entries.
/// Chia Python: `address_manager.py:26` (`TRIED_BUCKET_COUNT = 256`).
pub const TRIED_BUCKET_COUNT: usize = 256;

/// Total number of new-table buckets.
/// Chia Python: `address_manager.py:27` (`NEW_BUCKET_COUNT = 1024`).
pub const NEW_BUCKET_COUNT: usize = 1024;

/// Maximum entries per bucket (both tried and new tables).
/// Chia Python: `address_manager.py:28` (`BUCKET_SIZE = 64`).
pub const BUCKET_SIZE: usize = 64;

/// Maximum number of new-table buckets an individual address can appear in.
/// Prevents a single address from dominating the new table.
/// Chia Python: `address_manager.py:29` (`NEW_BUCKETS_PER_ADDRESS = 8`).
pub const NEW_BUCKETS_PER_ADDRESS: usize = 8;

/// Addresses not seen within this many days are considered stale and eligible for eviction.
/// Chia Python: `address_manager.py:30` (`HORIZON_DAYS = 30`).
pub const HORIZON_DAYS: u32 = 30;

/// Maximum connection attempts before an address is penalized.
/// Chia Python: `address_manager.py:31` (`MAX_RETRIES = 3`).
pub const MAX_RETRIES: u32 = 3;

/// Minimum days between the first and last failure before an address can be evicted.
/// Chia Python: `address_manager.py:32` (`MIN_FAIL_DAYS = 7`).
pub const MIN_FAIL_DAYS: u32 = 7;

/// Maximum total failures before an address is removed from the manager entirely.
/// Chia Python: `address_manager.py:33` (`MAX_FAILURES = 10`).
pub const MAX_FAILURES: u32 = 10;

/// Pending tried-slot collisions from `mark_good` when the target bucket is occupied (`address_manager.py:29`).
pub const TRIED_COLLISION_SIZE: usize = 10;

/// `log2(TRIED_BUCKET_COUNT)` — used by [`crate::discovery::address_manager::AddressManager`] sparse/dense
/// random walk in `select_peer` (Chia `address_manager.py:31`).
pub const LOG_TRIED_BUCKET_COUNT: u32 = 3;

/// `log2(NEW_BUCKET_COUNT)` — Chia `address_manager.py:32`.
pub const LOG_NEW_BUCKET_COUNT: u32 = 10;

/// `log2(BUCKET_SIZE)` — Chia `address_manager.py:33`.
pub const LOG_BUCKET_SIZE: u32 = 6;

/// Maximum rows across all tried buckets (`TRIED_BUCKET_COUNT * BUCKET_SIZE`). DSC-001 / SPEC §6.3.
pub const TRIED_TABLE_SIZE: usize = TRIED_BUCKET_COUNT * BUCKET_SIZE;

/// Maximum rows across all new buckets. DSC-001 / SPEC §6.3.
pub const NEW_TABLE_SIZE: usize = NEW_BUCKET_COUNT * BUCKET_SIZE;

// ---------------------------------------------------------------------------
// DIG network defaults
//
// DIG-specific ports and limits. No direct Chia Python analog; these are defined
// by the DIG network specification (SPEC §3, §5, and §6.5).
// ---------------------------------------------------------------------------

/// Default P2P listen port for DIG full nodes. SPEC §3.1.
/// Chia mainnet uses 8444; DIG uses 9444 to avoid collisions on dual-stack machines.
pub const DEFAULT_P2P_PORT: u16 = 9444;

/// Default per-introducer DNS resolution timeout passed to
/// [`chia_sdk_client::Network::lookup_all`](chia_sdk_client::Network::lookup_all) (DSC-003 / SPEC §6.2).
pub const DEFAULT_DNS_SEED_TIMEOUT_SECS: u64 = 30;

/// Default batch size for parallel DNS introducer lookups inside `lookup_all` (DSC-003).
/// Matches the sketch in [`docs/requirements/domains/discovery/specs/DSC-003.md`](../../docs/requirements/domains/discovery/specs/DSC-003.md).
pub const DEFAULT_DNS_SEED_BATCH_SIZE: usize = 2;

/// Default relay server port (SPEC §7 -- relay fallback, DIG-specific).
pub const DEFAULT_RELAY_PORT: u16 = 9450;

/// Default introducer port (SPEC §6.5 -- DIG introducer extension).
pub const DEFAULT_INTRODUCER_PORT: u16 = 9448;

/// Target number of outbound connections the discovery loop maintains.
/// SPEC §6.4 step 3. Chia Python: `node_discovery.py:34` (`target_outbound_count = 8`).
pub const DEFAULT_TARGET_OUTBOUND_COUNT: usize = 8;

/// Capacity of the message dedup LRU set (SPEC §8.1 step 2). Controls memory usage for
/// the `seen_messages` set in [`crate::service::state::ServiceState`].
pub const DEFAULT_MAX_SEEN_MESSAGES: usize = 100_000;

/// Cumulative penalty score at which a peer is banned (SPEC §1.8 #10, API-006).
/// See [`crate::types::reputation::PeerReputation`].
pub const PENALTY_BAN_THRESHOLD: u32 = 100;

/// Duration of a peer ban in seconds. After this period the peer may reconnect.
/// SPEC §5.4 (rate limiting + reputation).
pub const BAN_DURATION_SECS: u64 = 3600;

/// Peer timeout in seconds: if no `Pong` is received within this window, the connection
/// is considered dead and torn down (CON-004).
/// SPEC §2.13 constants; CON-004 spec (`PEER_TIMEOUT_SECS = 90`).
pub const PEER_TIMEOUT_SECS: u64 = 90;

/// Interval between Ping messages for keepalive probing (CON-004).
/// SPEC §2.13 constants (`PING_INTERVAL_SECS = 30`).
pub const PING_INTERVAL_SECS: u64 = 30;

/// Default timeout for [`GossipHandle::request`](crate::service::gossip_handle::GossipHandle::request)
/// RPC calls. Used until API-003 adds an explicit `GossipConfig` field.
/// SPEC §3.3 (API-002 implementation notes).
pub const DEFAULT_GOSSIP_REQUEST_TIMEOUT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Plumtree structured gossip (SPEC §8.1)
//
// Plumtree (Leitao et al., 2007) replaces Chia’s naive flood-to-all with a
// spanning-tree-based push/lazy-push protocol, reducing bandwidth 60-80%.
// ---------------------------------------------------------------------------

/// Time in milliseconds a node waits for an eagerly-pushed message after receiving a
/// lazy announcement before sending a GRAFT to pull it. Lower values repair the tree
/// faster but generate more GRAFT traffic. SPEC §8.1 ("lazy_timeout_ms").
pub const PLUMTREE_LAZY_TIMEOUT_MS: u64 = 500;

/// Maximum number of recently broadcast messages cached for GRAFT responses.
/// SPEC §8.1: "Recently broadcast messages are cached (LRU, capacity 1000)."
pub const PLUMTREE_MESSAGE_CACHE_SIZE: usize = 1000;

/// Time-to-live for entries in the Plumtree message cache (seconds).
/// SPEC §8.1: "Cache entries expire after 60 seconds."
pub const PLUMTREE_MESSAGE_CACHE_TTL_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Compact block relay (SPEC §8.2, inspired by Bitcoin BIP 152)
//
// Blocks are sent as header + short tx IDs; the receiver reconstructs from its
// mempool. Reduces block propagation bandwidth 90%+ vs Chia’s full `RespondBlock`.
// ---------------------------------------------------------------------------

/// Length of a short transaction ID in bytes (truncated SipHash).
/// SPEC §8.2: "6-byte truncated SipHash of transaction ID."
/// At 6 bytes, collision probability is ~1 in 2^48 per transaction pair.
pub const SHORT_TX_ID_BYTES: usize = 6;

/// Maximum missing transactions before falling back to a full `RequestBlock`.
/// SPEC §8.2: "If compact block reconstruction fails (>5 missing transactions),
/// fall back to requesting the full block."
pub const COMPACT_BLOCK_MAX_MISSING_TXS: usize = 5;

// ---------------------------------------------------------------------------
// ERLAY-style transaction relay (SPEC §8.3, Naumenko et al., 2019)
//
// Low-fanout flooding to ~8 peers + periodic minisketch set reconciliation with
// the rest. Per-transaction bandwidth drops from O(connections) to O(1).
// ---------------------------------------------------------------------------

/// Number of peers to flood `NewTransaction` to immediately (the "flood set").
/// Remaining peers use set reconciliation. SPEC §8.3: "default 8 (matching ERLAY
/// paper recommendation)."
/// Chia comparison: Chia floods to ALL peers -- no reconciliation.
pub const ERLAY_FLOOD_PEER_COUNT: usize = 8;

/// Interval in milliseconds between reconciliation rounds with each non-flood peer.
/// SPEC §8.3: "default 2000."
pub const ERLAY_RECONCILIATION_INTERVAL_MS: u64 = 2000;

/// Minisketch capacity: maximum set-difference size decodable in one round.
/// SPEC §8.3: "default 20 (handles up to 20 tx difference per reconciliation)."
pub const ERLAY_SKETCH_CAPACITY: usize = 20;

/// The flood-set is re-randomized at this interval to prevent topology fingerprinting.
/// SPEC §8.3: "The flood set is re-randomized every 60 seconds."
pub const ERLAY_FLOOD_SET_ROTATION_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Priority lanes and adaptive backpressure (SPEC §8.4, §8.5)
//
// DIG improvement: Chia multiplexes all messages on one WebSocket with no
// prioritization. A large `RespondBlocks` blocks a time-critical `NewPeak`.
// Priority lanes and adaptive backpressure prevent this.
// ---------------------------------------------------------------------------

/// Outbound queue depth at which duplicate `NewTransaction` announcements are
/// suppressed. SPEC §8.5 table: "25 - 50: Duplicate NewTransaction announcements
/// suppressed."
pub const BACKPRESSURE_TX_DEDUP_THRESHOLD: usize = 25;

/// Queue depth at which `Bulk`-priority messages are silently dropped and ERLAY
/// reconciliation is paused. SPEC §8.5: "50 - 100: Bulk messages dropped silently."
pub const BACKPRESSURE_BULK_DROP_THRESHOLD: usize = 50;

/// Queue depth at which `Normal`-priority messages begin to be delayed (batched,
/// sent every 500ms). `Critical` messages are never affected.
/// SPEC §8.5: "100+: Normal messages delayed."
pub const BACKPRESSURE_NORMAL_DELAY_THRESHOLD: usize = 100;

/// Starvation prevention ratio: for every N critical/normal messages drained, at
/// least 1 bulk message is guaranteed. Prevents indefinite starvation of peer
/// exchange and mempool sync during sustained high-priority load.
/// SPEC §8.4: "Bulk messages are guaranteed at least 1 message per 10 critical/normal."
pub const PRIORITY_STARVATION_RATIO: usize = 10;

// ---------------------------------------------------------------------------
// Latency scoring (SPEC §1.8 #6 -- latency-aware peer scoring)
//
// DIG improvement: Chia selects peers by address-manager recency, not quality.
// Tracking RTT from Ping/Pong and preferring low-latency peers improves block
// and attestation propagation. See [`crate::types::reputation::PeerReputation`].
// ---------------------------------------------------------------------------

/// Number of RTT samples in the sliding window for computing `avg_rtt_ms`.
/// A window of 10 Ping/Pong exchanges (~5 minutes at 30s intervals) smooths
/// transient spikes without being too slow to adapt.
pub const RTT_WINDOW_SIZE: usize = 10;

/// RTT threshold (milliseconds) above which a peer receives a latency penalty.
/// Peers with consistently high RTT are deprioritized for outbound selection
/// and Plumtree eager-push (CON-004, SPEC §1.8 #6).
pub const RTT_PENALTY_THRESHOLD_MS: u64 = 5000;
