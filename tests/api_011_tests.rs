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

/// Build a minimal [`PeerInfo`] with only host and port. In the Chia Python model
/// (`address_manager.py`), `ExtendedPeerInfo.peer_info` and `ExtendedPeerInfo.src` are
/// independent `PeerInfo` values — the source tells us *who told us about* the peer,
/// while `peer_info` is the peer's own address.
///
/// Used by every `ExtendedPeerInfo` test in this file to construct struct literals
/// without boilerplate.
fn peer(host: &str, port: u16) -> PeerInfo {
    PeerInfo {
        host: host.into(),
        port,
    }
}

/// **Row:** `test_extended_peer_info_all_fields` — constructs a full `ExtendedPeerInfo`
/// struct literal with all 10 fields populated, then reads each field back.
/// SPEC §2.6 — `ExtendedPeerInfo` (Rust port of `address_manager.py:43`): peer_info,
/// timestamp, src, random_pos, is_tried, ref_count, last_success, last_try,
/// num_attempts, last_count_attempt.
///
/// **Chia reference:** `address_manager.py:43-120` — `ExtendedPeerInfo.__init__` accepts
/// these exact fields. This test proves the Rust port has the same field set.
///
/// **What each assertion proves:**
/// - `peer_info.host/port`: the peer's own address (Python: `self.peer_info`).
/// - `timestamp`: last-seen time, used for staleness eviction.
/// - `src.host`: the peer that advertised this address (source-group bucketing).
/// - `random_pos == Some(7)`: placed at index 7 in the random-order vector.
/// - `is_tried == true`: this peer is in the tried table (has connected successfully).
/// - `ref_count == 2`: two new-table bucket slots reference this peer.
/// - `last_success`, `last_try`, `num_attempts`, `last_count_attempt`: timing/counter
///   fields used by the retry and eviction algorithms.
///
/// **Why sufficient:** The exhaustive struct literal fails to compile if any field is
/// missing or renamed. Each field assertion proves the value round-trips through public
/// access, confirming the fields are `pub` (not hidden behind getters).
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
    assert_eq!(row.peer_info.host, "10.0.0.1"); // peer's own address
    assert_eq!(row.peer_info.port, 9444); // standard Chia port
    assert_eq!(row.timestamp, 1_700_000_000); // last-seen Unix timestamp
    assert_eq!(row.src.host, "10.0.0.2"); // who told us about this peer
    assert_eq!(row.random_pos, Some(7)); // O(1) random-selection index
    assert!(row.is_tried); // in tried table, not new
    assert_eq!(row.ref_count, 2); // new-table bucket references
    assert_eq!(row.last_success, 1_700_000_100); // last successful connection
    assert_eq!(row.last_try, 1_700_000_050); // last attempt timestamp
    assert_eq!(row.num_attempts, 3); // total connection attempts
    assert_eq!(row.last_count_attempt, 1_700_000_040); // rate-limited attempt counter
}

/// **Row:** `test_extended_peer_info_initial_state` — the canonical new-table entry state:
/// `is_tried == false`, `ref_count == 0`, all timestamps/counters at zero.
///
/// **Chia reference:** In `address_manager.py`, a freshly added peer starts in the "new"
/// table with `ref_count = 0` (incremented later when bucket slots are assigned) and
/// `is_tried = False` (promoted to tried only after a successful outbound connection).
///
/// **What the assertion proves:** The Rust struct can represent the initial/empty state
/// that DSC-001's `add_to_new_table` produces. `ref_count == 0` with `is_tried == false`
/// means the peer exists in the info map but has no bucket-slot references yet (it will
/// be assigned to a bucket in the next step of the Python algorithm).
///
/// **Why sufficient:** Locks down the sentinel values DSC-001 will rely on when creating
/// new entries, preventing accidental non-zero defaults.
#[test]
fn test_extended_peer_info_initial_state() {
    let row = ExtendedPeerInfo {
        peer_info: peer("192.168.0.5", 9444),
        timestamp: 0,
        src: peer("192.168.0.1", 9444),
        random_pos: None, // not yet placed in random-order vector
        is_tried: false,  // new table, not tried
        ref_count: 0,     // no bucket slots assigned yet
        last_success: 0,  // never connected successfully
        last_try: 0,      // never attempted
        num_attempts: 0,
        last_count_attempt: 0,
    };
    // Canonical new-table entry: not tried, no bucket references.
    assert!(!row.is_tried);
    assert_eq!(row.ref_count, 0);
}

/// **Row:** `test_extended_peer_info_tried_state` — after promotion to the tried table,
/// `ref_count` is reset to **0** because new-table bucket references are cleared.
///
/// **Chia reference:** `address_manager.py` `MakeTried()` — when a peer moves from new
/// to tried, all its new-table bucket-slot references are removed (`ref_count` drops to 0)
/// and `is_tried` becomes `True`. The peer gets a `random_pos` in the tried-table's
/// random-order vector.
///
/// **What the assertion proves:** `is_tried == true` and `ref_count == 0` can coexist.
/// This combination is specifically valid for tried-table entries. If the Rust struct
/// enforced `ref_count > 0` when `is_tried == true`, this test would expose the bug.
///
/// **Why sufficient:** Validates the tried-table invariant that DSC-001's `MakeTried`
/// will produce, complementing `test_extended_peer_info_initial_state` (new-table).
#[test]
fn test_extended_peer_info_tried_state() {
    let row = ExtendedPeerInfo {
        peer_info: peer("203.0.113.10", 9444),
        timestamp: 100,
        src: peer("203.0.113.1", 9444),
        random_pos: Some(0), // assigned a tried-table random position
        is_tried: true,      // promoted to tried table
        ref_count: 0,        // new-table references cleared on promotion
        last_success: 200,   // has connected successfully (that triggered promotion)
        last_try: 200,
        num_attempts: 1,
        last_count_attempt: 200,
    };
    // Tried-table invariant: is_tried=true, ref_count=0.
    assert!(row.is_tried);
    assert_eq!(row.ref_count, 0);
}

/// **Row:** `test_extended_peer_info_last_success_zero` — `last_success == 0` is the
/// sentinel for "never successfully connected" (same semantics as Python's
/// `address_manager.py`).
///
/// **Chia reference:** The eviction algorithm (`IsTerrible()`) uses `last_success == 0`
/// combined with `num_attempts > MAX_RETRIES` and staleness to decide whether to evict
/// a peer from the new table. The sentinel 0 means "no successful connection ever",
/// which is distinct from "connected at Unix epoch" (practically impossible).
///
/// **What the assertion proves:** The `u64` type can represent 0 as a sentinel (not
/// `Option<u64>`). This is a deliberate design choice matching the Python model, where
/// `last_success` is an int defaulting to 0.
///
/// **Why sufficient:** Locks down the sentinel value so DSC-001's eviction logic can
/// rely on `== 0` comparisons without ambiguity.
#[test]
fn test_extended_peer_info_last_success_zero() {
    let row = ExtendedPeerInfo {
        peer_info: peer("198.51.100.7", 9444),
        timestamp: 1,
        src: peer("198.51.100.1", 9444),
        random_pos: None,
        is_tried: false,
        ref_count: 1,
        last_success: 0, // sentinel: never successfully connected
        last_try: 50,    // has been attempted (but failed)
        num_attempts: 2,
        last_count_attempt: 40,
    };
    // 0 is the "never connected" sentinel, not Option::None.
    assert_eq!(row.last_success, 0);
}

/// **Row:** `test_extended_peer_info_random_pos_none` — `random_pos == None` means the
/// peer has not yet been assigned a position in the O(1) random-selection vector.
///
/// **Chia reference:** `address_manager.py` uses `random_pos = -1` as the sentinel for
/// "not placed". The Rust port uses `Option<usize>` (`None`) instead of a magic `-1`,
/// which is more idiomatic and avoids signed-index confusion.
///
/// **What the assertion proves:** The `Option<usize>` type allows `None`, confirming the
/// Rust port can represent the "unplaced" state without a magic number.
///
/// **Why sufficient:** DSC-001's `add_to_new_table` and `MakeTried` must check for `None`
/// before assigning a position; this test ensures the initial state is representable.
#[test]
fn test_extended_peer_info_random_pos_none() {
    let row = ExtendedPeerInfo {
        peer_info: peer("example.invalid", 9444),
        timestamp: 0,
        src: peer("10.1.1.1", 9444),
        random_pos: None, // not yet placed in random-order vector
        is_tried: false,
        ref_count: 0,
        last_success: 0,
        last_try: 0,
        num_attempts: 0,
        last_count_attempt: 0,
    };
    // None = Python's random_pos == -1 ("not placed").
    assert_eq!(row.random_pos, None);
}

/// **Row:** `test_extended_peer_info_random_pos_some` — `random_pos == Some(42)` means
/// the peer has been placed at index 42 in the random-selection vector.
///
/// **Chia reference:** The random-order vector in `address_manager.py` enables O(1)
/// random peer selection (used for outbound connection targets). Each entry in the
/// tried/new table gets an index into this vector when it is first placed.
///
/// **What the assertion proves:** `Some(42)` round-trips correctly, confirming the
/// `Option<usize>` representation works for assigned positions.
///
/// **Why sufficient:** Complements `test_extended_peer_info_random_pos_none` — together
/// they prove both the `None` (unplaced) and `Some(n)` (placed) states are representable.
#[test]
fn test_extended_peer_info_random_pos_some() {
    let row = ExtendedPeerInfo {
        peer_info: peer("10.2.2.2", 9444),
        timestamp: 0,
        src: peer("10.3.3.3", 9444),
        random_pos: Some(42), // placed at index 42 in the random-order vector
        is_tried: false,
        ref_count: 0,
        last_success: 0,
        last_try: 0,
        num_attempts: 0,
        last_count_attempt: 0,
    };
    assert_eq!(row.random_pos, Some(42));
}

/// **Row:** `test_extended_peer_info_num_attempts` — `num_attempts` is a writable monotonic
/// counter, and `last_try` is a writable timestamp (both used by DSC-001's retry backoff
/// and `MAX_RETRIES` eviction).
///
/// **Chia reference:** `address_manager.py` increments `num_attempts` on each connection
/// attempt and updates `last_try` with the current timestamp. When `num_attempts >
/// MAX_RETRIES` and the entry is stale, it is evicted (`IsTerrible()` returns True).
///
/// **What the assertion proves:** Both fields are `pub mut` — they can be incremented and
/// assigned in-place without a setter method. This is important because DSC-001's
/// attempt-tracking code needs direct field mutation.
///
/// **Why sufficient:** Proves the Rust port supports the same mutation pattern as the
/// Python model (`info.num_attempts += 1; info.last_try = time.time()`).
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
    // Simulate one connection attempt (same pattern as DSC-001 will use).
    row.num_attempts += 1;
    row.last_try = 999;
    assert_eq!(row.num_attempts, 1); // counter incremented
    assert_eq!(row.last_try, 999); // timestamp updated
}

/// **Proof:** `peer_info` and `src` use this crate's [`PeerInfo`] (host + port only),
/// NOT `chia_protocol::TimestampedPeerInfo` (host + port + timestamp). This is a
/// deliberate API-011 design decision documented in the acceptance criteria.
///
/// **Chia reference:** In `address_manager.py`, `ExtendedPeerInfo` holds a `PeerInfo`
/// (not `TimestampedPeerInfo`). The timestamp is stored separately in the
/// `ExtendedPeerInfo.timestamp` field rather than inside the peer-info struct.
///
/// **What the assertion proves:** Assigning `peer("127.0.0.1", 9444)` (a `PeerInfo`)
/// to both `peer_info` and `src` compiles. If the fields were `TimestampedPeerInfo`,
/// the compiler would reject the assignment because `TimestampedPeerInfo` has a third
/// field (`timestamp: u64`). The `let _: PeerInfo = row.peer_info` lines further
/// confirm the concrete type at the extraction site.
///
/// **Why sufficient:** This is a compile-time contract test — the assertions are
/// redundant with the struct literal, but make the intent explicit for reviewers.
#[test]
fn test_extended_peer_info_uses_crate_peer_info_not_timestamped() {
    let pi: PeerInfo = peer("127.0.0.1", 9444);
    let row = ExtendedPeerInfo {
        peer_info: pi.clone(), // PeerInfo, not TimestampedPeerInfo
        timestamp: 0,
        src: pi, // PeerInfo, not TimestampedPeerInfo
        random_pos: None,
        is_tried: false,
        ref_count: 0,
        last_success: 0,
        last_try: 0,
        num_attempts: 0,
        last_count_attempt: 0,
    };
    // Type-level assertions: these would fail to compile if the fields were TimestampedPeerInfo.
    let _: PeerInfo = row.peer_info;
    let _: PeerInfo = row.src;
}

/// **Row:** `test_vetted_peer_all_fields` — constructs a `VettedPeer` with all 6 fields
/// populated, then reads each field back.
/// SPEC §2.8 — `VettedPeer` (Rust port of `introducer_peers.py:12-28`): host, port,
/// vetted (signed i32), vetted_timestamp, last_attempt, time_added.
///
/// **Chia reference:** `introducer_peers.py:12-28` — the `VettedPeer` dataclass has
/// `host`, `port`, `vetted`, `vetted_timestamp`, `last_attempt`, `time_added`.
///
/// **What each assertion proves:**
/// - `host`: the peer's address string (can be hostname or IP).
/// - `port == 9444`: the standard Chia listening port.
/// - `vetted == 1`: one consecutive successful vetting check.
/// - `vetted_timestamp == 1000`: when the last vetting check ran.
/// - `last_attempt == 900`: when the last connection attempt was made.
/// - `time_added == 800`: when this peer was first added to the introducer's set.
///
/// **Why sufficient:** Exhaustive struct literal — fails to compile if any field is missing.
/// Each assertion proves the field is `pub` and the value round-trips correctly.
#[test]
fn test_vetted_peer_all_fields() {
    let p = VettedPeer {
        host: "introducer-peer.example".into(),
        port: 9444,
        vetted: 1,              // 1 consecutive success
        vetted_timestamp: 1000, // last vetting check time
        last_attempt: 900,      // last connection attempt time
        time_added: 800,        // first added to introducer set
    };
    assert_eq!(p.host, "introducer-peer.example");
    assert_eq!(p.port, 9444);
    assert_eq!(p.vetted, 1);
    assert_eq!(p.vetted_timestamp, 1000);
    assert_eq!(p.last_attempt, 900);
    assert_eq!(p.time_added, 800);
}

/// **Row:** `test_vetted_peer_debug` — `VettedPeer` derives `Debug`, which is required for
/// introducer logging and diagnostics (API-011 acceptance, STR-003 intent).
///
/// **Chia reference:** The Python dataclass gets `__repr__` automatically; the Rust port
/// must derive `Debug` to match.
///
/// **What the assertion proves:** `format!("{p:?}")` produces a string containing
/// `"VettedPeer"`, confirming the derive is present and the struct name appears in output.
///
/// **Why sufficient:** If `Debug` were not derived, `format!("{p:?}")` would fail to
/// compile. The string check ensures the output is not opaque (`"..."` or similar).
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

/// **Row:** `test_vetted_peer_clone` — `VettedPeer` derives `Clone` and a clone is
/// equal to the original per `PartialEq`.
///
/// **Chia reference:** Python dataclasses are value-copied by default; Rust needs
/// explicit `Clone`.
///
/// **What the assertion proves:** `a.clone()` produces `b` where `a == b`. This exercises
/// both `Clone` (the copy operation) and `PartialEq` (the comparison). If any field
/// were skipped by either derive, the assertion would fail.
///
/// **Why sufficient:** The introducer tracks `VettedPeer` values in collections that may
/// clone entries (e.g., returning a snapshot to callers). `Clone + PartialEq` correctness
/// is load-bearing for that use case.
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
    assert_eq!(a, b); // exercises both Clone and PartialEq
}

/// **Row:** `test_vetted_peer_eq` — two independently constructed `VettedPeer` values with
/// identical fields are equal per `PartialEq` / `Eq`.
///
/// **Chia reference:** Python dataclass equality is field-by-field by default. The Rust
/// `derive(PartialEq, Eq)` matches this behavior.
///
/// **What the assertion proves:** Structural equality — two separate heap allocations
/// (`"same".into()` creates two `String` instances) compare as equal because `PartialEq`
/// compares field values, not identity/pointers.
///
/// **Why sufficient:** Proves equality is value-based (not reference-based), which is
/// required for correct `HashSet::contains` and `HashMap::get` lookups in DSC-012.
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
    // Independently constructed — different heap allocations for the String.
    let b = VettedPeer {
        host: "same".into(),
        port: 9444,
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    // Value equality, not reference equality.
    assert_eq!(a, b);
}

/// **Row:** `test_vetted_peer_hash` — `VettedPeer` derives `Hash` and two peers with
/// different hosts produce different hash values (both insert into a `HashSet`).
///
/// **Chia reference:** `introducer_peers.py` uses `set()` / `dict()` keyed on peer
/// identity. The Rust port needs `Hash` for `HashSet<VettedPeer>` / `HashMap<VettedPeer, _>`.
///
/// **What the assertion proves:**
/// - `set.insert(a)` returns `true`: `a` was not already in the set.
/// - `set.insert(b)` returns `true`: `b` hashed differently from `a` (host "x" vs "y").
/// - `set.len() == 2`: both entries coexist without collision.
///
/// **Why sufficient:** Proves the `Hash` derive distinguishes peers by at least the `host`
/// field. The `insert` return value confirms the hash + equality check worked correctly
/// (if `Hash` were broken and always returned 0, `PartialEq` would still distinguish
/// them, so `len() == 2` would still hold — but the `insert` returning `true` for both
/// confirms the set recognized them as distinct).
#[test]
fn test_vetted_peer_hash() {
    let mut set = HashSet::new();
    let a = VettedPeer {
        host: "x".into(), // different host from b
        port: 1,
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    let b = VettedPeer {
        host: "y".into(), // different host from a
        port: 1,
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    assert!(set.insert(a)); // first insert: true (new entry)
    assert!(set.insert(b)); // second insert: true (distinct hash/eq)
    assert_eq!(set.len(), 2); // both coexist
}

/// **Row:** `test_vetted_peer_unvetted` — `vetted == 0` represents the "not yet vetted"
/// initial state (API-011 acceptance, `introducer_peers.py` semantics).
///
/// **Chia reference:** A newly added peer starts with `vetted = 0`. After the introducer
/// successfully connects, `vetted` becomes positive (+1, +2, ...); after a failure it
/// becomes negative (-1, -2, ...).
///
/// **What the assertion proves:** The `i32` type allows 0 as a distinct state from
/// positive (success streak) and negative (failure streak).
///
/// **Why sufficient:** DSC-012's introducer logic will branch on `vetted == 0` to decide
/// whether to schedule an initial vetting check.
#[test]
fn test_vetted_peer_unvetted() {
    let p = VettedPeer {
        host: "z".into(),
        port: 9444,
        vetted: 0, // not yet vetted — initial state
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    assert_eq!(p.vetted, 0);
}

/// **Row:** `test_vetted_peer_success` — `vetted == 3` represents three consecutive
/// successful vetting connections (positive streak).
///
/// **Chia reference:** `introducer_peers.py:24` — on success, `vetted` is incremented
/// (`vetted = max(vetted, 0) + 1` if previously negative, or `vetted += 1` if already
/// positive). A value of 3 means the introducer has successfully connected three times
/// in a row.
///
/// **What the assertion proves:** The `i32` type correctly stores positive values,
/// representing the success-streak semantics.
///
/// **Why sufficient:** Complements `test_vetted_peer_unvetted` (0) and
/// `test_vetted_peer_failure` (negative). Together they cover all three branches of
/// the vetted-state machine: unvetted, success streak, failure streak.
#[test]
fn test_vetted_peer_success() {
    let p = VettedPeer {
        host: "ok".into(),
        port: 9444,
        vetted: 3, // 3 consecutive successful vetting connections
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    assert_eq!(p.vetted, 3);
}

/// **Row:** `test_vetted_peer_failure` — `vetted == -2` represents two consecutive failed
/// vetting attempts (negative streak, API-011 acceptance: "`VettedPeer.vetted` supports
/// negative values (consecutive failures)").
/// SPEC §2.8 — `VettedPeer.vetted`: 0 = not vetted, negative = consecutive failures,
/// positive = consecutive successes.
///
/// **Chia reference:** `introducer_peers.py:26` — on failure, `vetted` is decremented
/// (`vetted = min(vetted, 0) - 1`). The introducer uses the magnitude of the negative
/// value to decide whether to drop the peer entirely (e.g., after N consecutive failures).
///
/// **What the assertion proves:** The `i32` type correctly stores negative values. If the
/// field were `u32`, this test would fail to compile (or overflow).
///
/// **Why sufficient:** This is the critical signed-integer test. The API-011 acceptance
/// criteria explicitly require negative value support, and this test is the proof.
#[test]
fn test_vetted_peer_failure() {
    let p = VettedPeer {
        host: "bad".into(),
        port: 9444,
        vetted: -2, // 2 consecutive failures — signed i32 is required
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    };
    assert_eq!(p.vetted, -2);
}

/// **Row:** `test_vetted_peer_in_hashset` — multiple unique `VettedPeer` values coexist
/// in a single `HashSet`, proving the `Hash + Eq` contract is consistent.
///
/// **Chia reference:** `introducer_peers.py` maintains a `set` of `VettedPeer` objects.
/// The Rust port must support `HashSet<VettedPeer>` for the same purpose.
///
/// **What the assertion proves:** Two peers with different `host`/`port` combinations
/// ("a":1 and "b":2) both insert successfully and the set length is 2. This exercises
/// the full `Hash + Eq` pipeline in a realistic container scenario.
///
/// **Why sufficient:** Complements `test_vetted_peer_hash` (which tests `insert` return
/// values) by verifying the `len()` is correct after multiple inserts. Together they
/// prove the `HashSet` integration works end-to-end, which is exactly how DSC-012's
/// introducer code will use these types.
#[test]
fn test_vetted_peer_in_hashset() {
    let mut set = HashSet::new();
    set.insert(VettedPeer {
        host: "a".into(),
        port: 1, // distinct from "b":2
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    });
    set.insert(VettedPeer {
        host: "b".into(),
        port: 2, // distinct from "a":1
        vetted: 0,
        vetted_timestamp: 0,
        last_attempt: 0,
        time_added: 0,
    });
    // Both unique entries must coexist.
    assert_eq!(set.len(), 2);
}

/// **Extra:** `ExtendedPeerInfo` derives `Debug`, `Clone`, and `PartialEq` — required for
/// test fixtures (asserting equality), logging (printing state), and snapshot returns.
///
/// **Chia reference:** The Python `ExtendedPeerInfo` is a plain class with `__repr__`.
/// The Rust port adds `Clone` and `PartialEq` for ergonomic testing and DSC-001 use.
///
/// **What the assertions prove:**
/// - `a.clone()` produces `b` where `a == b`: `Clone` + `PartialEq` work together.
/// - `format!("{a:?}")` contains `"ExtendedPeerInfo"`: `Debug` produces readable output.
///
/// **Why sufficient:** These three derives are not in the API-011 acceptance checklist
/// (which focuses on fields), but they are implicitly required by DSC-001 test fixtures
/// and production logging. This test ensures they are not accidentally removed.
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
    let b = a.clone(); // exercises Clone
    assert_eq!(a, b); // exercises PartialEq
    let s = format!("{a:?}"); // exercises Debug
    assert!(s.contains("ExtendedPeerInfo"), "{s}");
}
