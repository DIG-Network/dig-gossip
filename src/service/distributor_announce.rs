//! distributor-announce broadcast wire message — opcode 226 (`DISTRIBUTOR_ANNOUNCE`).
//!
//! # What this is
//!
//! A peer floods a `distributor-announce`: a `store_id` plus the launcher ids of reward
//! distributors it knows of for that store. It is a public all-peers flood, same §5.4
//! carve-out as [`STORE_MELTED`](crate::service::store_melted::STORE_MELTED) and
//! [`HOLDINGS_ANNOUNCE`](crate::service::holdings_announce::HOLDINGS_ANNOUNCE). See
//! [`dig_peer_protocol::DISTRIBUTOR_ANNOUNCE`] for the canonical cross-repo doc comment this
//! module must not contradict; the wording below restates it.
//!
//! # Deliberately unsigned
//!
//! Unlike opcode 222, there is **no signature field and no signing code** in this module.
//! The authority for a distributor is the **on-chain coin**, not the announcing peer: a
//! receiver re-derives every property from chain (`advertises(store, root, epoch)` +
//! `declares_peer(peer_id)` + `owner_puzzle_hash()` via `dig-mirror-coin`'s binding) before a
//! launcher id becomes a candidate. This frame carries no addresses, so — unlike a holdings
//! announce — there is no address-rewriting or holder-set-poisoning threat for a signature to
//! close: a forged announce costs a receiver one wasted chain lookup that then fails that
//! compare.
//!
//! # Membership only, never completeness
//!
//! The launcher ids present are ids the sender claims to know of for that `store_id`. **The
//! absence of an id asserts nothing at all** — not that the sender doesn't know of it, not
//! that it was evicted, nothing. A sender MAY omit known ids from any frame at **any** count,
//! not only above the cap, so a frame carrying fewer than
//! [`MAX_LAUNCHER_IDS_PER_ANNOUNCE`] is not thereby complete.
//!
//! # Union, never replace, never diff
//!
//! A receiver **MUST union** a frame into what it already holds for that store; it **MUST
//! NOT** replace its per-store set from a frame, and **MUST NOT** diff two frames against each
//! other. This holds on the bytes themselves: because any subset may be sent and rotated, a
//! frame omitting an id is byte-identical whether the sender never knew it, rotated it out, or
//! dropped it, so a receiver that diffs manufactures an eviction rather than recovering one.
//! This is what makes eviction **unrepresentable** on this wire, and is exactly
//! `dig_ecosystem` §12.5 clause 7 (no consumer may reconstruct never-admitted versus evicted).
//! Staleness is instead handled by the receiver's own age-based eviction — see
//! [`DistributorHintCache`] — never by a peer's frame.
//!
//! # The empty list is a positive statement
//!
//! An **empty** launcher-id list is distinct from not announcing at all: it is a real,
//! decodable frame the sender chose to send, not the absence of one — silence and an empty
//! frame are different signals. It is **not**, however, a guarantee that the sender knows of no
//! distributors: a sender MAY omit known ids from any frame at any count (see "membership only,
//! never completeness" above), so a sender that knows ids may still choose to send an empty
//! frame. A receiver MUST NOT read an empty frame as a clear, a retraction, or a claim that the
//! sender's known set is empty — union-with-empty is a no-op, exactly as with any other frame.
//!
//! # Hint, never authority
//!
//! Nothing this module produces may admit an entry, rank or order a candidate, or be a claim's
//! authority. There is no remove operation of any kind: no retraction opcode, no tombstone, no
//! `Remove` variant.
//!
//! # Silent choices this implementation pins
//!
//! Five points the wire layout alone does not settle, pinned here as normative so a second
//! implementation matches this one rather than guessing:
//!
//! 1. **Duplicate launcher id within one frame** — accepted and deduped (both at decode-time
//!    shape and at [`DistributorHintCache::union`] time); a duplicate is never a decode error.
//! 2. **Trailing bytes after the last launcher id** — rejected; [`DistributorAnnounce::decode`]
//!    returns `None` rather than silently ignoring the extra bytes.
//! 3. **Launcher-id order within a frame** — not significant; a decoder MUST NOT infer anything
//!    from the order ids appear on the wire (see "hints_for_store returns a deterministic,
//!    receiver-computed order" below — that order is unrelated to wire order).
//! 4. **All-zero `store_id` or launcher id** — accepted, with no sentinel meaning; the all-zero
//!    32 bytes is an ordinary id like any other, never a wildcard, "none" or "unknown" marker.
//! 5. **[`DigMessage::id`] is always `None`** — a distributor announce is a fire-and-forget
//!    flood broadcast, never a correlated request/response.
//!
//! # Wire layout
//!
//! A `distributor-announce` frame is a [`DigMessage`] with `msg_type = 226`
//! ([`DISTRIBUTOR_ANNOUNCE`]) whose `data` is the encoding of [`DistributorAnnounce`] (see
//! [`DistributorAnnounce::encode`]), all integers big-endian:
//!
//! `store_id(32) ‖ launcher_id_count(u16 BE) ‖ launcher_ids(32 bytes each, at most
//! [`MAX_LAUNCHER_IDS_PER_ANNOUNCE`])`
//!
//! # Routing
//!
//! `distributor-announce` is a **broadcast flood** (Plumtree eager/lazy push, like the other
//! announce messages) at **Bulk** priority — small and infrequent, never consensus-critical.
//! See [`classify_broadcast`](crate::gossip::broadcaster::classify_broadcast) and
//! [`MessagePriority`](crate::gossip::priority::MessagePriority).

use dig_peer_protocol::{Bytes, DigMessage};

/// Wire opcode for a `distributor-announce` broadcast.
///
/// Canonical value **226** — the seventh opcode of the 220-255 "free" band, after
/// [`PROFILE_BODY`](crate::service::profile_sync::PROFILE_BODY)`= 225`. Mirrors
/// [`dig_peer_protocol::DISTRIBUTOR_ANNOUNCE`], which is the single definition. This value is
/// a cross-repo canonical constant (dig-node pins it to decode the broadcast) — it MUST NOT
/// drift, and MUST NEVER be written as the bare literal `226` outside a pinning test.
pub const DISTRIBUTOR_ANNOUNCE: u8 = dig_peer_protocol::DISTRIBUTOR_ANNOUNCE;

/// Maximum number of launcher ids a single announce may carry.
///
/// A sender who knows of more distributors than this sends any subset of at most this many,
/// and MAY rotate which subset it sends across frames — see the module docs' "membership
/// only" rule. Both [`DistributorAnnounce::new`] and [`DistributorAnnounce::decode`] reject a
/// count above this cap.
pub const MAX_LAUNCHER_IDS_PER_ANNOUNCE: usize = 32;

/// Maximum encoded **body** size, in bytes, of a [`DistributorAnnounce`] — i.e. the maximum
/// `data_len` of the [`DigMessage`] this opcode carries. This is NOT the framed total (the
/// `SPEC.md` §2.1 header is separate).
///
/// Derived from the other constants rather than hardcoded: `store_id(32) +
/// launcher_id_count(2) + MAX_LAUNCHER_IDS_PER_ANNOUNCE * 32`. This is the LOAD-BEARING
/// availability guarantee for opcode 226: it equals the opcode-226 inbound rate-limit
/// `max_size` (`connection::inbound_limits`), referenced by that row rather than restated, so
/// the limiter and the enforced bound can never drift apart (mirrors the opcode-222 tie to
/// `MAX_ANNOUNCE_FRAME_BYTES`).
pub const MAX_DISTRIBUTOR_ANNOUNCE_BODY_BYTES: usize = 32 + 2 + MAX_LAUNCHER_IDS_PER_ANNOUNCE * 32;

/// Bounds how many distinct `(store_id, launcher_id)` hints [`DistributorHintCache`] retains
/// for one sending peer before the oldest is aged out.
///
/// Sybil bound: at `freq` 6 frames/min/conn and up to [`MAX_LAUNCHER_IDS_PER_ANNOUNCE`] (32)
/// novel ids per frame, a single connection can present at most 192 novel launcher ids/min —
/// each costing the receiver one wasted chain lookup at candidate time, never an admission.
/// Retention itself is capped far below that per-minute ceiling so one connection cannot grow
/// its footprint without bound over time.
pub const MAX_RETAINED_HINTS_PER_PEER: usize = 64;

/// Why building a [`DistributorAnnounce`] failed. Fail-closed — the announce is not
/// constructed and nothing is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributorAnnounceError {
    /// The launcher-id list carried more than [`MAX_LAUNCHER_IDS_PER_ANNOUNCE`] entries.
    TooManyLauncherIds {
        /// The rejected count.
        count: usize,
    },
}

impl std::fmt::Display for DistributorAnnounceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyLauncherIds { count } => write!(
                f,
                "distributor announce has {count} launcher ids (max {MAX_LAUNCHER_IDS_PER_ANNOUNCE})"
            ),
        }
    }
}

impl std::error::Error for DistributorAnnounceError {}

/// An unsigned announcement of the reward-distributor launcher ids a peer knows of for one
/// store. See the module docs for the membership-only, union-never-replace, empty-is-positive
/// and hint-never-authority rules — every one of them is normative for this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributorAnnounce {
    /// The store this announce concerns.
    pub store_id: [u8; 32],
    /// Launcher ids of distributors the sender claims to know of for `store_id` (at most
    /// [`MAX_LAUNCHER_IDS_PER_ANNOUNCE`]). Absence of an id here asserts nothing — see the
    /// module docs.
    pub launcher_ids: Vec<[u8; 32]>,
}

impl DistributorAnnounce {
    /// Build an announce, rejecting a launcher-id list over [`MAX_LAUNCHER_IDS_PER_ANNOUNCE`].
    ///
    /// # Errors
    ///
    /// [`DistributorAnnounceError::TooManyLauncherIds`] if `launcher_ids.len()` exceeds the
    /// cap. The caller is expected to send a SUBSET rather than truncate silently — see the
    /// module docs' "membership only" rule.
    pub fn new(
        store_id: [u8; 32],
        launcher_ids: Vec<[u8; 32]>,
    ) -> Result<Self, DistributorAnnounceError> {
        if launcher_ids.len() > MAX_LAUNCHER_IDS_PER_ANNOUNCE {
            return Err(DistributorAnnounceError::TooManyLauncherIds {
                count: launcher_ids.len(),
            });
        }
        Ok(Self {
            store_id,
            launcher_ids,
        })
    }

    /// Encode to the wire bytes.
    ///
    /// Layout, all integers big-endian: `store_id(32) ‖ launcher_id_count(u16) ‖
    /// launcher_ids(32 bytes each)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 2 + self.launcher_ids.len() * 32);
        buf.extend_from_slice(&self.store_id);
        buf.extend_from_slice(&(self.launcher_ids.len() as u16).to_be_bytes());
        for id in &self.launcher_ids {
            buf.extend_from_slice(id);
        }
        buf
    }

    /// Decode from the wire bytes produced by [`encode`](Self::encode).
    ///
    /// Returns `None` on any truncated/malformed frame or trailing bytes — never panics.
    /// Rejects a `launcher_id_count` above [`MAX_LAUNCHER_IDS_PER_ANNOUNCE`] **before**
    /// reserving any `Vec` capacity, mirroring `holdings_announce`'s `decode_delta` fix
    /// (#1777): a crafted count up to `u16::MAX` must not trigger a large transient
    /// reservation on a tiny frame.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0usize;
        let store_id = take_32(bytes, &mut pos)?;
        let count = take_u16(bytes, &mut pos)? as usize;
        if count > MAX_LAUNCHER_IDS_PER_ANNOUNCE {
            return None;
        }
        let mut launcher_ids = Vec::with_capacity(count);
        for _ in 0..count {
            launcher_ids.push(take_32(bytes, &mut pos)?);
        }
        if pos != bytes.len() {
            return None; // trailing bytes — reject rather than silently ignore
        }
        Some(Self {
            store_id,
            launcher_ids,
        })
    }
}

/// Read a fixed 32-byte array at `*pos`, advancing `*pos`.
fn take_32(bytes: &[u8], pos: &mut usize) -> Option<[u8; 32]> {
    let v: [u8; 32] = bytes.get(*pos..*pos + 32)?.try_into().ok()?;
    *pos += 32;
    Some(v)
}

/// Read a big-endian `u16` at `*pos`, advancing `*pos`.
fn take_u16(bytes: &[u8], pos: &mut usize) -> Option<u16> {
    let v = u16::from_be_bytes(bytes.get(*pos..*pos + 2)?.try_into().ok()?);
    *pos += 2;
    Some(v)
}

/// True iff `msg_type` is the `distributor-announce` opcode ([`DISTRIBUTOR_ANNOUNCE`]).
#[must_use]
pub fn is_distributor_announce(msg_type: u8) -> bool {
    msg_type == DISTRIBUTOR_ANNOUNCE
}

/// Lift and decode a [`DistributorAnnounce`] from an inbound [`DigMessage`].
///
/// Returns `Some(announce)` iff `msg` is an opcode-226 frame whose `data` decodes, else
/// `None`. The caller is expected to [`DistributorHintCache::union`] the result — never
/// replace its per-store set.
#[must_use]
pub fn distributor_announce_payload(msg: &DigMessage) -> Option<DistributorAnnounce> {
    if is_distributor_announce(msg.msg_type) {
        DistributorAnnounce::decode(msg.data.as_ref())
    } else {
        None
    }
}

/// Build the outbound opcode-226 [`DigMessage`] that floods `announce` to peers.
///
/// `id` is `None`: a distributor announcement is a fire-and-forget flood broadcast, not a
/// correlated request/response.
#[must_use]
pub fn frame_distributor_announce(announce: &DistributorAnnounce) -> DigMessage {
    DigMessage::new(DISTRIBUTOR_ANNOUNCE, None, Bytes::new(announce.encode()))
}

// ============================================================================
// Receiver-side hint cache — union with age-based eviction, never replace-by-store
// ============================================================================

/// A per-sending-peer cache of `(store_id, launcher_id)` hints, unioned across every
/// `distributor-announce` frame that peer has sent — **never replaced**.
///
/// Bounded by [`MAX_RETAINED_HINTS_PER_PEER`]: once at capacity, [`Self::union`] ages out the
/// **oldest-inserted** entry, one per new entry admitted — never in response to what a frame
/// does or doesn't contain. A frame can therefore only ever GROW what is retained (subject to
/// that age-based cap); it can never shrink it, and two frames are never diffed against each
/// other. This is the module invariant applied to storage: see the module docs' "union, never
/// replace, never diff" rule.
#[derive(Debug, Clone, Default)]
pub struct DistributorHintCache {
    /// Oldest-first insertion order, for age-based eviction.
    order: std::collections::VecDeque<([u8; 32], [u8; 32])>,
    /// Membership index mirroring `order`, so `union` can dedupe in O(1).
    seen: std::collections::HashSet<([u8; 32], [u8; 32])>,
}

impl DistributorHintCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Union `announce`'s launcher ids into what this cache already holds for
    /// `announce.store_id`.
    ///
    /// A no-op for any id already present (including every id when `announce.launcher_ids` is
    /// empty — the module docs' "empty is a positive statement, not a clear" rule). Never
    /// removes an entry because a frame omitted it.
    pub fn union(&mut self, announce: &DistributorAnnounce) {
        for &launcher_id in &announce.launcher_ids {
            let key = (announce.store_id, launcher_id);
            if self.seen.insert(key) {
                self.order.push_back(key);
                while self.order.len() > MAX_RETAINED_HINTS_PER_PEER {
                    if let Some(evicted) = self.order.pop_front() {
                        self.seen.remove(&evicted);
                    }
                }
            }
        }
    }

    /// The launcher ids currently retained for `store_id`, sorted ascending byte-wise by
    /// launcher id.
    ///
    /// This order is **deterministic and meaningless**: it exists only so two receivers that
    /// retain the same set return the same sequence, and carries no preference, recency, trust
    /// or ranking signal of any kind. **Arrival order is not observable through this API** —
    /// see the module docs' "hint, never authority" rule, which this accessor must not violate
    /// by leaking the order ids happened to arrive in.
    #[must_use]
    pub fn hints_for_store(&self, store_id: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = self
            .order
            .iter()
            .filter(|(s, _)| s == store_id)
            .map(|(_, l)| *l)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// Total retained hints across every store, for this peer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether nothing is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn sample() -> DistributorAnnounce {
        DistributorAnnounce::new(id(0x01), vec![id(0x10), id(0x11), id(0x12)])
            .expect("within MAX_LAUNCHER_IDS_PER_ANNOUNCE")
    }

    #[test]
    fn opcode_is_226() {
        assert_eq!(DISTRIBUTOR_ANNOUNCE, 226);
        assert!(is_distributor_announce(226));
        assert!(!is_distributor_announce(225));
    }

    #[test]
    fn body_bound_is_1058() {
        assert_eq!(MAX_DISTRIBUTOR_ANNOUNCE_BODY_BYTES, 1058);
        assert_eq!(MAX_DISTRIBUTOR_ANNOUNCE_BODY_BYTES, 32 + 2 + 32 * 32);
    }

    #[test]
    fn encode_decode_round_trips_byte_identically() {
        let a = sample();
        let bytes = a.encode();
        let decoded = DistributorAnnounce::decode(&bytes).expect("decode");
        assert_eq!(decoded, a);
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn a_max_size_announce_encodes_within_the_body_bound() {
        let launcher_ids: Vec<[u8; 32]> =
            (0..MAX_LAUNCHER_IDS_PER_ANNOUNCE as u8).map(id).collect();
        let a = DistributorAnnounce::new(id(0xAA), launcher_ids).expect("at cap");
        assert_eq!(a.encode().len(), MAX_DISTRIBUTOR_ANNOUNCE_BODY_BYTES);
    }

    #[test]
    fn new_rejects_over_cap_launcher_ids() {
        let over_cap: Vec<[u8; 32]> = (0..=MAX_LAUNCHER_IDS_PER_ANNOUNCE as u16)
            .map(|i| id(i as u8))
            .collect();
        assert_eq!(
            DistributorAnnounce::new(id(0x01), over_cap),
            Err(DistributorAnnounceError::TooManyLauncherIds {
                count: MAX_LAUNCHER_IDS_PER_ANNOUNCE + 1
            })
        );
    }

    /// #1777-style regression: a crafted `launcher_id_count` above the cap MUST be rejected at
    /// decode time, before the per-id `Vec` is reserved. A hostile `u16::MAX` count sits far
    /// below any total-frame-size bound, so decode is the only line of defence against a large
    /// transient over-reservation.
    #[test]
    fn decode_rejects_launcher_id_count_over_cap_before_reserving() {
        let mut bytes = id(0x01).to_vec();
        bytes.extend_from_slice(&u16::MAX.to_be_bytes());
        // No id bytes follow — if decode reserved `Vec::with_capacity(u16::MAX)` before
        // checking the cap, it would still return `None` on the immediate truncation, so this
        // alone cannot distinguish the fixed decode. What it DOES prove is decode returns
        // `None` promptly, exactly as it must both before and after the fix.
        assert!(DistributorAnnounce::decode(&bytes).is_none());

        // A count one over the cap, but with enough legit trailing bytes to decode fully if
        // decode did NOT enforce the cap — this is the discriminating case.
        let over_cap = (MAX_LAUNCHER_IDS_PER_ANNOUNCE + 1) as u16;
        let mut full = id(0x02).to_vec();
        full.extend_from_slice(&over_cap.to_be_bytes());
        for i in 0..over_cap {
            full.extend_from_slice(&id(i as u8));
        }
        assert!(
            DistributorAnnounce::decode(&full).is_none(),
            "decode must reject a launcher_id_count over MAX_LAUNCHER_IDS_PER_ANNOUNCE (mirrors #1777)"
        );
    }

    #[test]
    fn decode_rejects_truncated_and_trailing() {
        let bytes = sample().encode();
        assert!(DistributorAnnounce::decode(&bytes[..bytes.len() - 1]).is_none());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(DistributorAnnounce::decode(&extra).is_none());
        assert!(DistributorAnnounce::decode(&[]).is_none());
    }

    #[test]
    fn empty_launcher_list_round_trips_and_is_distinct_from_absence() {
        let empty = DistributorAnnounce::new(id(0x01), vec![]).expect("empty is valid");
        let bytes = empty.encode();
        // Distinct from "no announce at all": it is a real, decodable frame with a positive
        // (zero) launcher-id count, not the absence of a frame.
        assert_eq!(bytes.len(), 32 + 2);
        let decoded = DistributorAnnounce::decode(&bytes).expect("empty list decodes");
        assert_eq!(decoded, empty);
        assert!(decoded.launcher_ids.is_empty());
    }

    #[test]
    fn union_with_empty_is_a_no_op() {
        let mut cache = DistributorHintCache::new();
        cache.union(&sample());
        let before = cache.hints_for_store(&sample().store_id);

        let empty = DistributorAnnounce::new(sample().store_id, vec![]).expect("empty is valid");
        cache.union(&empty);
        let after = cache.hints_for_store(&sample().store_id);
        assert_eq!(before, after);
        assert_eq!(cache.len(), 3);
    }

    /// The union-never-replace rule, pinned: two DISJOINT frames for the same store leave the
    /// UNION of both retained, never just the latest.
    #[test]
    fn two_disjoint_frames_leave_the_union_of_both() {
        let store = id(0xEE);
        let first = DistributorAnnounce::new(store, vec![id(0x01), id(0x02)]).unwrap();
        let second = DistributorAnnounce::new(store, vec![id(0x03), id(0x04)]).unwrap();

        let mut cache = DistributorHintCache::new();
        cache.union(&first);
        cache.union(&second);

        let mut retained = cache.hints_for_store(&store);
        retained.sort();
        let mut expected = vec![id(0x01), id(0x02), id(0x03), id(0x04)];
        expected.sort();
        assert_eq!(
            retained, expected,
            "must retain the union, not just `second`"
        );
    }

    /// A later frame that omits an id previously announced does NOT evict it — the absence
    /// asserts nothing, so union-ing it must leave the earlier id retained.
    #[test]
    fn omitting_a_previously_known_id_does_not_evict_it() {
        let store = id(0xCC);
        let mut cache = DistributorHintCache::new();
        cache.union(&DistributorAnnounce::new(store, vec![id(0x01)]).unwrap());
        // A second frame for the same store that no longer mentions 0x01.
        cache.union(&DistributorAnnounce::new(store, vec![id(0x02)]).unwrap());

        let mut retained = cache.hints_for_store(&store);
        retained.sort();
        assert_eq!(retained, vec![id(0x01), id(0x02)]);
    }

    #[test]
    fn cache_ages_out_the_oldest_entry_past_capacity() {
        let store = id(0xDD);
        let mut cache = DistributorHintCache::new();
        for i in 0..MAX_RETAINED_HINTS_PER_PEER as u16 {
            cache.union(&DistributorAnnounce::new(store, vec![id(i as u8)]).unwrap());
        }
        assert_eq!(cache.len(), MAX_RETAINED_HINTS_PER_PEER);
        assert!(cache.hints_for_store(&store).contains(&id(0)));

        // One more distinct id pushes the cache over capacity: the OLDEST (id 0) ages out.
        cache.union(&DistributorAnnounce::new(store, vec![id(200)]).unwrap());
        assert_eq!(cache.len(), MAX_RETAINED_HINTS_PER_PEER);
        assert!(
            !cache.hints_for_store(&store).contains(&id(0)),
            "the oldest entry must age out once capacity is exceeded"
        );
        assert!(cache.hints_for_store(&store).contains(&id(200)));
    }

    /// The ordering-leak regression: two receivers hearing the SAME set of ids in OPPOSITE
    /// arrival order must return the SAME sequence from `hints_for_store`. Arrival order is not
    /// observable through this API — only the deterministic byte-wise sort is.
    #[test]
    fn hints_for_store_is_the_same_regardless_of_arrival_order() {
        let store = id(0xAB);
        let a = id(0x01);
        let b = id(0x02);
        let c = id(0x03);

        let mut forward = DistributorHintCache::new();
        forward.union(&DistributorAnnounce::new(store, vec![a]).unwrap());
        forward.union(&DistributorAnnounce::new(store, vec![b]).unwrap());
        forward.union(&DistributorAnnounce::new(store, vec![c]).unwrap());

        let mut reverse = DistributorHintCache::new();
        reverse.union(&DistributorAnnounce::new(store, vec![c]).unwrap());
        reverse.union(&DistributorAnnounce::new(store, vec![b]).unwrap());
        reverse.union(&DistributorAnnounce::new(store, vec![a]).unwrap());

        assert_eq!(
            forward.hints_for_store(&store),
            reverse.hints_for_store(&store)
        );
        assert_eq!(forward.hints_for_store(&store), vec![a, b, c]);
    }

    /// Pinned choice 1: a duplicate launcher id within one frame is accepted and deduped, both
    /// by the cache (`union`) and observably via `hints_for_store` — never a decode/build error.
    #[test]
    fn duplicate_launcher_id_within_one_frame_is_accepted_and_deduped() {
        let store = id(0x77);
        let dup = id(0x09);
        let announce = DistributorAnnounce::new(store, vec![dup, dup, id(0x0A)]).unwrap();
        assert_eq!(
            announce.launcher_ids.len(),
            3,
            "the frame itself carries the duplicate"
        );

        let mut cache = DistributorHintCache::new();
        cache.union(&announce);
        let retained = cache.hints_for_store(&store);
        assert_eq!(
            retained,
            vec![dup, id(0x0A)],
            "the cache dedupes the duplicate"
        );
        assert_eq!(cache.len(), 2);
    }

    /// Pinned choice 4: an all-zero `store_id` and an all-zero launcher id round-trip like any
    /// other id and carry no sentinel meaning (not a wildcard, not "none", not "unknown").
    #[test]
    fn all_zero_ids_round_trip_as_ordinary_ids() {
        let zero_store = [0u8; 32];
        let zero_launcher = [0u8; 32];
        let announce = DistributorAnnounce::new(zero_store, vec![zero_launcher]).unwrap();

        let bytes = announce.encode();
        let decoded = DistributorAnnounce::decode(&bytes).expect("all-zero frame decodes");
        assert_eq!(decoded, announce);

        let mut cache = DistributorHintCache::new();
        cache.union(&announce);
        assert_eq!(cache.hints_for_store(&zero_store), vec![zero_launcher]);
    }

    #[test]
    fn frame_and_lift_round_trip() {
        let a = sample();
        let msg = frame_distributor_announce(&a);
        assert_eq!(msg.msg_type, DISTRIBUTOR_ANNOUNCE);
        assert_eq!(msg.id, None);
        assert_eq!(distributor_announce_payload(&msg), Some(a));
    }

    #[test]
    fn payload_ignores_other_opcodes() {
        let msg = crate::service::dig_message::frame_envelope(&[1, 2, 3], None);
        assert!(distributor_announce_payload(&msg).is_none());
    }

    #[test]
    fn routed_as_bulk_flood_broadcast() {
        use crate::gossip::broadcaster::{classify_broadcast, BroadcastStrategy};
        use crate::gossip::priority::MessagePriority;

        assert_eq!(
            classify_broadcast(DISTRIBUTOR_ANNOUNCE, false),
            BroadcastStrategy::Plumtree
        );
        assert_eq!(
            MessagePriority::from_dig_type(DISTRIBUTOR_ANNOUNCE),
            MessagePriority::Bulk
        );
    }

    // ---- KAT golden vector (CI-fail-on-drift) ---------------------------------

    #[test]
    fn kat_body_layout_is_pinned() {
        // store_id(32x0x33) || launcher_id_count(u16 BE = 0x0002) || id1(32x0x44) || id2(32x0x55).
        // Regression (#3252): the previous literal here was short by 3 bytes (31 repeats of
        // 0x33 instead of 32), a hand-typing slip that shifted every field after `store_id`.
        // The encoder was never wrong — every other test in this module (round-trip, max-size,
        // body-bound) already proved it matches this exact layout.
        const KAT_HEX: &str = "3333333333333333333333333333333333333333333333333333333333333333000244444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555";
        let a = DistributorAnnounce {
            store_id: [0x33; 32],
            launcher_ids: vec![[0x44; 32], [0x55; 32]],
        };
        let got = hex::encode(a.encode());
        assert_eq!(got, KAT_HEX, "KAT_HEX drift: got {got}");
    }
}
