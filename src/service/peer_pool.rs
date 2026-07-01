//! The connected-peer POOL (POOL-*) — the maintained set of ready, CONNECTED peers a DIG Node keeps
//! for peer-RPC + downloads, and the DISCOVER → CONNECT → MAINTAIN loop that keeps it full.
//!
//! # Why a pool (and not just the address manager)
//!
//! [`AddressManager`](crate::discovery::address_manager::AddressManager) tracks KNOWN addresses —
//! candidates a node *could* dial. The pool is the layer above it: the set of peers the node is
//! *actually connected to right now*, kept at a target size so peer-RPC and multi-source downloads
//! always have live peers to talk to. This is what makes "many nodes across machines auto-discover
//! and stay connected" concrete: each node continuously discovers peers (relay introducer + node
//! peer-exchange), dials them over [`dig-nat`](dig_nat) (mTLS, `peer_id = SHA-256(SPKI)`, NAT-traversal
//! ladder with relay fallback), and replenishes the connected set as peers churn.
//!
//! This module deliberately **reuses** the existing machinery rather than duplicating it: the
//! [`ServiceState::peers`](crate::service::state::ServiceState) map IS the connected set (a pool peer
//! is a live/stub slot there); the [`AddressManager`] IS the known-address source the pool dials from;
//! the gossip ALGORITHMS ride unchanged on the resulting connections. The pool only adds the
//! *maintenance policy* (how many to keep, when to replenish, backoff on failure) + the
//! *churn-observation surface* + a dial abstraction.
//!
//! # The lifecycle (L7 peer-network §12 operational lifecycle)
//!
//! Each maintenance pass ([`run_maintenance_pass`]) does, in order:
//! 1. **DISCOVER** — learn new candidate addresses (relay introducer `get_peers` + node peer-exchange
//!    `dig.getPeers`) into the [`AddressManager`]. Discovery is continuous, not one-shot.
//! 2. **REPLENISH** — if the live connected count is below `target`, pick that many candidates from the
//!    address manager (skipping already-connected / backed-off / dead ones) and dial them via
//!    [`Dialer::dial`], capped so the pool never exceeds `max_peers`.
//! 3. **HEALTH** — evict peers that keepalive (CON-004) has already torn down or that have been banned,
//!    and record each dial outcome so a repeatedly-failing candidate is backed off (capped-exponential)
//!    and eventually dropped from the rotation.
//!
//! # Testability (no real network)
//!
//! The decision core ([`PoolPlan`], [`plan_pass`], [`DialBackoff`]) is PURE — it takes counts + a
//! candidate list + a clock and returns *what to do*, so every rule (fills to target, replenishes
//! after a drop, caps at max, dedups by `peer_id`, backs off failures) is unit-tested without a
//! socket. The async loop just executes that plan through a [`Dialer`], which tests implement with
//! loopback / in-memory peers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use crate::types::config::PeerPoolConfig;
use crate::types::peer::PeerId;

/// A churn event published as the pool gains or loses a connected peer.
///
/// Consumers (dig-node's peer-RPC layer, the download planner) subscribe via
/// [`GossipHandle::subscribe_pool_events`](crate::service::gossip_handle::GossipHandle::subscribe_pool_events)
/// to react to the pool changing — e.g. re-plan a download when a new holder joins, or drop a peer
/// from an in-flight fan-out when it leaves. It is a [`broadcast`] so multiple consumers each see
/// every event independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolEvent {
    /// A peer was added to the connected pool (dialed successfully, or accepted inbound and adopted).
    PeerAdded {
        /// The verified peer identity now in the pool.
        peer_id: PeerId,
        /// The remote endpoint the connection runs over (peer, or relay for a relayed link).
        addr: SocketAddr,
    },
    /// A peer left the connected pool (disconnected, evicted dead/stale, or banned).
    PeerRemoved {
        /// The peer identity that is no longer connected.
        peer_id: PeerId,
        /// Why it left.
        reason: PoolRemovalReason,
    },
}

/// Why a peer was removed from the pool (observability for churn consumers + logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolRemovalReason {
    /// A normal disconnect (peer closed, or we called `disconnect`).
    Disconnected,
    /// Evicted because keepalive (CON-004) found it dead / unresponsive.
    Dead,
    /// Removed because the peer was banned (CON-007) for misbehaviour.
    Banned,
}

/// One dialable candidate the pool may connect to: its [`PeerId`] (when known) + address.
///
/// The address manager yields addresses; the relay introducer yields `peer_id`s (relay-only, no
/// address). A candidate carries whichever it has — [`Self::peer_id`] is `None` for an
/// address-only candidate (identity is learned from the mTLS cert on connect), and `addr` is `None`
/// for a relay-only candidate (reached via the relay / a hole punch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolCandidate {
    /// The peer's identity, if already known (relay introducer path). `None` for an address-only
    /// candidate learned from node peer-exchange.
    pub peer_id: Option<PeerId>,
    /// A directly-dialable address, if known. `None` for a relay-only candidate.
    pub addr: Option<SocketAddr>,
}

impl PoolCandidate {
    /// An address-only candidate (from the address manager / node peer-exchange).
    pub fn from_addr(addr: SocketAddr) -> Self {
        PoolCandidate {
            peer_id: None,
            addr: Some(addr),
        }
    }

    /// A candidate known by identity + address.
    pub fn with_id(peer_id: PeerId, addr: SocketAddr) -> Self {
        PoolCandidate {
            peer_id: Some(peer_id),
            addr: Some(addr),
        }
    }

    /// A stable dedup key for this candidate: its `peer_id` if known, else its address. Two
    /// candidates with the same key denote the same peer and must not be dialed twice.
    fn dedup_key(&self) -> CandidateKey {
        match (self.peer_id, self.addr) {
            (Some(id), _) => CandidateKey::Id(id),
            (None, Some(a)) => CandidateKey::Addr(a),
            (None, None) => CandidateKey::Addr("0.0.0.0:0".parse().expect("valid sentinel addr")),
        }
    }
}

/// Identity-or-address dedup key for a candidate (so we never dial the same peer twice concurrently).
///
/// A peer is keyed by its `peer_id` once known, else by its address. The planner + in-flight
/// reservation set use this so the same peer is never dialed twice at once (POOL dedup rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateKey {
    /// Keyed by verified/known `peer_id`.
    Id(PeerId),
    /// Keyed by address (identity not yet known).
    Addr(SocketAddr),
}

/// Capped-exponential backoff bookkeeping for a single dial candidate.
///
/// After a failed dial the candidate is not retried until `next_retry_at`; each consecutive failure
/// doubles the delay up to the configured cap (so a flapping peer is retried rarely, not hammered).
/// A success resets the record. After [`PeerPoolConfig::max_dial_failures`] consecutive failures the
/// candidate is considered dead for the session ([`Self::is_dead`]) and dropped from the rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialBackoff {
    /// Consecutive failed dials (reset to 0 on success).
    pub failures: u32,
    /// Unix seconds before which this candidate must not be re-dialed.
    pub next_retry_at: u64,
}

impl DialBackoff {
    /// Fresh record — dialable immediately, zero failures.
    pub fn new() -> Self {
        DialBackoff {
            failures: 0,
            next_retry_at: 0,
        }
    }

    /// Whether this candidate may be dialed at `now` (backoff window elapsed).
    pub fn is_ready(&self, now: u64) -> bool {
        now >= self.next_retry_at
    }

    /// Whether this candidate has failed too many times to keep trying this session.
    pub fn is_dead(&self, max_failures: u32) -> bool {
        self.failures >= max_failures
    }

    /// Record a failed dial at `now`: bump the failure count and push `next_retry_at` out by the
    /// capped-exponential delay `base * 2^(failures-1)` (clamped to `max`).
    pub fn record_failure(&mut self, now: u64, base_secs: u64, max_secs: u64) {
        self.failures = self.failures.saturating_add(1);
        // `base * 2^(failures-1)`, saturating, capped at `max`. Shift is bounded to avoid overflow.
        let shift = self.failures.saturating_sub(1).min(16);
        let delay = base_secs
            .saturating_mul(1u64.checked_shl(shift).unwrap_or(u64::MAX))
            .min(max_secs.max(base_secs));
        self.next_retry_at = now.saturating_add(delay);
    }
}

impl Default for DialBackoff {
    fn default() -> Self {
        Self::new()
    }
}

/// The PURE plan for one maintenance pass: which candidates to dial (and how many slots are free).
///
/// Produced by [`plan_pass`] from the current live count, in-flight dial count, the (normalized)
/// config, and the candidate list + backoff table. The async loop just executes it — so the policy
/// (fill to target, cap at max, dedup, skip connected/backed-off/dead) is testable with plain data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolPlan {
    /// Candidates to dial this pass, most-preferred first, already deduped and within the free-slot
    /// budget. Empty when the pool is at/above target or no eligible candidate remains.
    pub to_dial: Vec<PoolCandidate>,
    /// How many free connection slots existed at plan time (`target - live - in_flight`, clamped to
    /// the `max` budget). Diagnostics; `to_dial.len() <= free_slots`.
    pub free_slots: usize,
}

/// Inputs describing the pool's current state for [`plan_pass`] (kept as a struct so the pure planner
/// has no dependency on the live [`ServiceState`]).
#[derive(Debug, Clone)]
pub struct PoolSnapshot<'a> {
    /// Number of peers currently connected (live + adopted).
    pub connected: usize,
    /// Number of dials currently in flight (reserved slots not yet resolved).
    pub in_flight: usize,
    /// Dedup keys of peers already connected — never dialed again.
    pub connected_keys: &'a [CandidateKey],
    /// Ordered candidate list (most-preferred first) from discovery / the address manager.
    pub candidates: &'a [PoolCandidate],
    /// Per-candidate backoff table (missing entry == dialable, zero failures).
    pub backoff: &'a HashMap<CandidateKey, DialBackoff>,
    /// Current unix time (seconds) for backoff-window checks.
    pub now: u64,
}

/// Compute the free-slot budget: how many MORE outbound connections the pool wants right now.
///
/// `target - (connected + in_flight)`, then clamped so `connected + in_flight + budget <= max`. Never
/// negative. This is the single rule that both fills toward target and caps at max.
pub fn free_slot_budget(connected: usize, in_flight: usize, cfg: &PeerPoolConfig) -> usize {
    let cfg = cfg.normalized();
    let current = connected.saturating_add(in_flight);
    let want_to_target = cfg.target_peers.saturating_sub(current);
    let room_to_max = cfg.max_peers.saturating_sub(current);
    want_to_target.min(room_to_max)
}

/// Plan one maintenance pass: pick up to the free-slot budget of eligible candidates to dial.
///
/// A candidate is ELIGIBLE when it is not already connected, not already selected this pass (dedup by
/// `peer_id`-or-address), not within its backoff window, and not marked dead. The result preserves
/// the candidate order (callers pass most-preferred — e.g. most-direct / most-diverse — first).
pub fn plan_pass(snap: &PoolSnapshot, cfg: &PeerPoolConfig) -> PoolPlan {
    let cfg = cfg.normalized();
    let free_slots = free_slot_budget(snap.connected, snap.in_flight, &cfg);
    if free_slots == 0 {
        return PoolPlan {
            to_dial: Vec::new(),
            free_slots: 0,
        };
    }

    let connected: std::collections::HashSet<CandidateKey> =
        snap.connected_keys.iter().copied().collect();
    let mut chosen_keys: std::collections::HashSet<CandidateKey> = std::collections::HashSet::new();
    let mut to_dial = Vec::with_capacity(free_slots);

    for cand in snap.candidates {
        if to_dial.len() >= free_slots {
            break;
        }
        let key = cand.dedup_key();
        // Already connected — never redial.
        if connected.contains(&key) {
            continue;
        }
        // Already selected this pass — dedup.
        if chosen_keys.contains(&key) {
            continue;
        }
        // Backed off or dead?
        if let Some(b) = snap.backoff.get(&key) {
            if b.is_dead(cfg.max_dial_failures) || !b.is_ready(snap.now) {
                continue;
            }
        }
        chosen_keys.insert(key);
        to_dial.push(cand.clone());
    }

    PoolPlan {
        to_dial,
        free_slots,
    }
}

/// Mutable pool bookkeeping held inside [`ServiceState`] — the dial backoff table, the in-flight
/// reservation set, and the churn event broadcaster.
///
/// The connected SET itself is not stored here (it is the `ServiceState::peers` map); this struct only
/// holds the extra state the maintenance policy needs.
pub struct PoolState {
    /// Per-candidate capped-exponential dial backoff (keyed by `peer_id`-or-address).
    pub(crate) backoff: Mutex<HashMap<CandidateKey, DialBackoff>>,
    /// Dedup keys of dials currently in flight — reserved so two passes (or a pass + a manual connect)
    /// never dial the same peer at once, and so `free_slot_budget` accounts for pending connections.
    pub(crate) in_flight: Mutex<std::collections::HashSet<CandidateKey>>,
    /// Churn broadcaster: [`PoolEvent`]s go out here as peers join/leave. `None` until `start()` wires
    /// it (same lifecycle as the inbound channel).
    pub(crate) events_tx: Mutex<Option<broadcast::Sender<PoolEvent>>>,
}

impl PoolState {
    /// Construct empty pool bookkeeping (no events channel until `start()`).
    pub(crate) fn new() -> Self {
        PoolState {
            backoff: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(std::collections::HashSet::new()),
            events_tx: Mutex::new(None),
        }
    }

    /// Publish a churn event to all subscribers (no-op if the channel isn't wired or has no
    /// subscribers — a dropped event is never fatal).
    pub(crate) fn publish(&self, event: PoolEvent) {
        if let Ok(g) = self.events_tx.lock() {
            if let Some(tx) = g.as_ref() {
                let _ = tx.send(event);
            }
        }
    }

    /// Try to RESERVE a candidate key for an in-flight dial. Returns `true` if reserved (caller must
    /// dial then [`Self::release`]), `false` if a dial for this key is already in flight (skip it).
    pub(crate) fn reserve(&self, key: CandidateKey) -> bool {
        match self.in_flight.lock() {
            Ok(mut g) => g.insert(key),
            Err(_) => false,
        }
    }

    /// Release an in-flight reservation (call after the dial resolves, success or failure).
    pub(crate) fn release(&self, key: CandidateKey) {
        if let Ok(mut g) = self.in_flight.lock() {
            g.remove(&key);
        }
    }

    /// Number of dials currently in flight.
    pub(crate) fn in_flight_count(&self) -> usize {
        self.in_flight.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Record a successful dial for `key`: clear its backoff so it is immediately eligible again if it
    /// later drops.
    pub(crate) fn record_success(&self, key: CandidateKey) {
        if let Ok(mut g) = self.backoff.lock() {
            g.remove(&key);
        }
    }

    /// Record a failed dial for `key` at `now`, bumping its capped-exponential backoff.
    pub(crate) fn record_failure(&self, key: CandidateKey, now: u64, cfg: &PeerPoolConfig) {
        if let Ok(mut g) = self.backoff.lock() {
            let entry = g.entry(key).or_insert_with(DialBackoff::new);
            entry.record_failure(now, cfg.dial_backoff_base_secs, cfg.max_dial_backoff_secs);
        }
    }

    /// Snapshot the backoff table (clone) for a pure [`plan_pass`] call.
    pub(crate) fn backoff_snapshot(&self) -> HashMap<CandidateKey, DialBackoff> {
        self.backoff.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl std::fmt::Debug for PoolState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolState")
            .field(
                "backoff_entries",
                &self.backoff.lock().map(|g| g.len()).unwrap_or(0),
            )
            .field("in_flight", &self.in_flight_count())
            .finish_non_exhaustive()
    }
}

/// A snapshot summary of the pool's health, returned by
/// [`GossipHandle::pool_stats`](crate::service::gossip_handle::GossipHandle::pool_stats).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PoolStats {
    /// Peers currently connected (live + adopted).
    pub connected: usize,
    /// Dials currently in flight.
    pub in_flight: usize,
    /// Configured target the pool replenishes toward.
    pub target: usize,
    /// Configured minimum below which the node is under-connected.
    pub min: usize,
    /// Configured hard cap.
    pub max: usize,
    /// Candidates currently in a backoff/dead state (not dialable right now).
    pub backed_off: usize,
}

impl PoolStats {
    /// Whether the pool is under-connected (below `min`) — a signal to prioritise discovery/dialing.
    pub fn is_under_connected(&self) -> bool {
        self.connected < self.min
    }

    /// Whether the pool has reached its target (steady state).
    pub fn is_at_target(&self) -> bool {
        self.connected >= self.target
    }
}

/// Abstraction over "dial one candidate and, on success, put it in the connected pool".
///
/// Implemented for production by the [`GossipHandle`](crate::service::gossip_handle::GossipHandle)
/// (which dials via `dig-nat`'s `connect_via_nat` and adopts the connection), and by tests with
/// loopback / in-memory peers — so the maintenance loop is exercised end-to-end WITHOUT a real
/// network. The dialer reports the resulting `peer_id` on success so the loop can record it + emit a
/// [`PoolEvent::PeerAdded`].
///
/// `dial` must be bounded (never hang): the caller relies on it returning within a reasonable time so
/// the maintenance loop makes progress. `dig-nat` guarantees this via its per-method timeout.
#[allow(async_fn_in_trait)]
pub trait Dialer: Send + Sync {
    /// Attempt to connect to `candidate` and add it to the pool. On success return the verified
    /// `peer_id`; on failure return an error string (used only for logging + backoff).
    async fn dial(&self, candidate: &PoolCandidate) -> Result<PeerId, String>;
}

/// Run ONE maintenance pass against a live pool: plan the dials, then execute them through `dialer`,
/// recording each outcome (success clears backoff + emits `PeerAdded`; failure bumps backoff).
///
/// Returns the number of NEW peers added this pass. Reserves each candidate in-flight for the
/// duration of its dial so concurrent passes / manual connects never double-dial the same peer, and
/// releases the reservation when the dial resolves. Bounded by the dialer's own per-dial timeout.
///
/// This is the executable half of the pool; the decision half is the pure [`plan_pass`]. `connected`
/// / `connected_keys` are supplied by the caller (read from `ServiceState::peers`) so this stays
/// independent of the exact peer-map layout.
pub async fn run_maintenance_pass<D: Dialer>(
    pool: &Arc<PoolState>,
    cfg: &PeerPoolConfig,
    connected: usize,
    connected_keys: &[CandidateKey],
    candidates: &[PoolCandidate],
    now: u64,
    dialer: &D,
) -> usize {
    let backoff = pool.backoff_snapshot();
    let snap = PoolSnapshot {
        connected,
        in_flight: pool.in_flight_count(),
        connected_keys,
        candidates,
        backoff: &backoff,
        now,
    };
    let plan = plan_pass(&snap, cfg);

    let mut added = 0usize;
    for cand in plan.to_dial {
        let key = cand.dedup_key();
        // Reserve the slot; if another dial for this key is already in flight, skip.
        if !pool.reserve(key) {
            continue;
        }
        let result = dialer.dial(&cand).await;
        pool.release(key);
        match result {
            Ok(peer_id) => {
                // Key the success by the identity we now know (so future dedup uses the real id).
                pool.record_success(CandidateKey::Id(peer_id));
                pool.record_success(key);
                if let Some(addr) = cand.addr {
                    pool.publish(PoolEvent::PeerAdded { peer_id, addr });
                }
                added += 1;
            }
            Err(_reason) => {
                pool.record_failure(key, now, cfg);
            }
        }
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u16) -> SocketAddr {
        format!("127.0.0.1:{n}").parse().unwrap()
    }

    fn cfg(min: usize, target: usize, max: usize) -> PeerPoolConfig {
        PeerPoolConfig {
            min_peers: min,
            target_peers: target,
            max_peers: max,
            ..Default::default()
        }
    }

    #[test]
    fn free_slot_budget_fills_toward_target_and_caps_at_max() {
        let c = cfg(2, 5, 8);
        // Empty pool wants target.
        assert_eq!(free_slot_budget(0, 0, &c), 5);
        // Half full wants the remainder.
        assert_eq!(free_slot_budget(3, 0, &c), 2);
        // In-flight dials count against the budget.
        assert_eq!(free_slot_budget(3, 2, &c), 0);
        // At target — no budget.
        assert_eq!(free_slot_budget(5, 0, &c), 0);
        // Never negative when above target.
        assert_eq!(free_slot_budget(7, 0, &c), 0);
    }

    #[test]
    fn budget_is_bounded_by_max_even_if_target_is_higher() {
        // Pathological but must not dial past max: target above max is clamped by normalized().
        let c = cfg(1, 10, 4);
        assert_eq!(free_slot_budget(0, 0, &c), 4);
        assert_eq!(free_slot_budget(3, 0, &c), 1);
        assert_eq!(free_slot_budget(4, 0, &c), 0);
    }

    #[test]
    fn plan_dedups_candidates_by_peer_id_and_address() {
        let c = cfg(1, 4, 8);
        let id = PeerId::from([7u8; 32]);
        let candidates = vec![
            PoolCandidate::with_id(id, addr(1)),
            // Same peer_id, different address — duplicate.
            PoolCandidate::with_id(id, addr(2)),
            PoolCandidate::from_addr(addr(3)),
            // Same address — duplicate.
            PoolCandidate::from_addr(addr(3)),
            PoolCandidate::from_addr(addr(4)),
        ];
        let backoff = HashMap::new();
        let snap = PoolSnapshot {
            connected: 0,
            in_flight: 0,
            connected_keys: &[],
            candidates: &candidates,
            backoff: &backoff,
            now: 0,
        };
        let plan = plan_pass(&snap, &c);
        // 3 unique: id, addr(3), addr(4).
        assert_eq!(plan.to_dial.len(), 3);
        assert_eq!(plan.to_dial[0].peer_id, Some(id));
        assert_eq!(plan.to_dial[1].addr, Some(addr(3)));
        assert_eq!(plan.to_dial[2].addr, Some(addr(4)));
    }

    #[test]
    fn plan_skips_already_connected_peers() {
        let c = cfg(1, 4, 8);
        let id = PeerId::from([9u8; 32]);
        let candidates = vec![
            PoolCandidate::with_id(id, addr(1)),
            PoolCandidate::from_addr(addr(2)),
        ];
        let backoff = HashMap::new();
        let snap = PoolSnapshot {
            connected: 1,
            in_flight: 0,
            connected_keys: &[CandidateKey::Id(id)],
            candidates: &candidates,
            backoff: &backoff,
            now: 0,
        };
        let plan = plan_pass(&snap, &c);
        assert_eq!(plan.to_dial.len(), 1);
        assert_eq!(plan.to_dial[0].addr, Some(addr(2)));
    }

    #[test]
    fn plan_respects_the_free_slot_budget() {
        let c = cfg(1, 3, 8);
        let candidates: Vec<_> = (10..20)
            .map(|n| PoolCandidate::from_addr(addr(n)))
            .collect();
        let backoff = HashMap::new();
        let snap = PoolSnapshot {
            connected: 1,
            in_flight: 0,
            connected_keys: &[],
            candidates: &candidates,
            backoff: &backoff,
            now: 0,
        };
        // target 3, connected 1 => budget 2.
        let plan = plan_pass(&snap, &c);
        assert_eq!(plan.free_slots, 2);
        assert_eq!(plan.to_dial.len(), 2);
    }

    #[test]
    fn plan_skips_backed_off_and_dead_candidates() {
        let c = cfg(1, 5, 8);
        let candidates = vec![
            PoolCandidate::from_addr(addr(1)),
            PoolCandidate::from_addr(addr(2)),
            PoolCandidate::from_addr(addr(3)),
        ];
        let mut backoff = HashMap::new();
        // addr(1): backed off until t=100 (now=10 -> not ready).
        backoff.insert(
            CandidateKey::Addr(addr(1)),
            DialBackoff {
                failures: 1,
                next_retry_at: 100,
            },
        );
        // addr(2): dead (>= max_dial_failures).
        backoff.insert(
            CandidateKey::Addr(addr(2)),
            DialBackoff {
                failures: c.max_dial_failures,
                next_retry_at: 0,
            },
        );
        let snap = PoolSnapshot {
            connected: 0,
            in_flight: 0,
            connected_keys: &[],
            candidates: &candidates,
            backoff: &backoff,
            now: 10,
        };
        let plan = plan_pass(&snap, &c);
        // Only addr(3) is eligible.
        assert_eq!(plan.to_dial.len(), 1);
        assert_eq!(plan.to_dial[0].addr, Some(addr(3)));
    }

    #[test]
    fn backoff_is_capped_exponential_and_resets() {
        let mut b = DialBackoff::new();
        assert!(b.is_ready(0));
        b.record_failure(0, 5, 300);
        assert_eq!(b.failures, 1);
        assert_eq!(b.next_retry_at, 5); // 5 * 2^0
        b.record_failure(0, 5, 300);
        assert_eq!(b.next_retry_at, 10); // 5 * 2^1
        b.record_failure(0, 5, 300);
        assert_eq!(b.next_retry_at, 20); // 5 * 2^2
                                         // Cap kicks in.
        for _ in 0..20 {
            b.record_failure(0, 5, 300);
        }
        assert_eq!(b.next_retry_at, 300); // capped
        assert!(b.is_dead(5));
    }

    #[tokio::test]
    async fn maintenance_pass_fills_to_target_via_the_dialer() {
        // A dialer that "connects" any candidate, minting a deterministic peer_id from the port.
        struct OkDialer;
        impl Dialer for OkDialer {
            async fn dial(&self, cand: &PoolCandidate) -> Result<PeerId, String> {
                let port = cand.addr.map(|a| a.port()).unwrap_or(0);
                let mut b = [0u8; 32];
                b[0..2].copy_from_slice(&port.to_le_bytes());
                Ok(PeerId::from(b))
            }
        }
        let pool = Arc::new(PoolState::new());
        let c = cfg(2, 4, 8);
        let candidates: Vec<_> = (1..=10)
            .map(|n| PoolCandidate::from_addr(addr(n)))
            .collect();
        // Empty pool -> should dial exactly `target` (4).
        let added = run_maintenance_pass(&pool, &c, 0, &[], &candidates, 0, &OkDialer).await;
        assert_eq!(added, 4);
        assert_eq!(
            pool.in_flight_count(),
            0,
            "reservations released after dial"
        );
    }

    #[tokio::test]
    async fn maintenance_pass_replenishes_after_a_drop() {
        struct OkDialer;
        impl Dialer for OkDialer {
            async fn dial(&self, cand: &PoolCandidate) -> Result<PeerId, String> {
                let port = cand.addr.map(|a| a.port()).unwrap_or(0);
                let mut b = [0u8; 32];
                b[0..2].copy_from_slice(&port.to_le_bytes());
                Ok(PeerId::from(b))
            }
        }
        let pool = Arc::new(PoolState::new());
        let c = cfg(2, 4, 8);
        let candidates: Vec<_> = (1..=10)
            .map(|n| PoolCandidate::from_addr(addr(n)))
            .collect();
        // Simulate 3 already connected (one dropped from a full pool of 4) -> replenish 1.
        let connected_keys = vec![
            CandidateKey::Addr(addr(1)),
            CandidateKey::Addr(addr(2)),
            CandidateKey::Addr(addr(3)),
        ];
        let added =
            run_maintenance_pass(&pool, &c, 3, &connected_keys, &candidates, 0, &OkDialer).await;
        assert_eq!(added, 1, "one slot below target -> dial exactly one more");
    }

    #[tokio::test]
    async fn maintenance_pass_records_failure_backoff() {
        struct FailDialer;
        impl Dialer for FailDialer {
            async fn dial(&self, _cand: &PoolCandidate) -> Result<PeerId, String> {
                Err("connection refused".to_string())
            }
        }
        let pool = Arc::new(PoolState::new());
        let c = cfg(1, 2, 4);
        let candidates = vec![
            PoolCandidate::from_addr(addr(1)),
            PoolCandidate::from_addr(addr(2)),
        ];
        let added = run_maintenance_pass(&pool, &c, 0, &[], &candidates, 100, &FailDialer).await;
        assert_eq!(added, 0);
        // Both candidates now backed off.
        let bo = pool.backoff_snapshot();
        assert_eq!(bo.len(), 2);
        assert!(bo.get(&CandidateKey::Addr(addr(1))).unwrap().next_retry_at > 100);
    }

    #[test]
    fn pool_stats_flags_under_connected_and_at_target() {
        let s = PoolStats {
            connected: 1,
            in_flight: 0,
            target: 4,
            min: 2,
            max: 8,
            backed_off: 0,
        };
        assert!(s.is_under_connected());
        assert!(!s.is_at_target());
        let s2 = PoolStats { connected: 5, ..s };
        assert!(!s2.is_under_connected());
        assert!(s2.is_at_target());
    }

    #[test]
    fn events_publish_reaches_subscribers() {
        let pool = PoolState::new();
        let (tx, mut rx) = broadcast::channel(8);
        *pool.events_tx.lock().unwrap() = Some(tx);
        let id = PeerId::from([1u8; 32]);
        pool.publish(PoolEvent::PeerAdded {
            peer_id: id,
            addr: addr(9),
        });
        let ev = rx.try_recv().expect("event delivered");
        assert_eq!(
            ev,
            PoolEvent::PeerAdded {
                peer_id: id,
                addr: addr(9)
            }
        );
    }

    #[test]
    fn reserve_dedups_in_flight_dials() {
        let pool = PoolState::new();
        let k = CandidateKey::Addr(addr(1));
        assert!(pool.reserve(k), "first reservation succeeds");
        assert!(!pool.reserve(k), "second reservation for same key fails");
        pool.release(k);
        assert!(pool.reserve(k), "reservable again after release");
    }
}
