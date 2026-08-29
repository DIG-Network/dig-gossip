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
    /// Evicted by the departed-peer reaper (#1703 item 2) — the peer's transport was provably
    /// closed but, being a keepalive-less `dig-nat` slot, nothing else observed its departure.
    /// Distinguished from [`Self::Dead`] (a CON-004 keepalive eviction) so churn consumers can tell
    /// the periodic sweep apart from the keepalive path.
    Reaped,
    /// Cycled out — while healthy — to make room for a holder content discovery found outside the
    /// persistent set (**dig_ecosystem#3128** requirement 8).
    ///
    /// The only removal reason that is not a failure. Every other variant reports a peer that broke,
    /// misbehaved or left; this one reports a peer that was fine and was simply contributing nothing,
    /// so a consumer must not read it as evidence against the peer. It is deliberately distinct for
    /// that reason: eviction here had no vocabulary at all, which is what made the policy
    /// inexpressible rather than merely unimplemented.
    Displaced,
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

    /// EVERY identity dimension by which this candidate could match an already-connected peer: its
    /// `peer_id` (when known) AND its address (when known).
    ///
    /// The skip-connected filter (#2176) must match on *either* dimension, not just the single
    /// [`Self::dedup_key`]. A peer already in the pool is recorded under BOTH keys (peer_id + addr) by
    /// [`ServiceState::connected_pool_keys`](crate::service::state::ServiceState); a peer-exchange
    /// candidate for that same peer, however, carries only its ADDRESS. Comparing just `dedup_key`
    /// (which prefers `Id` and would key an id-bearing candidate to `Id`) against an address-keyed
    /// connected entry — or the reverse — misses the match, and the pool re-dials a peer it already
    /// holds every maintenance pass (the ~30s churn this method's caller closes). Yielding both keys
    /// lets the planner exclude the candidate when EITHER dimension is already connected.
    fn identity_keys(&self) -> impl Iterator<Item = CandidateKey> {
        self.peer_id
            .map(CandidateKey::Id)
            .into_iter()
            .chain(self.addr.map(CandidateKey::Addr))
    }
}

/// Identity-or-address dedup key for a candidate (so we never dial the same peer twice concurrently).
///
/// A peer is keyed by its `peer_id` once known, else by its address. The planner + in-flight
/// reservation set use this so the same peer is never dialed twice at once (POOL dedup rule).
///
/// A *candidate* is dedup'd by a single preferred key ([`PoolCandidate::dedup_key`]), but an
/// already-*connected* peer is recorded under BOTH keys it is known by (#2176) so the skip-connected
/// filter can match a candidate on either dimension — see [`PoolSnapshot::connected_keys`].
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
    /// Number of peers currently connected (live + adopted), counting the UNION of directly-connected
    /// and relay-reachable peers (a peer reachable both ways counted once — #870 finding 1). Drives the
    /// fill-toward-target / cap-at-max math.
    pub connected: usize,
    /// Of [`Self::connected`], how many are in the live DIRECT pool. Drives the direct-dial floor
    /// (#870 finding 2) so relay-reachable peers can never starve direct dialing to zero. When there is
    /// no relay, this equals `connected`.
    pub direct_connected: usize,
    /// Number of dials currently in flight (reserved slots not yet resolved).
    pub in_flight: usize,
    /// Identity keys of peers already connected — never dialed again. Each connected peer contributes
    /// BOTH dimensions it is known by (#2176): a [`CandidateKey::Id`] for its `peer_id` AND a
    /// [`CandidateKey::Addr`] for its address (a relay-transport peer contributes only its `Id`, since
    /// its remote is the relay endpoint, not the peer's own routable address). Carrying both is what
    /// lets [`plan_pass`] exclude a candidate that matches an already-connected peer on EITHER
    /// dimension — so a peer held by `peer_id` but offered address-only (or vice-versa) is never
    /// re-dialed.
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

/// One quarter of `target_peers` (at least 1): the minimum number of DIRECT peer connections the pool
/// always works toward, regardless of how many peers a relay advertises as reachable.
///
/// Without this floor a compromised or misbehaving relay reporting `>= target_peers` known peers would
/// drive the free-slot budget to zero (#870 finding 2), stopping the node from making ANY direct dials
/// and stranding it on that single relay with no independent fan-out. A quarter keeps meaningful direct
/// connectivity for gossip resilience while still letting genuine relay reachability reduce redundant
/// dialing. Relay-reachable peers count toward reachability/health/stats — they just cannot zero out
/// the direct-dial budget.
fn min_direct_peers(cfg: &PeerPoolConfig) -> usize {
    (cfg.target_peers / 4).max(1)
}

/// The maximum number of RELAYED-tier outbound connections the pool admits (#1716).
///
/// Relayed peers are exempt from the /16//AS diversity cap ([`outbound_diversity_conflict`] returns
/// `None` for them) because their `remote_addr` is the relay endpoint, not a routable peer address —
/// so the cap gives zero eclipse value on that tier. Left wholly ungated, though, a Sybil could flood
/// the outbound budget with relayed reservations. This bound keeps the relayed tier open (a NAT'd node
/// can hold several relayed peers) while RESERVING at least `target_outbound_count - max_relayed_outbound`
/// (≥2 with the default 8) outbound slots for diversity-checked non-relayed peers.
///
/// Mirrors the #870 direct-floor derivation (`target/4`, min 1): reserve a quarter of the outbound
/// budget for the diversity-checked tier, cap the rest as relayed → **6** with the default target of 8.
pub(crate) fn max_relayed_outbound(target_outbound_count: usize) -> usize {
    reserving_a_quarter(target_outbound_count)
}

/// The maximum number of ACCEPTED (responder-side) relayed circuits the pool admits (#870/#1871).
///
/// A relay introduces circuits to a reservation holder, so — left ungated — a single misbehaving
/// relay could occupy the node's entire connection budget with peers it chose, an eclipse by
/// introduction rather than by dialing.
///
/// A reserved quarter of the INBOUND budget ([`max_inbound_total`]), exactly as
/// [`max_direct_inbound`] takes the other tier's share out of the same budget. **The two inbound
/// tiers are derived symmetrically, and that symmetry is the security property**, not a tidiness
/// preference: taking each tier's cap out of the shared aggregate is the only arrangement in which
/// NEITHER tier can consume the whole of it.
///
/// Applying the reserve to `max_connections` here instead — one level up, where the aggregate is also
/// taken — made this cap equal to [`max_inbound_total`] for every input, with two consequences. It was
/// **vacuous**: the aggregate is charged immediately after it on the same path with an equivalent
/// exemption, so no state existed in which this cap changed the outcome. And it made the reservation
/// **one-way**: the direct tier was held to 5 of 6 so a circuit always had a slot, while the relayed
/// tier was held to 6 of 6, so six circuits — an ordinary load for a NAT'd node, and free for anyone
/// who can open circuits through this node's relay — left the direct tier ZERO. That is a live denial
/// of the very path #3124 exists to register, and the relayed tier is the one that can never be
/// source-bounded: a circuit's `remote` is the relay endpoint, so
/// [`crate::service::state::outbound_diversity_conflict`] returns `None` for it by construction and
/// [`max_direct_inbound_per_group`] has no analogue on that tier.
///
/// `max_relayed_inbound(8) == 5`, against an aggregate of 6: a full relayed tier still leaves a slot
/// for a direct accept, and a full direct tier still leaves one for a circuit.
///
/// Derived identically to [`max_direct_inbound`] and, one level up, to [`max_relayed_outbound`] and
/// the #870 direct-dial floor, so the reserve is ONE rule with several applications rather than
/// several constants that can drift apart.
pub(crate) fn max_relayed_inbound(max_connections: usize) -> usize {
    a_reserved_share_of(max_inbound_total(max_connections))
}

/// **dig_ecosystem#3124** — how many ACCEPTED direct connections may hold pool slots at once.
///
/// Inbound peers must not be able to fill the pool. Every slot an accepted connection holds is one
/// the maintenance loop cannot use to dial a peer of THIS node's choosing, so an unbounded accepted
/// tier lets anyone who can complete a handshake decide this node's entire peer set — the eclipse
/// [`max_relayed_inbound`] already guards on the relayed path, reachable here without a relay at all.
///
/// A reserved quarter again — but of the INBOUND budget ([`max_inbound_total`]), not of the pool.
///
/// Applying the reserve to the pool a second time is what made the two inbound caps fail to compose:
/// `max_direct_inbound == max_relayed_inbound == max_inbound_total` leaves the direct cap unable to
/// ever bind, and — before the aggregate bound existed — let the two tiers sum to the whole pool.
/// Taking the direct tier's share OUT of the inbound budget keeps every cap load-bearing and reserves
/// room on the tier a NAT'd peer has no alternative to: a peer that can only be reached through a
/// relay cannot instead arrive directly, so a flood of direct accepts must not be able to deny it.
///
/// `max_direct_inbound(8) == 5`: at most five accepted direct peers, at most six accepted peers
/// overall. [`max_relayed_inbound`] is derived the same way from the same budget, so the reservation
/// runs in BOTH directions — see the discussion there.
pub(crate) fn max_direct_inbound(max_connections: usize) -> usize {
    a_reserved_share_of(max_inbound_total(max_connections))
}

/// **dig_ecosystem#3124** — how many ACCEPTED connections of ANY inbound tier may hold pool slots at
/// once, direct and relayed counted TOGETHER.
///
/// # Why an aggregate bound exists at all
///
/// [`max_direct_inbound`] and [`max_relayed_inbound`] are each a reserved quarter and were counted
/// separately, which bounds each tier's size and NEITHER tier's share of the sum: at the default
/// `max_connections = 8` that is `6 + 2 = 8`, a pool filled entirely by peers the other side chose.
/// The reserve every one of these caps is written to protect only exists if the two tiers draw from
/// ONE budget, so this is the bound the per-tier caps sit under rather than beside.
///
/// The same reserved quarter again, for the same reason the per-tier caps share it: one rule with
/// several applications cannot drift the way several constants can. `max_inbound_total(8) == 6`,
/// leaving two of the eight slots to the peers this node itself reaches — whatever mixture of the two
/// ACCEPTED tiers arrives.
///
/// # Exactly which slots this budget counts, and which it does not
///
/// This bound is charged over [`crate::service::state::is_accepted_inbound`], which is scoped to
/// `PeerSlot::Nat` — the two adoption entry points, and only those. It is therefore a reserve
/// **against the accepted `dig-nat` tiers**, and it is deliberately NOT a whole-pool guarantee: an
/// inbound Chia-protocol WebSocket peer is inserted as a `Stub`/`Live` slot by the listener, which
/// bounds itself against `max_connections` alone, so a pool filled that way can leave this reserve
/// with nothing behind it. `MaxConnectionsReached` is what bounds that path today.
///
/// Stated deliberately rather than by omission, because the narrower claim is the TRUE one and the
/// broader one ("two slots are free whatever arrives") would be false the moment a reader relied on
/// it. Extending the aggregate to charge the listener is a change to this crate's most reachable
/// inbound path and belongs to its own unit of work, not to #3124.
pub(crate) fn max_inbound_total(max_connections: usize) -> usize {
    reserving_a_quarter(max_connections)
}

/// **dig_ecosystem#3124** — how many ACCEPTED DIRECT peers may share one SOURCE GROUP: an IPv4 `/16`
/// or an IPv6 `/48`, as [`crate::util::ip_address::inbound_source_group`] derives it.
///
/// # Why the pool-wide cap is not enough
///
/// A pool-wide inbound bound answers "how many strangers", not "how many strangers from ONE place",
/// and on this path identities are free: any host can mint arbitrarily many CA-signed leaves locally
/// (`crate::nat`), so one machine can present one identity per slot and occupy the entire accepted
/// tier by itself. That is the eclipse INT-006 bounds on the outbound side, reachable inbound without
/// dialing anything — and [`crate::service::state::outbound_diversity_conflict`] deliberately does
/// not apply here, because an inbound peer occupies no OUTBOUND group.
///
/// A quarter of the accepted-direct tier, at least two — two so a genuine pair of nodes behind one
/// NAT is never refused, a quarter so no single group can crowd the tier. `== 2` at the default 8,
/// `== 8` at 50.
pub(crate) fn max_direct_inbound_per_group(max_connections: usize) -> usize {
    (max_direct_inbound(max_connections).div_ceil(4)).max(2)
}

/// `n` less a reserved quarter (at least one) — the ecosystem's single "leave room for the other
/// tier" derivation. `reserving_a_quarter(8) == 6`.
fn reserving_a_quarter(n: usize) -> usize {
    n.saturating_sub((n / 4).max(1))
}

/// ONE inbound tier's share of the inbound budget: a reserved quarter of it, but never ZERO while
/// the budget can hold a peer at all.
///
/// The floor is the half of the reservation that a plain [`reserving_a_quarter`] cannot express.
/// Applying the quarter twice — once to reach the inbound budget, once to reach a tier's share of it
/// — collapses to `0` for every `max_connections <= 3`, because `reserving_a_quarter(1) == 0`. A cap
/// of zero does not RESERVE a tier's room, it DENIES the tier outright: at `max_connections = 2`
/// every relayed circuit this node serves was refused with
/// `accepted relayed circuit cap reached (0)`, which is the same starvation the symmetric derivation
/// exists to prevent, merely inflicted on the other side.
///
/// One slot is the smallest cap that leaves a tier reachable, and it costs the sibling tier nothing
/// it is entitled to: the aggregate [`max_inbound_total`] is charged on the same path, so two tiers
/// each floored at `1` still cannot exceed the shared budget — whichever peer arrives first takes the
/// single slot, and neither tier is closed by construction. Clamped to the budget so a budget of zero
/// stays zero.
fn a_reserved_share_of(inbound_budget: usize) -> usize {
    reserving_a_quarter(inbound_budget)
        .max(1)
        .min(inbound_budget)
}

/// A connected pool member as PEER SELECTION sees it: who it is, how it is reached, which side
/// opened it, and — the load-bearing field — whether it may be dialed at all.
///
/// [`Self::dial_addr`] is the reason this type exists. A relayed peer is genuinely connected but has
/// no address at which it answers, so "connected" and "dialable" are different questions and a caller
/// that conflates them will dial the relay endpoint forever. Encoding the distinction as an
/// `Option<SocketAddr>` makes the mistake unexpressible rather than merely documented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedPoolPeer {
    /// The verified peer identity.
    pub peer_id: PeerId,
    /// How this node reaches the peer — [`Via::Relay`](crate::nat::peer_record::Via) for a peer whose
    /// traffic is tunnelled through a relay, [`Via::Direct`](crate::nat::peer_record::Via) otherwise.
    pub via: crate::nat::peer_record::Via,
    /// Whether THIS node initiated the connection. An accepted relayed circuit is inbound.
    pub is_outbound: bool,
    /// The address at which this peer may be dialed, or `None` when it has none (every relayed
    /// peer). A `None` here is a structural refusal, not a missing lookup: there is no address to
    /// find.
    pub dial_addr: Option<SocketAddr>,
    /// The endpoint the session actually runs over — the peer, or the relay for a relayed link.
    /// Observability only; NEVER a dial target (that is [`Self::dial_addr`]).
    pub session_addr: SocketAddr,
}

/// Free-slot budget that lets relay-reachable peers reduce redundant direct dialing WITHOUT letting
/// them starve direct dialing below [`min_direct_peers`].
///
/// `direct_connected` is the live direct-pool size; `relay_reachable` is the count of peers reachable
/// only through the relay reservation, already de-duplicated against the direct set (a peer reachable
/// both ways is counted once, as direct — #870 finding 1). The relay-aware budget treats relay-reachable
/// peers as connected so the pool doesn't dial for slots the relay already fills; the direct-dial floor
/// then guarantees the pool keeps working toward [`min_direct_peers`] direct connections no matter how
/// many peers the relay advertises. The floor may raise the budget above the relay-aware value, but
/// direct dialing still never exceeds the hard cap on direct connections.
pub fn free_slot_budget_with_direct_floor(
    direct_connected: usize,
    relay_reachable: usize,
    in_flight: usize,
    cfg: &PeerPoolConfig,
) -> usize {
    let cfg = cfg.normalized();
    let relay_aware = free_slot_budget(
        direct_connected.saturating_add(relay_reachable),
        in_flight,
        &cfg,
    );
    let direct_current = direct_connected.saturating_add(in_flight);
    let floor_budget = min_direct_peers(&cfg).saturating_sub(direct_current);
    let room_to_max = cfg.max_peers.saturating_sub(direct_current);
    relay_aware.max(floor_budget).min(room_to_max)
}

/// Plan one maintenance pass: pick up to the free-slot budget of eligible candidates to dial.
///
/// A candidate is ELIGIBLE when it is not already connected, not already selected this pass (dedup by
/// `peer_id`-or-address), not within its backoff window, and not marked dead. The result preserves
/// the candidate order (callers pass most-preferred — e.g. most-direct / most-diverse — first).
///
/// "Not already connected" is tested on EITHER identity dimension (#2176): a candidate is excluded
/// when its `peer_id` OR its address matches any peer in [`PoolSnapshot::connected_keys`] (which
/// records both dimensions of each held peer). This makes re-dialing an already-connected peer
/// unrepresentable regardless of whether the pool holds it by id and the candidate offers an address,
/// or vice-versa — the mismatch that otherwise re-dials a held peer every maintenance pass.
pub fn plan_pass(snap: &PoolSnapshot, cfg: &PeerPoolConfig) -> PoolPlan {
    let cfg = cfg.normalized();
    let relay_reachable = snap.connected.saturating_sub(snap.direct_connected);
    let free_slots = free_slot_budget_with_direct_floor(
        snap.direct_connected,
        relay_reachable,
        snap.in_flight,
        &cfg,
    );
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
        // Already connected — never redial. Match on EITHER identity dimension (#2176): the
        // connected set carries both the peer_id AND the address of each held peer, and a candidate
        // is the same peer if either of ITS dimensions matches. Keying only by `dedup_key` misses a
        // peer connected under one dimension but offered under the other (id-in-pool vs
        // address-only peer-exchange candidate), which re-dials an already-held peer every pass.
        if cand.identity_keys().any(|k| connected.contains(&k)) {
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

// ---------------------------------------------------------------------------
// Displacement (dig_ecosystem#3128 requirement 8) — cycling an UNUSED connection
// out so a holder content discovery found can be held instead.
// ---------------------------------------------------------------------------

/// What the pool knows about ONE held peer's usefulness to this node.
///
/// # Why usefulness has to be reported rather than observed
///
/// The pool never sends over a `dig-nat` slot's transport — the gossip loop for such a peer is wired
/// in dig-node, not here — so this crate cannot see a peer being used and must be told. That is what
/// [`GossipHandle::peer_activity_guard`](crate::GossipHandle::peer_activity_guard) is for, and it is
/// also why the metric is deliberately narrow: it measures what THIS node did with the peer, and
/// nothing about what the peer holds.
///
/// A peer that is quiet but holds rare content is therefore not distinguished here — it is
/// distinguished by its USER. dig-node marks a peer active whenever it fetches from it, so a rarely
/// but genuinely used holder keeps a recent [`Self::last_active_at`] and is never the idlest peer. A
/// peer this node has never once talked to is idle from the moment it was admitted, which is the
/// honest reading: whatever it may hold, this node has never obtained anything from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerActivity {
    /// The held peer.
    pub peer_id: PeerId,
    /// Unix seconds at which this peer was admitted (a supersede re-admits, resetting this).
    pub admitted_at: u64,
    /// Unix seconds of the most recent time work started or finished over this peer. Equals
    /// [`Self::admitted_at`] for a peer that has never been used.
    pub last_active_at: u64,
    /// How many pieces of work are in flight over this peer right now. Non-zero means "mid-request",
    /// and a peer mid-request is never displaced regardless of every other measure.
    pub in_flight: usize,
}

impl PeerActivity {
    /// Whether this peer may be cycled out at `now` under `cfg` — unused for long enough, held for
    /// long enough, and with nothing in flight.
    fn is_displaceable(&self, now: u64, cfg: &PeerPoolConfig) -> bool {
        self.in_flight == 0
            && now.saturating_sub(self.admitted_at) >= cfg.min_established_secs
            && now.saturating_sub(self.last_active_at) >= cfg.min_idle_secs
    }
}

/// Everything the pure displacement planner needs, so the policy is testable without a socket (the
/// same split [`plan_pass`] uses for the maintenance policy).
#[derive(Debug, Clone)]
pub struct DisplacementRequest<'a> {
    /// Peers currently held, counting EVERY slot kind — this is what the admission cap compares.
    pub connected: usize,
    /// The hard admission cap (`GossipConfig::max_connections`). Below it there is nothing to
    /// displace, because the peer can simply be admitted.
    pub capacity: usize,
    /// Every incumbent that is a candidate to be cycled out, in any order.
    pub incumbents: &'a [PeerActivity],
    /// Unix seconds of the last displacement this pool performed, or `None` if it never has.
    pub last_displacement_at: Option<u64>,
    /// Current unix time (seconds).
    pub now: u64,
}

/// What the pool should do with a discovered holder that wants a place in the persistent set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplacementDecision {
    /// There is a free slot — admit without cycling anyone out.
    RoomAlready,
    /// Cycle this incumbent out, then admit.
    Displace(PeerId),
    /// Do not admit, for this reason.
    Refused(DisplacementRefusal),
}

/// Why a discovered holder was not given a place in the persistent set.
///
/// Named rather than collapsed into one error because the three mean different things to a caller: one
/// says try again later, one says the pool is too small to cycle at all, and one says every peer held
/// is doing useful work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplacementRefusal {
    /// The churn bound (`displacement_interval_secs`) has not elapsed since the last displacement.
    RateLimited {
        /// Seconds until a displacement would be allowed again.
        retry_after_secs: u64,
    },
    /// Cycling anyone out would take the pool to or below `min_peers`, leaving it under-connected.
    WouldBreachMinPeers,
    /// Every incumbent is either in use, too recently used, or too recently admitted.
    NoIdleIncumbent,
}

/// Decide whether a discovered holder may take a place in the persistent connection set, and at whose
/// expense (**dig_ecosystem#3128** requirement 8).
///
/// # The rules, in the order they apply
///
/// 1. **Room already** — below `capacity` nothing is displaced; ordinary admission handles it.
/// 2. **Never below `min_peers`** — a pool small enough that cycling would leave it under-connected
///    refuses instead. Losing a peer to gain a peer is neutral for a healthy pool and harmful for a
///    starving one.
/// 3. **The churn bound** — at most one displacement per `displacement_interval_secs`. This is the
///    bound on the attacker-reachable lever: a provider record is a claim by an untrusted peer, so a
///    hostile peer that gets itself returned as a holder reaches this path directly, and without a
///    rate it could choose the whole persistent set one lookup at a time. See
///    [`DEFAULT_POOL_DISPLACEMENT_INTERVAL_SECS`](crate::constants::DEFAULT_POOL_DISPLACEMENT_INTERVAL_SECS)
///    for why the interval is enough.
/// 4. **The victim is the idlest DISPLACEABLE incumbent** — nothing in flight, held for at least
///    `min_established_secs`, unused for at least `min_idle_secs`; among those, the one used longest
///    ago. Ties break on the older admission and then on identity, so the choice is deterministic
///    rather than dependent on map iteration order.
///
/// Rules 2-4 are all necessary: 2 protects connectivity, 3 protects against a chosen set, and 4 is
/// what makes "unused" mean unused rather than merely least-recently-used.
pub fn plan_displacement(req: &DisplacementRequest, cfg: &PeerPoolConfig) -> DisplacementDecision {
    let cfg = cfg.normalized();
    if req.connected < req.capacity {
        return DisplacementDecision::RoomAlready;
    }
    if req.connected <= cfg.min_peers {
        return DisplacementDecision::Refused(DisplacementRefusal::WouldBreachMinPeers);
    }
    if let Some(last) = req.last_displacement_at {
        let next_allowed = last.saturating_add(cfg.displacement_interval_secs);
        if req.now < next_allowed {
            return DisplacementDecision::Refused(DisplacementRefusal::RateLimited {
                retry_after_secs: next_allowed - req.now,
            });
        }
    }
    req.incumbents
        .iter()
        .filter(|peer| peer.is_displaceable(req.now, &cfg))
        .min_by_key(|peer| (peer.last_active_at, peer.admitted_at, peer.peer_id))
        .map_or(
            DisplacementDecision::Refused(DisplacementRefusal::NoIdleIncumbent),
            |victim| DisplacementDecision::Displace(victim.peer_id),
        )
}

/// The outcome of admitting a holder content discovery found: who was admitted, and who — if anyone —
/// was cycled out to make room.
///
/// `displaced` is `Some` only when the pool was at capacity and an unused incumbent was retired for
/// this peer. A caller that tracks its own view of the connected set needs that identity, and the
/// alternative (inferring it from the churn bus) is a race against the very event this returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryAdmission {
    /// The verified identity now in the pool.
    pub peer_id: PeerId,
    /// The peer cycled out to make room, or `None` when a slot was already free.
    pub displaced: Option<PeerId>,
}

/// The per-peer usefulness record the pool keeps for each held peer, behind [`PoolState`]'s lock.
#[derive(Debug, Clone, Copy)]
struct ActivityRecord {
    admitted_at: u64,
    last_active_at: u64,
    in_flight: usize,
}

/// Marks a held peer BUSY for as long as it is alive, and stamps it active at both ends
/// (**dig_ecosystem#3128** requirement 8).
///
/// Hold one for the duration of any work over a pool peer — a peer-RPC round trip, a range stream, a
/// parked recursive ask. While it lives the peer cannot be displaced at all, which is what makes
/// "never evict a peer mid-request" structural rather than a documented hope: a long transfer that
/// emits no intermediate signal is still protected, because the guard does not decay with time the way
/// a last-used stamp would.
///
/// Dropping it stamps the peer active again, so a request that has just finished leaves the peer at
/// the FRONT of the usefulness order rather than wherever it was when the request began.
#[must_use = "the peer counts as busy only while the guard is held"]
#[derive(Debug)]
pub struct PeerActivityGuard {
    pool: Arc<PoolState>,
    peer_id: PeerId,
}

impl PeerActivityGuard {
    /// Begin a unit of work over `peer_id`, or `None` when the pool holds no such peer.
    pub(crate) fn begin(pool: Arc<PoolState>, peer_id: PeerId, now: u64) -> Option<Self> {
        pool.begin_activity(peer_id, now)
            .then(|| PeerActivityGuard { pool, peer_id })
    }
}

impl Drop for PeerActivityGuard {
    fn drop(&mut self) {
        self.pool.end_activity(
            self.peer_id,
            crate::types::peer::metric_unix_timestamp_secs(),
        );
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
    /// Per-peer usefulness for the displacement policy (#3128 requirement 8).
    ///
    /// **Bounded by the peer map, and only by it.** An entry is created solely by
    /// [`Self::record_admission`] for a peer that was just inserted into `ServiceState::peers`, and is
    /// removed on every departure plus swept against the live map on every admission
    /// ([`Self::retain_admitted`]). Untrusted input never reaches it: a stranger cannot name a key
    /// here without first completing an mTLS handshake and passing admission. That matters because an
    /// unbounded map keyed by peer-supplied identity is a live defect class in this ecosystem.
    activity: Mutex<HashMap<PeerId, ActivityRecord>>,
    /// Unix seconds of the last discovery displacement, for the churn bound. `None` until the pool has
    /// displaced anyone.
    last_displacement_at: Mutex<Option<u64>>,
}

impl PoolState {
    /// Construct empty pool bookkeeping (no events channel until `start()`).
    pub(crate) fn new() -> Self {
        PoolState {
            backoff: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(std::collections::HashSet::new()),
            events_tx: Mutex::new(None),
            activity: Mutex::new(HashMap::new()),
            last_displacement_at: Mutex::new(None),
        }
    }

    /// Start tracking a peer's usefulness from its admission (#3128 requirement 8). A re-admission —
    /// the newest-wins supersede — resets both CLOCKS, because the session being measured is new.
    ///
    /// # It does not reset `in_flight` (dig-gossip#74)
    ///
    /// `in_flight` counts LIVE [`PeerActivityGuard`]s, and a supersede does not drop them: the guard
    /// is held by whoever is doing the work, not by the session. Re-inserting a fresh record with
    /// `in_flight: 0` therefore made "a peer mid-request is never displaced" a matter of TIMING — a
    /// supersede landing inside a live guard published a peer as idle while a transfer ran, and the
    /// guard's own `Drop` then decremented a count that no longer knew about it.
    ///
    /// So the reset writes only the two clocks. That is what makes the property structural rather than
    /// checked: `in_flight` is **never assigned on an existing record** anywhere in this type — it is
    /// created at `0` for a peer the map does not hold, incremented by [`Self::begin_activity`], and
    /// decremented by [`Self::end_activity`], which only [`PeerActivityGuard::drop`] calls. There is no
    /// code path that can zero it while a guard lives, so the count equals the number of live guards by
    /// construction.
    pub(crate) fn record_admission(&self, peer_id: PeerId, now: u64) {
        if let Ok(mut g) = self.activity.lock() {
            g.entry(peer_id)
                .and_modify(|record| {
                    record.admitted_at = now;
                    record.last_active_at = now;
                })
                .or_insert(ActivityRecord {
                    admitted_at: now,
                    last_active_at: now,
                    in_flight: 0,
                });
        }
    }

    /// Forget a departed peer's usefulness record.
    ///
    /// # Call this AT the removal site, under the `peers` lock (dig-gossip#74)
    ///
    /// Every departure path removes the peer from `ServiceState::peers` under that map's lock and
    /// calls this in the SAME critical section, because doing it afterwards carries the #1792 reconnect
    /// race: a reconnect landing in the gap re-admits the id with a fresh record, and a trailing
    /// removal would then wipe the LIVE session's record. Removing inside the hold closes the window by
    /// construction — the reconnect must acquire the lock to insert, and `record_admission` runs after,
    /// creating a happens-before chain — which is stronger than the best-effort re-check
    /// [`ServiceState::remove_from_plumtree_unless_reconnected`](crate::service::state::ServiceState::remove_from_plumtree_unless_reconnected)
    /// can manage for Plumtree, whose state is behind a second lock that must not be nested with this
    /// one.
    ///
    /// This is why [`Self::publish`] does NOT remove records for
    /// [`PoolEvent::PeerRemoved`]: that runs after the lock is released, so it is exactly the trailing
    /// removal described above. [`Self::retain_admitted`] remains the backstop, and a record that
    /// outlives its peer is harmless in the meantime — [`Self::activity_of`] only reports records whose
    /// peer is in the live eligible set, so a stale record can never be chosen as a victim.
    pub(crate) fn record_departure(&self, peer_id: &PeerId) {
        if let Ok(mut g) = self.activity.lock() {
            g.remove(peer_id);
        }
    }

    /// Drop every usefulness record for a peer that is no longer held.
    ///
    /// [`Self::record_departure`] is called on each departure path, so this is the backstop that keeps
    /// the map bounded by the peer map even if a future path forgets: it is run against the live peer
    /// map on every displacement decision, which is the one moment the map is already in hand.
    pub(crate) fn retain_admitted(&self, held: &std::collections::HashSet<PeerId>) {
        if let Ok(mut g) = self.activity.lock() {
            g.retain(|peer_id, _| held.contains(peer_id));
        }
    }

    /// Mark work as STARTED over `peer_id`, returning `false` when the peer holds no record — a peer
    /// this pool does not hold cannot be made busy, which is what bounds [`Self::activity`].
    pub(crate) fn begin_activity(&self, peer_id: PeerId, now: u64) -> bool {
        match self.activity.lock() {
            Ok(mut g) => match g.get_mut(&peer_id) {
                Some(record) => {
                    record.in_flight = record.in_flight.saturating_add(1);
                    record.last_active_at = now;
                    true
                }
                None => false,
            },
            Err(_) => false,
        }
    }

    /// Mark work as FINISHED over `peer_id`, stamping it active so a just-served peer sorts as the
    /// most recently useful rather than as of when its request began.
    pub(crate) fn end_activity(&self, peer_id: PeerId, now: u64) {
        if let Ok(mut g) = self.activity.lock() {
            if let Some(record) = g.get_mut(&peer_id) {
                record.in_flight = record.in_flight.saturating_sub(1);
                record.last_active_at = now;
            }
        }
    }

    /// The usefulness of every held peer whose identity is in `eligible`, as the pure planner sees it.
    ///
    /// `eligible` is what scopes displacement to the `dig-nat` pool slots: those are the persistent
    /// connection set requirement 8 speaks of, and the only slots whose usage this crate cannot
    /// observe for itself. A Chia-protocol WebSocket peer is busy with gossip this crate never stamps,
    /// so measuring it by this clock would read as permanently idle and evict it first.
    pub(crate) fn activity_of(
        &self,
        eligible: &std::collections::HashSet<PeerId>,
    ) -> Vec<PeerActivity> {
        let Ok(g) = self.activity.lock() else {
            return Vec::new();
        };
        eligible
            .iter()
            .filter_map(|peer_id| {
                g.get(peer_id).map(|record| PeerActivity {
                    peer_id: *peer_id,
                    admitted_at: record.admitted_at,
                    last_active_at: record.last_active_at,
                    in_flight: record.in_flight,
                })
            })
            .collect()
    }

    /// When this pool last displaced a peer, for the churn bound.
    pub(crate) fn last_displacement_at(&self) -> Option<u64> {
        self.last_displacement_at.lock().ok().and_then(|g| *g)
    }

    /// Charge the churn bound for a displacement performed at `now`.
    pub(crate) fn record_displacement(&self, now: u64) {
        if let Ok(mut g) = self.last_displacement_at.lock() {
            *g = Some(now);
        }
    }

    /// Number of peers whose usefulness is being tracked — so a test can assert this map never
    /// outgrows the peer map it is bounded by, and that each departure path still forgets its peer
    /// (dig-gossip#74).
    #[doc(hidden)]
    pub fn tracked_peer_count(&self) -> usize {
        self.activity.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Publish a churn event to all subscribers (no-op if the channel isn't wired or has no
    /// subscribers — a dropped event is never fatal), and start tracking a newly-admitted peer.
    ///
    /// # Admission is funnelled here; departure is not (dig-gossip#74)
    ///
    /// Admission bookkeeping lives HERE because this is already the one place every admission path
    /// funnels through to announce itself, and an announcement can only ever FOLLOW the insertion it
    /// announces — a late `PeerAdded` cannot destroy anything.
    ///
    /// A late `PeerRemoved` can. This runs after the `peers` lock is released, so removing the
    /// usefulness record here is the trailing removal the #1792 reconnect race exploits. Departure is
    /// therefore recorded at each removal site instead, inside the same lock hold as the
    /// `peers.remove` — see [`Self::record_departure`], and [`Self::retain_admitted`] for the backstop
    /// that keeps the map bounded if a future path forgets.
    pub(crate) fn publish(&self, event: PoolEvent) {
        match &event {
            PoolEvent::PeerAdded { peer_id, .. } => {
                self.record_admission(*peer_id, crate::types::peer::metric_unix_timestamp_secs());
            }
            PoolEvent::PeerRemoved { .. } => {}
        }
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
/// `connected` is the UNION of directly-connected and relay-reachable peers (deduped — #870 finding 1);
/// `direct_connected` is the directly-connected subset that drives the direct-dial floor (#870 finding
/// 2). When there is no relay the two are equal.
///
/// This is the executable half of the pool; the decision half is the pure [`plan_pass`]. `connected`
/// / `connected_keys` are supplied by the caller (read from `ServiceState::peers`) so this stays
/// independent of the exact peer-map layout.
#[allow(clippy::too_many_arguments)]
pub async fn run_maintenance_pass<D: Dialer>(
    pool: &Arc<PoolState>,
    cfg: &PeerPoolConfig,
    connected: usize,
    direct_connected: usize,
    connected_keys: &[CandidateKey],
    candidates: &[PoolCandidate],
    now: u64,
    dialer: &D,
) -> usize {
    let backoff = pool.backoff_snapshot();
    let snap = PoolSnapshot {
        connected,
        direct_connected,
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

    /// **Neither inbound tier may be CLOSED by the reservation that is meant to protect it.** The
    /// share is a reserved quarter of the inbound budget, and taking a quarter twice reaches zero for
    /// every small pool — which refuses the tier outright instead of reserving room for its sibling.
    /// Asserted at every `max_connections` where the budget is non-empty, in BOTH directions, plus
    /// the aggregate that keeps the floor honest: two floored tiers still cannot outgrow the budget
    /// they share.
    #[test]
    fn neither_inbound_tier_is_ever_capped_at_zero_while_the_budget_holds_a_peer() {
        for max_connections in 0..=64usize {
            let total = max_inbound_total(max_connections);
            let direct = max_direct_inbound(max_connections);
            let relayed = max_relayed_inbound(max_connections);

            assert_eq!(direct, relayed, "the two tiers are derived symmetrically");
            assert!(
                direct <= total,
                "a tier cannot exceed the shared inbound budget"
            );
            if total == 0 {
                assert_eq!(direct, 0, "an empty inbound budget grants no tier a slot");
            } else {
                assert!(
                    direct >= 1,
                    "max_connections={max_connections}: a non-empty inbound budget must leave                      each tier at least one slot, not deny it"
                );
            }
        }

        // The two configurations that produced the regression and the one the suites pin.
        assert_eq!(
            max_relayed_inbound(2),
            1,
            "a two-slot pool still serves a circuit"
        );
        assert_eq!(max_relayed_inbound(3), 1);
        assert_eq!(max_relayed_inbound(8), 5);
        assert_eq!(max_direct_inbound(8), 5);
        assert_eq!(max_inbound_total(8), 6);
    }

    fn addr(n: u16) -> SocketAddr {
        format!("127.0.0.1:{n}").parse().unwrap()
    }

    /// **#1716:** the relayed-outbound cap reserves ≥`target/4` (min 1) slots for the diversity-checked
    /// tier — 6 of 8 with the default target, and never underflows for tiny/zero targets.
    #[test]
    fn max_relayed_outbound_reserves_a_quarter_for_the_direct_tier() {
        assert_eq!(
            max_relayed_outbound(8),
            6,
            "default target 8 → 6 relayed, 2 reserved"
        );
        assert_eq!(max_relayed_outbound(4), 3);
        assert_eq!(
            max_relayed_outbound(1),
            0,
            "a single-slot target reserves it for diversity"
        );
        assert_eq!(max_relayed_outbound(0), 0);
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
    fn relay_reachable_peers_do_not_shrink_budget_below_the_direct_floor() {
        // #870 finding 2: a relay advertising >= target reachable peers must NOT zero out direct
        // dialing. With target 8 the floor is 8/4 = 2 direct dials, held regardless of relay count.
        let c = cfg(2, 8, 16);
        // No direct peers, but the relay claims 100 reachable peers -> relay-aware budget is 0.
        assert_eq!(free_slot_budget(100, 0, &c), 0);
        // The floored budget still keeps direct dialing alive at the floor.
        assert_eq!(free_slot_budget_with_direct_floor(0, 100, 0, &c), 2);
        // Once the direct floor is met, extra relay peers stop new direct dials.
        assert_eq!(free_slot_budget_with_direct_floor(2, 100, 0, &c), 0);
        // In-flight direct dials count toward the floor so we don't over-dial it.
        assert_eq!(free_slot_budget_with_direct_floor(0, 100, 2, &c), 0);
    }

    #[test]
    fn direct_floor_never_dials_past_the_max_cap() {
        // The floor can raise the budget above the relay-aware value but never past max direct room.
        let c = cfg(1, 8, 3);
        // Two direct + one in-flight already occupy all 3 max slots -> no room even for the floor.
        assert_eq!(free_slot_budget_with_direct_floor(2, 50, 1, &c), 0);
    }

    #[test]
    fn relay_aware_budget_matches_plain_budget_without_a_relay() {
        // With zero relay-reachable peers the floored budget degrades to the plain fill-to-target math.
        let c = cfg(2, 5, 8);
        assert_eq!(free_slot_budget_with_direct_floor(3, 0, 0, &c), 2);
        assert_eq!(free_slot_budget_with_direct_floor(5, 0, 0, &c), 0);
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
            direct_connected: 0,
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
            direct_connected: 1,
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

    /// **#2176 regression** — the pure planner must exclude a candidate whose
    /// `peer_id` matches a connected peer recorded ONLY by address (and vice-versa). This is the
    /// strongest form: the candidate keys to `Id`, the connected side carries only `Addr` — before
    /// the fix the `dedup_key` (`Id`) never matched `Addr`, so the peer was re-dialed.
    #[test]
    fn plan_matches_connected_on_either_dimension() {
        let c = cfg(1, 4, 8);
        let id = PeerId::from([12u8; 32]);
        // Candidate known by id+addr; connected side recorded ONLY by that address.
        let candidates = vec![PoolCandidate::with_id(id, addr(1))];
        let backoff = HashMap::new();
        let snap = PoolSnapshot {
            connected: 1,
            direct_connected: 1,
            in_flight: 0,
            connected_keys: &[CandidateKey::Addr(addr(1))],
            candidates: &candidates,
            backoff: &backoff,
            now: 0,
        };
        let plan = plan_pass(&snap, &c);
        assert!(
            plan.to_dial.is_empty(),
            "candidate matching a connected peer by address must not be dialed even when it also carries an id"
        );
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
            direct_connected: 1,
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
            direct_connected: 0,
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
        let added = run_maintenance_pass(&pool, &c, 0, 0, &[], &candidates, 0, &OkDialer).await;
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
            run_maintenance_pass(&pool, &c, 3, 3, &connected_keys, &candidates, 0, &OkDialer).await;
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
        let added = run_maintenance_pass(&pool, &c, 0, 0, &[], &candidates, 100, &FailDialer).await;
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

    // -----------------------------------------------------------------------
    // Displacement policy (dig_ecosystem#3128 requirement 8)
    //
    // Every bound below is pinned from BOTH sides — at the threshold it is
    // allowed, one unit short it is refused — because a bound tested only from
    // the refusing side is satisfied by an implementation that refuses always.
    // -----------------------------------------------------------------------

    /// Pool config with the three displacement bounds set explicitly, so no fixture depends on the
    /// shipped defaults and each test states the bound it is exercising.
    fn displacement_cfg(min: usize, idle: u64, established: u64, interval: u64) -> PeerPoolConfig {
        PeerPoolConfig {
            min_peers: min,
            target_peers: min.max(4),
            max_peers: 16,
            min_idle_secs: idle,
            min_established_secs: established,
            displacement_interval_secs: interval,
            ..Default::default()
        }
    }

    fn incumbent(tag: u8, admitted_at: u64, last_active_at: u64, in_flight: usize) -> PeerActivity {
        PeerActivity {
            peer_id: PeerId::from([tag; 32]),
            admitted_at,
            last_active_at,
            in_flight,
        }
    }

    /// A request with one knob per fixture; `connected` defaults to the incumbent count, which is the
    /// realistic shape (every held peer is cyclable in these fixtures).
    fn request<'a>(
        incumbents: &'a [PeerActivity],
        capacity: usize,
        now: u64,
        last_displacement_at: Option<u64>,
    ) -> DisplacementRequest<'a> {
        DisplacementRequest {
            connected: incumbents.len(),
            capacity,
            incumbents,
            last_displacement_at,
            now,
        }
    }

    #[test]
    fn below_capacity_nobody_is_displaced() {
        let cfg = displacement_cfg(1, 0, 0, 0);
        let held = [incumbent(1, 0, 0, 0), incumbent(2, 0, 0, 0)];
        assert_eq!(
            plan_displacement(&request(&held, 4, 1_000, None), &cfg),
            DisplacementDecision::RoomAlready,
            "a free slot is not a reason to evict anyone"
        );
    }

    /// The min-peers floor, from both sides: with `min_peers` peers held, cycling would leave the node
    /// under-connected and is refused; one peer above it, the same request succeeds. Every other input
    /// is identical, so only the floor can explain the difference.
    #[test]
    fn displacement_never_takes_the_pool_to_or_below_min_peers() {
        let cfg = displacement_cfg(2, 0, 0, 0);
        let at_floor = [incumbent(1, 0, 0, 0), incumbent(2, 0, 0, 0)];
        assert_eq!(
            plan_displacement(&request(&at_floor, 2, 1_000, None), &cfg),
            DisplacementDecision::Refused(DisplacementRefusal::WouldBreachMinPeers),
            "two peers with min_peers=2: losing one leaves the node under-connected"
        );
        let above_floor = [
            incumbent(1, 0, 0, 0),
            incumbent(2, 0, 0, 0),
            incumbent(3, 0, 0, 0),
        ];
        assert!(
            matches!(
                plan_displacement(&request(&above_floor, 3, 1_000, None), &cfg),
                DisplacementDecision::Displace(_)
            ),
            "one peer above the floor, the same cycle is allowed"
        );
    }

    /// **The churn bound — the bound on the attacker-reachable lever**, pinned from both sides. One
    /// second before the interval elapses the displacement is refused with the wait; exactly at the
    /// interval it is allowed. A bound only tested from below would also pass against an
    /// implementation that never displaces again at all.
    #[test]
    fn the_churn_bound_admits_one_displacement_per_interval_and_no_more() {
        let cfg = displacement_cfg(1, 0, 0, 600);
        let held = [incumbent(1, 0, 0, 0), incumbent(2, 0, 0, 0)];

        assert_eq!(
            plan_displacement(&request(&held, 2, 1_599, Some(1_000)), &cfg),
            DisplacementDecision::Refused(DisplacementRefusal::RateLimited {
                retry_after_secs: 1
            }),
            "one second short of the interval, a second displacement is refused"
        );
        assert!(
            matches!(
                plan_displacement(&request(&held, 2, 1_600, Some(1_000)), &cfg),
                DisplacementDecision::Displace(_)
            ),
            "exactly at the interval it is allowed again, or the bound is a permanent stop"
        );
        assert!(
            matches!(
                plan_displacement(&request(&held, 2, 1, None), &cfg),
                DisplacementDecision::Displace(_)
            ),
            "a pool that has never displaced is not rate-limited"
        );
    }

    /// **Never evict a peer mid-request**, and the fixture makes the in-flight peer the one a
    /// policy ignoring `in_flight` would certainly pick: it is BOTH the longest-established and the
    /// longest-idle. So a pass here cannot come from the victim simply being unattractive.
    #[test]
    fn a_peer_with_work_in_flight_is_never_the_victim() {
        let cfg = displacement_cfg(1, 0, 0, 0);
        let busy_but_idlest = incumbent(1, 0, 0, 1);
        let quiet = incumbent(2, 500, 500, 0);
        let held = [busy_but_idlest, quiet];
        assert_eq!(
            plan_displacement(&request(&held, 2, 1_000, None), &cfg),
            DisplacementDecision::Displace(quiet.peer_id),
            "the idlest peer had work in flight, so the next-idlest must be chosen instead"
        );

        let only_busy = [busy_but_idlest, incumbent(3, 0, 0, 2)];
        assert_eq!(
            plan_displacement(&request(&only_busy, 2, 1_000, None), &cfg),
            DisplacementDecision::Refused(DisplacementRefusal::NoIdleIncumbent),
            "when every peer is mid-request there is no victim, and refusing is the answer"
        );
    }

    /// **"Unused" must mean unused, not merely least-recently-used** — pinned from both sides of
    /// `min_idle_secs`. The single incumbent is the only possible victim in both halves, so the
    /// threshold is the only thing that can change the outcome.
    #[test]
    fn only_a_peer_idle_for_long_enough_may_be_displaced() {
        let cfg = displacement_cfg(1, 300, 0, 0);
        let held = [incumbent(1, 0, 0, 0), incumbent(2, 0, 800, 0)];
        assert_eq!(
            plan_displacement(&request(&held, 2, 1_099, None), &cfg),
            DisplacementDecision::Displace(PeerId::from([1; 32])),
            "peer 2 was used 299s ago and is protected; peer 1 has been idle far longer"
        );
        let both_recent = [incumbent(1, 0, 900, 0), incumbent(2, 0, 800, 0)];
        assert_eq!(
            plan_displacement(&request(&both_recent, 2, 1_099, None), &cfg),
            DisplacementDecision::Refused(DisplacementRefusal::NoIdleIncumbent),
            "a busy node whose least-recently-used peer was used 199s ago cycles nobody out"
        );
        let at_threshold = [incumbent(1, 0, 900, 0), incumbent(2, 0, 800, 0)];
        assert_eq!(
            plan_displacement(&request(&at_threshold, 2, 1_200, None), &cfg),
            DisplacementDecision::Displace(PeerId::from([2; 32])),
            "at exactly min_idle_secs the idlest peer becomes displaceable"
        );
    }

    /// **A freshly admitted peer is protected**, from both sides of `min_established_secs` — otherwise
    /// the maintenance loop and discovery thrash, each undoing the other's dial.
    #[test]
    fn a_recently_admitted_peer_is_protected_from_displacement() {
        let cfg = displacement_cfg(1, 0, 600, 0);
        let fresh = [incumbent(1, 500, 500, 0), incumbent(2, 401, 401, 0)];
        assert_eq!(
            plan_displacement(&request(&fresh, 2, 1_000, None), &cfg),
            DisplacementDecision::Refused(DisplacementRefusal::NoIdleIncumbent),
            "held for 500s and 599s: both are inside the establishment floor"
        );
        let one_established = [incumbent(1, 500, 500, 0), incumbent(2, 400, 400, 0)];
        assert_eq!(
            plan_displacement(&request(&one_established, 2, 1_000, None), &cfg),
            DisplacementDecision::Displace(PeerId::from([2; 32])),
            "at exactly 600s held, that peer becomes displaceable"
        );
    }

    /// **The victim is the IDLEST, not the oldest.** The fixture inverts the two orders: the
    /// longest-established peer is the most recently used, so a policy that evicted by admission time
    /// (an easy mistake, and what an LRU keyed on the wrong field looks like) picks the opposite peer.
    #[test]
    fn the_victim_is_the_idlest_peer_not_the_longest_established_one() {
        let cfg = displacement_cfg(1, 0, 0, 0);
        let oldest_but_busiest = incumbent(1, 0, 900, 0);
        let newest_but_idlest = incumbent(2, 100, 200, 0);
        let held = [oldest_but_busiest, newest_but_idlest];
        assert_eq!(
            plan_displacement(&request(&held, 2, 1_000, None), &cfg),
            DisplacementDecision::Displace(newest_but_idlest.peer_id),
            "usefulness is measured by last use, not by how long the peer has been held"
        );
    }

    /// Two peers equally idle and equally established must resolve the same way every time — a policy
    /// that fell through to map iteration order would make the eviction, and every test above it,
    /// non-deterministic.
    #[test]
    fn an_exact_tie_is_broken_deterministically() {
        let cfg = displacement_cfg(1, 0, 0, 0);
        let held = [incumbent(9, 100, 200, 0), incumbent(2, 100, 200, 0)];
        let reversed = [incumbent(2, 100, 200, 0), incumbent(9, 100, 200, 0)];
        assert_eq!(
            plan_displacement(&request(&held, 2, 1_000, None), &cfg),
            plan_displacement(&request(&reversed, 2, 1_000, None), &cfg),
            "the same set of incumbents must yield the same victim in either order"
        );
    }

    /// The usefulness map is bounded by POOL MEMBERSHIP, and an identity the pool does not hold cannot
    /// create an entry in it. That is the property that keeps an untrusted peer from growing it.
    #[test]
    fn usefulness_is_tracked_only_for_admitted_peers() {
        let pool = PoolState::new();
        let stranger = PeerId::from([0xaa; 32]);
        assert!(
            !pool.begin_activity(stranger, 10),
            "a peer the pool does not hold cannot be marked busy"
        );
        assert_eq!(
            pool.tracked_peer_count(),
            0,
            "and must not have created a record by asking"
        );

        pool.record_admission(stranger, 10);
        assert!(pool.begin_activity(stranger, 20), "an admitted peer can");
        assert_eq!(pool.tracked_peer_count(), 1);

        pool.retain_admitted(&std::collections::HashSet::new());
        assert_eq!(
            pool.tracked_peer_count(),
            0,
            "and the sweep drops every record whose peer is no longer held"
        );
    }

    // -----------------------------------------------------------------------
    // dig-gossip#74 - the config floor, and the two activity-map races.
    // -----------------------------------------------------------------------

    /// **D1 - the churn bound cannot be switched off by configuration.**
    ///
    /// `displacement_interval_secs: 0` made the only globally-charged, attacker-facing bound a no-op
    /// while `normalized()` - whose whole job is that a caller cannot hand the pool an incoherent
    /// config - passed it through untouched. Pinned from BOTH sides: below the floor the value is
    /// raised, at and above it the operator's larger value survives, because a clamp that also lowered
    /// a deliberately-stricter setting would invert the guard it is meant to be.
    #[test]
    fn normalized_floors_the_churn_bound_and_leaves_a_stricter_one_alone() {
        let disabled = PeerPoolConfig {
            displacement_interval_secs: 0,
            ..Default::default()
        };
        assert_eq!(
            disabled.normalized().displacement_interval_secs,
            600,
            "a zero interval must come out at the floor, or the churn bound is optional"
        );

        let too_low = PeerPoolConfig {
            displacement_interval_secs: 599,
            ..Default::default()
        };
        assert_eq!(
            too_low.normalized().displacement_interval_secs,
            600,
            "one second under the floor is still under it"
        );

        let stricter = PeerPoolConfig {
            displacement_interval_secs: 3_600,
            ..Default::default()
        };
        assert_eq!(
            stricter.normalized().displacement_interval_secs,
            3_600,
            "an operator who wants a SLOWER churn bound keeps it; the clamp only raises"
        );
    }

    /// **D1, behaviourally** - the floor has to be reached by the code that actually rate-limits, not
    /// merely be observable on the returned struct. With the bound configured to zero, a second
    /// displacement one second after the first must still be refused.
    #[test]
    fn a_zero_configured_interval_still_rate_limits_a_second_displacement() {
        let cfg = displacement_cfg(1, 0, 0, 0);
        let held = [incumbent(1, 0, 0, 0), incumbent(2, 0, 0, 0)];
        assert_eq!(
            plan_displacement(&request(&held, 2, 1_001, Some(1_000)), &cfg),
            DisplacementDecision::Refused(DisplacementRefusal::RateLimited {
                retry_after_secs: 599
            }),
            "displacement_interval_secs: 0 must not buy unbounded churn"
        );
    }

    /// **D1 - the two per-peer thresholds are ordered, the way `min <= target <= max` is.**
    ///
    /// `min_established_secs < min_idle_secs` is incoherent: a peer would become old enough to displace
    /// before it could possibly have been observed going unused. Repaired by raising the establishment
    /// floor (the conservative direction), never by lowering the idleness one.
    #[test]
    fn normalized_orders_the_establishment_floor_above_the_idleness_floor() {
        let incoherent = PeerPoolConfig {
            min_idle_secs: 900,
            min_established_secs: 120,
            ..Default::default()
        };
        let fixed = incoherent.normalized();
        assert_eq!(
            fixed.min_idle_secs, 900,
            "the idleness floor is never lowered to repair the ordering"
        );
        assert_eq!(
            fixed.min_established_secs, 900,
            "the establishment floor is raised to meet it"
        );

        let coherent = PeerPoolConfig {
            min_idle_secs: 300,
            min_established_secs: 600,
            ..Default::default()
        };
        assert_eq!(
            coherent.normalized().min_established_secs,
            600,
            "an already-ordered pair is left exactly as configured"
        );
    }

    /// **D2 - a supersede must not clear a live activity guard's in-flight count.**
    ///
    /// The fixture is shaped so the OUTCOME, not just the field, changes: the superseded peer is also
    /// the idlest, so a policy that saw `in_flight == 0` would pick it. Peer 2 is the honest control -
    /// a genuinely idle incumbent that remains a legitimate victim - so a pass here cannot come from
    /// the planner refusing everything.
    #[test]
    fn a_supersede_does_not_clear_a_live_activity_guards_in_flight_count() {
        let pool = PoolState::new();
        let busy = PeerId::from([1; 32]);
        let idle = PeerId::from([2; 32]);

        pool.record_admission(busy, 1_000);
        assert!(pool.begin_activity(busy, 1_000), "the guard starts");
        pool.record_admission(busy, 1_000); // the newest-wins supersede, guard still held.
        pool.record_admission(idle, 1_100);

        let held: Vec<PeerActivity> = pool.activity_of(&[busy, idle].into_iter().collect());
        assert_eq!(
            held.iter().find(|p| p.peer_id == busy).map(|p| p.in_flight),
            Some(1),
            "the supersede re-dated the session; it must not have forgotten the live guard"
        );

        let cfg = displacement_cfg(1, 300, 600, 600);
        assert_eq!(
            plan_displacement(&request(&held, 2, 100_000, None), &cfg),
            DisplacementDecision::Displace(idle),
            "the idlest peer is mid-request, so the honest idle control must be chosen instead"
        );
    }

    /// **D3 - a delayed `PeerRemoved` announcement cannot destroy the session that replaced it.**
    ///
    /// The #1792 shape: a departure path removes the peer, a reconnect re-admits it in the gap, and the
    /// first session's announcement then arrives. The record is now dropped AT the removal site, inside
    /// the same `peers`-lock hold as the `peers.remove`, so a reconnect cannot interleave - the
    /// announcement is only an announcement. The second half is the control that keeps this from being
    /// "nothing is ever forgotten": a departure with no reconnect still clears the record.
    #[test]
    fn a_delayed_departure_announcement_does_not_wipe_a_reconnected_session() {
        let pool = PoolState::new();
        let peer = PeerId::from([7; 32]);

        pool.record_admission(peer, 1_000); // session 1
        pool.record_departure(&peer); // ...removed, under the peers lock
        pool.record_admission(peer, 2_000); // session 2 - the reconnect
        assert!(
            pool.begin_activity(peer, 2_010),
            "session 2 is live and in use"
        );

        pool.publish(PoolEvent::PeerRemoved {
            peer_id: peer,
            reason: PoolRemovalReason::Disconnected,
        }); // session 1's announcement, delayed past the reconnect

        assert_eq!(
            pool.tracked_peer_count(),
            1,
            "the reconnected session's record must survive the stale announcement"
        );
        assert_eq!(
            pool.activity_of(&[peer].into_iter().collect())
                .first()
                .map(|p| (p.admitted_at, p.in_flight)),
            Some((2_000, 1)),
            "and it must be session 2's record, guard included - not a fresh, guard-less one"
        );

        let gone = PeerId::from([8; 32]);
        pool.record_admission(gone, 3_000);
        pool.record_departure(&gone);
        assert_eq!(
            pool.tracked_peer_count(),
            1,
            "control: an ordinary departure still forgets its peer, so the map stays bounded"
        );
    }
}
