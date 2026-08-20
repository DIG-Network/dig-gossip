//! Cheap-clone handle exposing the full gossip runtime API to callers.
//!
//! [`GossipHandle`] is the **primary public interface** of the `dig-gossip` crate. It is returned
//! by [`GossipService::start()`](super::gossip_service::GossipService::start) and wraps an
//! `Arc<ServiceState>`, making it freely cloneable across tasks with no extra allocation.
//!
//! Every method on `GossipHandle` ultimately reads from or mutates the shared
//! [`ServiceState`](super::state::ServiceState) via short mutex holds or atomic loads, so the
//! handle is safe for concurrent use by multiple Tokio tasks.
//!
//! # Requirement coverage
//!
//! | Requirement | Methods |
//! |-------------|---------|
//! | API-001 | [`health_check`](GossipHandle::health_check) (lifecycle probe) |
//! | API-002 | All messaging, peer-management, discovery, and stats methods |
//! | API-008 | [`stats`](GossipHandle::stats), [`relay_stats`](GossipHandle::relay_stats) |
//! | CON-001 | [`connect_to`](GossipHandle::connect_to) — outbound WSS + `RequestPeers` |
//! | CON-006 | Per-live-slot [`PeerConnectionWireMetrics`](crate::types::peer::PeerConnectionWireMetrics) + [`stats`](GossipHandle::stats) aggregation |
//! | CON-004 / CON-007 | [`penalize_peer`](GossipHandle::penalize_peer), [`ban_peer`](GossipHandle::ban_peer) |
//!
//! See: `docs/requirements/domains/crate_api/specs/API-002.md`
//! See: `docs/resources/SPEC.md` Section 3.3 — GossipHandle methods.
//!
//! # Deviations from the markdown spec (Rust ownership)
//!
//! - **`inbound_receiver`:** SPEC shows `&mpsc::Receiver<_>` while [`GossipHandle`] is [`Clone`].
//!   Cloning a handle cannot share a single-consumer `mpsc` receiver safely. We return a
//!   [`broadcast::Receiver`] subscription instead. This allows multiple subscribers (e.g. a relay
//!   task + an application handler) without contention. See
//!   [`ServiceState::inbound_tx`](super::state::ServiceState::inbound_tx) for the sender half.
//!
//! - **`connected_peers` / `get_connections`:** Returning owned [`crate::types::peer::PeerConnection`]
//!   values would duplicate [`tokio::sync::mpsc::Receiver`] halves; CON-001 keeps live
//!   [`dig_peer_protocol::DigLink`] handles inside [`super::state::PeerSlot::Live`] while these RPCs
//!   stay empty until a snapshot API lands. In the meantime,
//!   [`__stub_filter_count_for_tests`](GossipHandle::__stub_filter_count_for_tests) gives tests a
//!   way to verify filter semantics.
//!
//! # Chia equivalence
//!
//! This module loosely maps to the `FullNode` peer-handling surface in Chia's Python code
//! (`full_node.py`, `server.py`). The key difference is that Chia's `Server` object is not
//! `Clone` — callers must borrow it. Our `Arc` wrapper avoids lifetime gymnastics in async code.

use crate::connection::chia_opcodes;
use chia_protocol::{RequestPeers, RespondPeers, TimestampedPeerInfo};
use dig_nat::SafeText;
use dig_peer_protocol::DigLink;
use dig_peer_protocol::{ChiaProtocolMessage, DigMessage, NodeType};

use crate::discovery::introducer_client::{
    load_local_certificate_for_introducer, IntroducerClient, PeerRegistration,
};
use crate::discovery::introducer_register_wire::RegisterAck;
use dig_peer_protocol::Streamable;
use std::any::TypeId;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;

use crate::constants::PENALTY_BAN_THRESHOLD;
use crate::error::GossipError;
use crate::service::dig_message::{frame_dig_message, StreamFrame};
use crate::types::dig_messages::{route_dig_message, DigMessageType, RoutingStrategy};
use crate::types::peer::{
    message_wire_len, metric_unix_timestamp_secs, peer_id_from_tls_spki_der, PeerConnection,
    PeerConnectionWireMetrics, PeerId, PeerInfo,
};
use crate::types::reputation::PeerReputation;
use crate::types::reputation::PenaltyReason;
use crate::types::stats::{GossipStats, RelayStats};

use super::state::{
    apply_inbound_rate_limit_violation, record_live_peer_inbound_bytes,
    record_live_peer_outbound_bytes, sum_live_peer_wire_metrics, LiveSlot, PeerSlot, ServiceState,
    StubPeer,
};
// Only the cfg-gated `connect_stub_inner` test hook (#1718) derives a `peer_id` from a raw address;
// the production peer keys come from the TLS-verified SPKI, so this import is test-only.
#[cfg(any(test, feature = "test-util"))]
use super::state::peer_id_for_addr;

/// Map a DIG routing strategy that is neither fan-out nor unicast to its dispatch error (#1404).
///
/// Both [`GossipHandle::broadcast_dig`] and [`GossipHandle::send_dig`] fall through to this once
/// they have ruled out the shape they own, so the introducer / no-live-producer decision lives in
/// exactly one place. Introducer strategies steer the caller to the dedicated introducer socket;
/// every other strategy has no live producer yet and fails safe rather than guessing a wire shape.
///
/// # Panics
///
/// Never for a real call: the two fan-out and two unicast strategies are handled by the callers
/// before they reach here. The `unreachable!` documents that invariant for future strategies.
fn deferred_dispatch_error(strategy: RoutingStrategy, msg_type: DigMessageType) -> GossipError {
    match strategy {
        RoutingStrategy::UnicastToIntroducer | RoutingStrategy::UnicastFromIntroducer => {
            GossipError::UseDedicatedIntroducerMethod
        }
        RoutingStrategy::ErlayReconciliation
        | RoutingStrategy::DandelionStem
        | RoutingStrategy::PlumtreeLazy
        | RoutingStrategy::PlumtreeControl
        | RoutingStrategy::PlumtreePull => GossipError::StrategyNotYetProduced {
            strategy,
            opcode: msg_type as u8,
        },
        // Fan-out + unicast are dispatched by the callers before reaching here.
        RoutingStrategy::PlumtreeEager
        | RoutingStrategy::BroadcastFlood
        | RoutingStrategy::UnicastRequest
        | RoutingStrategy::UnicastResponse => {
            unreachable!("fan-out and unicast strategies are dispatched before this fallthrough")
        }
    }
}

/// Who produced the message a fan-out is disseminating — the ONLY thing that decides whether the
/// seen set may suppress it (dig_ecosystem#3061).
///
/// The seen set answers "have I put these exact bytes on the wire before?". For a
/// [`Forwarded`](MessageOrigin::Forwarded) message that is the right question: re-forwarding is a
/// loop, and suppressing it is what keeps gossip from becoming a storm. For a
/// [`Local`](MessageOrigin::Local) one it is the wrong question — a re-announce of unchanged state is
/// byte-identical by design, and the peers that need it are precisely the ones that were not
/// connected when it was first said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageOrigin {
    /// This node produced the message; a repeat is intentional and is never suppressed.
    Local,
    /// The message arrived from a peer and is being relayed onward; a repeat is a loop.
    Forwarded,
}

/// Connected peers a fan-out could NOT deliver to, split by reason.
///
/// Kept separate from the delivery count so neither can be mistaken for the other: the count a
/// broadcast returns is what went on a wire, and these are the peers that heard nothing despite
/// being connected (dig_ecosystem#3062 / #3063).
#[derive(Debug, Default, Clone, Copy)]
struct UnreachablePeers {
    /// `dig-nat` mux peers — no gossip frame codec / receive loop exists over that transport here.
    nat: usize,
    /// Plumtree-lazy peers — SPEC §8.1's hash-only `LazyAnnounce` is not yet produced.
    lazy: usize,
}

impl UnreachablePeers {
    fn total(self) -> usize {
        self.nat + self.lazy
    }
}

// ---------------------------------------------------------------------------
// GossipHandle — the user-facing façade
// ---------------------------------------------------------------------------

/// Cloneable façade over the shared [`ServiceState`].
///
/// `GossipHandle` is **the** user-facing type after [`GossipService::start()`]. It holds an
/// `Arc<ServiceState>` so clones are pointer-sized and allocation-free. All mutation goes
/// through interior-mutable fields (std `Mutex`, `AtomicU64`, etc.) inside `ServiceState`.
///
/// # Thread safety
///
/// The handle is `Send + Sync + Clone`. Multiple tasks can call methods concurrently; each
/// method acquires the narrowest possible lock (or uses relaxed atomics for counters) to
/// minimize contention.
///
/// # Lifecycle guard
///
/// Most public methods start with [`require_running`](Self::require_running) which reads the
/// [`ServiceState::lifecycle`] atomic. After [`GossipService::stop()`] sets it to `LC_STOPPED`,
/// all subsequent calls return [`GossipError::ServiceNotStarted`].
///
/// See: `docs/requirements/domains/crate_api/specs/API-002.md`
#[derive(Debug, Clone)]
pub struct GossipHandle {
    /// Shared runtime state — configuration, peer map, counters, inbound channel.
    /// `pub(crate)` so [`GossipService`](super::gossip_service::GossipService) and internal
    /// subsystems (e.g. the CON-002 accept loop) can reach the same state without going
    /// through the handle's public API.
    pub(crate) inner: Arc<ServiceState>,
}

impl GossipHandle {
    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Gate that every public method calls first.
    ///
    /// Reads [`ServiceState::lifecycle`] with `SeqCst` ordering. Returns
    /// [`GossipError::ServiceNotStarted`] when the service has never been started **or** has
    /// already been stopped (API-001 acceptance: "methods on handle after `stop()` return error").
    fn require_running(&self) -> Result<(), GossipError> {
        if self.inner.is_running() {
            Ok(())
        } else {
            Err(GossipError::ServiceNotStarted)
        }
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /// Lightweight liveness check — returns `Ok(())` iff the service is in the `RUNNING` state.
    ///
    /// **Requirement:** API-001 acceptance — "handle methods after `stop()` return
    /// `GossipError::ServiceNotStarted`". Also used by legacy API-001 tests as a smoke probe.
    ///
    /// This is intentionally cheap (single atomic load); it does **not** verify that background
    /// tasks (listener, keepalive loops, etc.) are still alive.
    pub async fn health_check(&self) -> Result<(), GossipError> {
        self.require_running()
    }

    // ------------------------------------------------------------------
    // Inbound message subscription
    // ------------------------------------------------------------------

    /// Subscribe to inbound `(sender_peer_id, wire_message)` pairs.
    ///
    /// Returns a **new** [`broadcast::Receiver`] each time it is called. Each receiver gets an
    /// independent copy of every message published after subscription; messages sent before
    /// the call are **not** replayed (unlike `mpsc`).
    ///
    /// # Deviation from SPEC §3.3
    ///
    /// The spec prototype shows `&mpsc::Receiver<_>`, but `mpsc` is single-consumer and
    /// cannot be shared across cloned handles. We use [`tokio::sync::broadcast`] instead,
    /// which supports multiple subscribers. See the module-level doc comment for the full
    /// rationale.
    ///
    /// # Errors
    ///
    /// - [`GossipError::ServiceNotStarted`] — service not yet started or already stopped.
    /// - [`GossipError::ChannelClosed`] — internal mutex poisoned (should not happen in practice).
    ///
    /// See: `docs/requirements/domains/crate_api/specs/API-002.md` — `inbound_receiver`
    pub fn inbound_receiver(
        &self,
    ) -> Result<broadcast::Receiver<(PeerId, DigMessage)>, GossipError> {
        self.require_running()?;
        // Short lock: grab the broadcast Sender, then immediately subscribe (subscribe() is O(1)).
        let g = self
            .inner
            .inbound_tx
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?;
        let tx = g.as_ref().ok_or(GossipError::ServiceNotStarted)?;
        Ok(tx.subscribe())
    }

    // ------------------------------------------------------------------
    // Messaging — broadcast / send / request
    // ------------------------------------------------------------------

    /// Forward a wire [`DigMessage`] to every reachable peer (optionally excluding one).
    ///
    /// This is the **forwarding** path: a message that arrived from a peer and is being relayed
    /// onward. It is seen-set deduplicated — a message this node has already broadcast or forwarded
    /// is dropped with `Ok(0)`, which is what stops a gossip loop becoming a broadcast storm.
    ///
    /// **Use [`broadcast_local`](Self::broadcast_local) for a message this node ORIGINATES**, such
    /// as a periodic re-announce of unchanged state. A locally-originated message is byte-identical
    /// on every repeat, so the dedup here would suppress it forever and a late-joining peer could
    /// never learn it (dig_ecosystem#3061).
    ///
    /// Returns the number of peers the message was **actually sent to** (dig_ecosystem#3063) — see
    /// [`unreachable_peer_count`](Self::unreachable_peer_count) for the connected-but-unreachable
    /// remainder. With zero connected peers the return value is `Ok(0)` — this is explicitly **not**
    /// an error (API-002 implementation notes: "broadcast with zero connected peers should return
    /// `Ok(0)`").
    ///
    /// # Wire behaviour (CON-001+ / CON-006)
    ///
    /// **Live** peers receive [`DigLink::send_message`](dig_peer_protocol::DigLink::send_message)
    /// with a cloned [`DigMessage`]; each successful send increments that slot’s CON-006 counters by the
    /// shared serialized length. **Stub** peers do not have a transport — the legacy
    /// [`ServiceState::messages_sent`] / [`ServiceState::bytes_sent`] atomics record the same
    /// fan-out counts so API-008 stub tests remain stable.
    ///
    /// # Parameters
    ///
    /// - `message` — Serialized Chia wire message (header + body).
    /// - `exclude` — If `Some(peer_id)`, that peer is skipped (typical use: don't echo a
    ///   message back to the peer that sent it).
    ///
    /// # Errors
    ///
    /// - [`GossipError::ServiceNotStarted`] — service not running.
    /// - [`GossipError::ChannelClosed`] — mutex poisoned.
    ///
    /// See: `docs/requirements/domains/crate_api/specs/API-002.md` — `broadcast`
    pub async fn broadcast(
        &self,
        message: DigMessage,
        exclude: Option<PeerId>,
    ) -> Result<usize, GossipError> {
        self.fan_out(message, exclude, MessageOrigin::Forwarded)
            .await
    }

    /// Broadcast a message this node **originates** — never suppressed by the seen set.
    ///
    /// A locally-originated announcement describes this node's own state (the profile root behind
    /// opcode 223, a holdings announce), so a repeat of unchanged state is byte-identical to its
    /// predecessor. Deduplicating on the message bytes cannot tell *"I already told these peers"*
    /// from *"I must tell the peers who were not here then"*, so the seen set — correct as a loop
    /// suppressor for FORWARDED gossip — silently made every re-announce a no-op for the life of the
    /// process (dig_ecosystem#3061). Measured live: a startup announce made at zero peers poisoned
    /// the entry, and no peer that connected afterwards could ever learn the root.
    ///
    /// The hash is still RECORDED, so the same message arriving back from a peer and offered to the
    /// forwarding [`broadcast`](Self::broadcast) is still dropped. Only this node's own repeat is
    /// exempt, and only because this node is the authority on when to say it again — periodic
    /// re-announce rate is the caller's decision, not the dedup's.
    ///
    /// Returns the number of peers actually sent to; errors are [`broadcast`](Self::broadcast)'s.
    pub async fn broadcast_local(
        &self,
        message: DigMessage,
        exclude: Option<PeerId>,
    ) -> Result<usize, GossipError> {
        self.fan_out(message, exclude, MessageOrigin::Local).await
    }

    /// The shared fan-out both broadcast paths run; `origin` decides only whether an already-seen
    /// message is suppressed (see [`MessageOrigin`]).
    async fn fan_out(
        &self,
        message: DigMessage,
        exclude: Option<PeerId>,
        origin: MessageOrigin,
    ) -> Result<usize, GossipError> {
        self.require_running()?;
        let wire_len = message_wire_len(&message);

        // -- INT-001: Plumtree dedup via seen set --
        // SPEC §8.1 step 2: "if seen_set.contains(hash) → return 0" — for a FORWARDED message. A
        // locally-originated one records the hash (arming the loop guard against its own echo) but is
        // never suppressed by it (#3061).
        let msg_hash =
            crate::gossip::seen_set::SeenSet::compute_hash(message.msg_type, &message.data);
        {
            let mut seen = self
                .inner
                .seen_messages
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            if origin == MessageOrigin::Forwarded && seen.contains(&msg_hash) {
                return Ok(0); // already seen — dedup
            }
            seen.put(msg_hash, ());
        }

        // -- INT-001: Cache message for GRAFT responses (PLT-007) --
        {
            let mut cache = self
                .inner
                .message_cache
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            cache.insert(msg_hash, message.msg_type, message.data.to_vec());
        }

        // -- INT-001: Route through Plumtree eager/lazy sets (SPEC §8.1) --
        // Eager peers get full message. Lazy peers get hash-only (LazyAnnounce).
        // Stubs (test-only) always get counted as delivered.
        #[allow(clippy::type_complexity)]
        let (stub_deliveries, eager_jobs, nat_jobs, mut unreachable): (
            usize,
            Vec<(DigLink, PeerId, u64)>,
            Vec<(crate::NatBroadcastSink, PeerId)>,
            UnreachablePeers,
        ) = {
            let peers = self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            let plumtree = self
                .inner
                .plumtree
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;

            let mut stub_n = 0usize;
            let mut eager = Vec::new();
            let mut nat_jobs = Vec::new();
            let mut unreachable = UnreachablePeers::default();

            for (pid, slot) in peers.iter() {
                if exclude.as_ref() == Some(pid) {
                    continue;
                }
                match slot {
                    PeerSlot::Stub(_) => stub_n += 1,
                    PeerSlot::Live(l) => {
                        // INT-001: check Plumtree classification
                        if plumtree.is_eager(pid) {
                            // Eager: full message (SPEC §8.1 step 5)
                            eager.push((l.peer.clone(), *pid, wire_len));
                        } else {
                            // Lazy: SPEC §8.1 step 6 prescribes a hash-only LazyAnnounce, which this
                            // crate does not yet put on the wire — so a lazy peer receives NOTHING
                            // and is counted as unreachable, never as delivered (#3063).
                            unreachable.lazy += 1;
                        }
                    }
                    // POOL-*: a `dig-nat` pool member has no `DigLink`, and this crate runs no frame
                    // codec over the mux — so the ONLY way a broadcast reaches it is the sink its
                    // session owner supplied (#69). Before that sink existed a relayed peer was
                    // counted as connected and yet received no announcement at all, which silences a
                    // NAT'd node outright. A peer with no sink is still reported unreachable rather
                    // than delivered (#3062 / #3063 honesty).
                    PeerSlot::Nat(n) => match &n.sink {
                        Some(sink) => nat_jobs.push((sink.clone(), *pid)),
                        None => unreachable.nat += 1,
                    },
                }
            }
            (stub_n, eager, nat_jobs, unreachable)
        };

        // Count stubs as delivered (test compatibility)
        self.inner
            .messages_sent
            .fetch_add(stub_deliveries as u64, std::sync::atomic::Ordering::Relaxed);
        self.inner.bytes_sent.fetch_add(
            wire_len.saturating_mul(stub_deliveries as u64),
            std::sync::atomic::Ordering::Relaxed,
        );

        // INT-001: Eager push — full message to eager peers (SPEC §8.1 step 5)
        for (peer, pid, wl) in eager_jobs.iter() {
            peer.send_message(message.clone())
                .await
                .map_err(GossipError::from)?;
            record_live_peer_outbound_bytes(&self.inner, *pid, *wl);
        }

        // #69: hand each `dig-nat` peer's broadcast to its session owner, outside the peer-map lock.
        // `offer` never awaits, so a peer that has stopped draining slows nobody down — it is simply
        // reported unreachable, exactly like a peer with no sink at all.
        let mut nat_deliveries = 0usize;
        for (sink, pid) in nat_jobs.iter() {
            if sink.offer(message.clone()) {
                nat_deliveries += 1;
                record_live_peer_outbound_bytes(&self.inner, *pid, wire_len);
            } else {
                unreachable.nat += 1;
            }
        }
        self.inner
            .messages_sent
            .fetch_add(nat_deliveries as u64, std::sync::atomic::Ordering::Relaxed);
        self.inner.bytes_sent.fetch_add(
            wire_len.saturating_mul(nat_deliveries as u64),
            std::sync::atomic::Ordering::Relaxed,
        );

        // A peer this fan-out could not reach is a silence the caller must be able to see: it looks
        // identical to a healthy broadcast in the delivery count alone (#3062 kept #3063 invisible
        // and vice versa). Warn rather than stay quiet, so a live node reporting "announced to 1
        // peer" also says which peers heard nothing.
        if unreachable.total() > 0 {
            tracing::warn!(
                delivered = stub_deliveries + eager_jobs.len() + nat_deliveries,
                unreachable_nat = unreachable.nat,
                unreachable_lazy = unreachable.lazy,
                msg_type = message.msg_type,
                "gossip broadcast could not reach every connected peer"
            );
        }

        Ok(stub_deliveries + eager_jobs.len() + nat_deliveries)
    }

    /// Type-safe broadcast: serialize `body` via [`Streamable`] then delegate to [`Self::broadcast`].
    ///
    /// This is the recommended entry point for application-level broadcasts — callers work with
    /// concrete Chia protocol types (e.g. `NewPeak`, `NewTransaction`) rather than raw
    /// [`DigMessage`] bytes.
    ///
    /// # Errors
    ///
    /// Inherits all errors from [`Self::broadcast`], plus [`GossipError::ClientError`] if
    /// serialization fails (e.g. the `Streamable` impl encounters an internal error).
    ///
    /// See: `docs/requirements/domains/crate_api/specs/API-002.md` — `broadcast_typed`
    pub async fn broadcast_typed<T: Streamable + ChiaProtocolMessage + Send>(
        &self,
        body: T,
        exclude: Option<PeerId>,
    ) -> Result<usize, GossipError> {
        let msg = encode_message(&body)?;
        self.broadcast(msg, exclude).await
    }

    /// Send a typed message to a single peer identified by [`PeerId`].
    ///
    /// For **live** peers (CON-001+), the message is forwarded through the underlying
    /// [`dig_peer_protocol::DigLink::send`] WebSocket channel. For **stub** peers (pre-CON-001
    /// test fixtures), the payload is serialized (to validate encoding) but not transmitted;
    /// the counter is still incremented so stats remain consistent.
    ///
    /// # Preconditions
    ///
    /// - Service must be running.
    /// - `peer_id` must be present in the peer map.
    /// - `peer_id` must **not** be in the ban set.
    ///
    /// # Errors
    ///
    /// - [`GossipError::ServiceNotStarted`] — service not running.
    /// - [`GossipError::PeerBanned`] — the target peer has been banned.
    /// - [`GossipError::PeerNotConnected`] — unknown `peer_id`.
    /// - [`GossipError::ClientError`] — serialization failure or WebSocket send error.
    ///
    /// See: `docs/requirements/domains/crate_api/specs/API-002.md` — `send_to`
    pub async fn send_to<T: Streamable + ChiaProtocolMessage + Send>(
        &self,
        peer_id: PeerId,
        body: T,
    ) -> Result<(), GossipError> {
        self.require_running()?;
        // Validate serialization upfront — fail fast even for stub peers so callers
        // get consistent error behaviour regardless of the peer type.
        let msg = encode_message(&body)?;
        let wire_len = message_wire_len(&msg);

        // Ban check before touching the peer map — avoids leaking message data to a banned peer.
        if self
            .inner
            .is_peer_id_banned_at(peer_id, metric_unix_timestamp_secs())
            .await
        {
            return Err(GossipError::PeerBanned(peer_id));
        }

        // Clone the live `DigLink` handle (Arc-backed, cheap) while the lock is held,
        // then release the lock before the async send to avoid holding it across `.await`.
        let maybe_live = {
            let peers = self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            match peers.get(&peer_id) {
                None => return Err(GossipError::PeerNotConnected(peer_id)),
                Some(PeerSlot::Live(l)) => Some(l.peer.clone()),
                // Stub + POOL-* `dig-nat` members have no WebSocket `DigLink`; the typed WS
                // send/request path treats them like a stub (the dig-node phase adds the mux RPC).
                Some(PeerSlot::Stub(_)) | Some(PeerSlot::Nat(_)) => None,
            }
        };
        if let Some(p) = maybe_live {
            p.send(body).await.map_err(GossipError::from)?;
            record_live_peer_outbound_bytes(&self.inner, peer_id, wire_len);
        } else {
            self.inner
                .messages_sent
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner
                .bytes_sent
                .fetch_add(wire_len, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    /// Send an already-framed [`DigMessage`] to ONE peer.
    ///
    /// The directed counterpart of [`broadcast`](Self::broadcast), for opcodes whose payload a
    /// caller has framed itself — the profile-sync request/response pair (224/225,
    /// [`crate::service::profile_sync`]) is the first user. The frame is carried verbatim: this
    /// crate is the transport and never inspects a directed payload.
    ///
    /// Use [`send_dig`](Self::send_dig) for a consensus-band ([`DigMessageType`]) opcode, whose
    /// routing strategy must be checked, and [`send_dig_message`](Self::send_dig_message) for an
    /// opcode-220 envelope.
    ///
    /// # Errors
    ///
    /// - [`GossipError::ServiceNotStarted`] — service not running.
    /// - [`GossipError::PeerBanned`] — the target peer is banned.
    /// - [`GossipError::PeerNotConnected`] — unknown `peer_id`.
    /// - [`GossipError::ClientError`] — WebSocket send failure.
    pub async fn send_frame(&self, peer_id: PeerId, msg: DigMessage) -> Result<(), GossipError> {
        self.send_directed_message(peer_id, msg).await
    }

    /// The [`PeerId`]s of every peer this node currently holds a LIVE transport to — the set a
    /// directed frame ([`send_frame`](Self::send_frame)) can actually reach.
    ///
    /// Excludes test-only stub rows, which have no transport, so a caller choosing a peer to ask
    /// for a profile body (opcode 224) never picks one whose send is guaranteed to fail. Order is
    /// unspecified and the snapshot is immediately stale — a peer may drop between this call and
    /// the send, which the send's own [`GossipError::PeerNotConnected`] reports.
    #[must_use]
    pub fn live_peer_ids(&self) -> Vec<PeerId> {
        self.inner
            .peers
            .lock()
            .map(|guard| {
                guard
                    .iter()
                    .filter(|(_, slot)| {
                        matches!(
                            slot,
                            super::state::PeerSlot::Live(_) | super::state::PeerSlot::Nat(_)
                        )
                    })
                    .map(|(peer_id, _)| *peer_id)
                    .collect()
            })
            .unwrap_or_default()
    }

    // ------------------------------------------------------------------
    // dig-message directed seam (opcode 220 — WU6, epic #796, Wave A)
    // ------------------------------------------------------------------

    /// Send a directed dig-message **envelope** to a single peer over opcode 220.
    ///
    /// dig-gossip is the transport only: `envelope` is carried as **opaque bytes**
    /// in the `DigMessage.data` field — dig-gossip never seals, opens, or parses it.
    /// `correlation_id` maps to `DigMessage.id` (pairs a streaming exchange or a
    /// request/response); pass `None` for fire-and-forget. See
    /// [`crate::service::dig_message`] for the seam overview.
    ///
    /// # Errors
    ///
    /// - [`GossipError::ServiceNotStarted`] — service not running.
    /// - [`GossipError::PeerBanned`] — the target peer is banned.
    /// - [`GossipError::PeerNotConnected`] — unknown `peer_id`.
    /// - [`GossipError::ClientError`] — WebSocket send failure.
    pub async fn send_dig_message(
        &self,
        peer_id: PeerId,
        envelope: &[u8],
        correlation_id: Option<u16>,
    ) -> Result<(), GossipError> {
        let msg = crate::service::dig_message::frame_envelope(envelope, correlation_id);
        self.send_directed_message(peer_id, msg).await
    }

    /// Open a dig-message stream to a peer (sends a [`StreamFrame::Open`] over opcode 220).
    ///
    /// The streaming *state machine* (windowing, backpressure, timeouts) is
    /// dig-message's (WU4); this helper only frames + delivers the OPEN marker.
    /// All frames of one stream share `stream_id` (mapped to the low 16 bits of
    /// `DigMessage.id` for cheap correlation).
    ///
    /// # Errors
    ///
    /// Same as [`send_dig_message`](Self::send_dig_message).
    pub async fn open_dig_stream(
        &self,
        peer_id: PeerId,
        stream_id: u64,
    ) -> Result<(), GossipError> {
        self.send_stream_frame(peer_id, &StreamFrame::Open { stream_id })
            .await
    }

    /// Send one `DATA` chunk of a dig-message stream (a [`StreamFrame::Data`]).
    ///
    /// `seq` is the monotonic 0-based sequence number; the receiver's
    /// [`StreamReassembler`](crate::service::dig_message::StreamReassembler)
    /// restores order. `payload` is opaque.
    ///
    /// # Errors
    ///
    /// Same as [`send_dig_message`](Self::send_dig_message).
    pub async fn send_dig_stream_data(
        &self,
        peer_id: PeerId,
        stream_id: u64,
        seq: u64,
        payload: Vec<u8>,
    ) -> Result<(), GossipError> {
        self.send_stream_frame(
            peer_id,
            &StreamFrame::Data {
                stream_id,
                seq,
                payload,
            },
        )
        .await
    }

    /// Close a dig-message stream (sends a [`StreamFrame::Close`] over opcode 220).
    ///
    /// # Errors
    ///
    /// Same as [`send_dig_message`](Self::send_dig_message).
    pub async fn close_dig_stream(
        &self,
        peer_id: PeerId,
        stream_id: u64,
    ) -> Result<(), GossipError> {
        self.send_stream_frame(peer_id, &StreamFrame::Close { stream_id })
            .await
    }

    /// Encode a [`StreamFrame`] into an opcode-220 envelope and deliver it,
    /// correlating on `stream_id`'s low 16 bits.
    async fn send_stream_frame(
        &self,
        peer_id: PeerId,
        frame: &StreamFrame,
    ) -> Result<(), GossipError> {
        let stream_id = match frame {
            StreamFrame::Open { stream_id }
            | StreamFrame::Data { stream_id, .. }
            | StreamFrame::Close { stream_id } => *stream_id,
        };
        let correlation_id = (stream_id & u64::from(u16::MAX)) as u16;
        self.send_dig_message(peer_id, &frame.encode(), Some(correlation_id))
            .await
    }

    /// Deliver a pre-built directed [`DigMessage`] to a single live peer.
    ///
    /// Shared by the dig-message seam helpers: runs the ban check, resolves the
    /// live [`DigLink`], and sends over its WebSocket. Stub / NAT-only pool members
    /// have no WebSocket transport (the dig-node mux phase adds it), so the send
    /// is counted but not transmitted — mirroring [`send_to`](Self::send_to).
    async fn send_directed_message(
        &self,
        peer_id: PeerId,
        msg: DigMessage,
    ) -> Result<(), GossipError> {
        self.require_running()?;
        let wire_len = message_wire_len(&msg);

        if self
            .inner
            .is_peer_id_banned_at(peer_id, metric_unix_timestamp_secs())
            .await
        {
            return Err(GossipError::PeerBanned(peer_id));
        }

        let maybe_live = {
            let peers = self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            match peers.get(&peer_id) {
                None => return Err(GossipError::PeerNotConnected(peer_id)),
                Some(PeerSlot::Live(l)) => Some(l.peer.clone()),
                Some(PeerSlot::Stub(_)) | Some(PeerSlot::Nat(_)) => None,
            }
        };
        if let Some(p) = maybe_live {
            p.send_message(msg).await.map_err(GossipError::from)?;
            record_live_peer_outbound_bytes(&self.inner, peer_id, wire_len);
        } else {
            self.inner
                .messages_sent
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner
                .bytes_sent
                .fetch_add(wire_len, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // DIG L2 per-opcode dispatch authority (#1404)
    // ------------------------------------------------------------------
    //
    // `broadcast_dig` / `send_dig` are the ONLY sanctioned way to put a DIG consensus-band
    // opcode (200-219) on the wire. Both consult `route_dig_message` so an opcode can never be
    // disseminated on the wrong shape — a fan-out (Plumtree eager / broadcast flood) opcode is
    // rejected by `send_dig`, a unicast opcode is rejected by `broadcast_dig`, introducer
    // opcodes route to the dedicated method, and a strategy with no live producer fails safe.

    /// Broadcast a DIG consensus-band opcode along its **fan-out** strategy.
    ///
    /// Valid only for opcodes whose [`route_dig_message`] strategy is
    /// [`PlumtreeEager`](RoutingStrategy::PlumtreeEager) (200/201/202/207) or
    /// [`BroadcastFlood`](RoutingStrategy::BroadcastFlood) (208). The opcode is framed
    /// ([`frame_dig_message`]) and delegated to [`broadcast`](Self::broadcast), which owns
    /// seen-set dedup + the message-cache. Returns the fan-out delivery count.
    ///
    /// # Errors
    ///
    /// - [`GossipError::WrongDispatchShape`] — the opcode is a unicast strategy (use
    ///   [`send_dig`](Self::send_dig)).
    /// - [`GossipError::UseDedicatedIntroducerMethod`] — an introducer opcode (218/219).
    /// - [`GossipError::StrategyNotYetProduced`] — a strategy with no live producer yet.
    /// - plus every error [`broadcast`](Self::broadcast) can return.
    pub async fn broadcast_dig(
        &self,
        msg_type: DigMessageType,
        body: Vec<u8>,
    ) -> Result<usize, GossipError> {
        self.require_running()?;
        match route_dig_message(msg_type) {
            // Fan-out strategies: the only ones `broadcast_dig` accepts.
            RoutingStrategy::PlumtreeEager | RoutingStrategy::BroadcastFlood => {
                self.broadcast(frame_dig_message(msg_type, body), None)
                    .await
            }
            // Unicast strategies belong to `send_dig`.
            RoutingStrategy::UnicastRequest | RoutingStrategy::UnicastResponse => {
                Err(GossipError::WrongDispatchShape)
            }
            other => Err(deferred_dispatch_error(other, msg_type)),
        }
    }

    /// Send a DIG consensus-band opcode to one peer along its **unicast** strategy.
    ///
    /// Valid only for opcodes whose [`route_dig_message`] strategy is
    /// [`UnicastRequest`](RoutingStrategy::UnicastRequest) (203/205/209) or
    /// [`UnicastResponse`](RoutingStrategy::UnicastResponse) (204/206/210). The opcode is framed
    /// ([`frame_dig_message`]) and delivered via [`send_directed_message`](Self::send_directed_message)
    /// — a directed request is intentionally NOT seen-set-deduped.
    ///
    /// # Errors
    ///
    /// - [`GossipError::WrongDispatchShape`] — the opcode is a fan-out strategy (use
    ///   [`broadcast_dig`](Self::broadcast_dig)).
    /// - [`GossipError::UseDedicatedIntroducerMethod`] — an introducer opcode (218/219).
    /// - [`GossipError::StrategyNotYetProduced`] — a strategy with no live producer yet.
    /// - plus every error [`send_directed_message`](Self::send_directed_message) can return.
    pub async fn send_dig(
        &self,
        peer_id: PeerId,
        msg_type: DigMessageType,
        body: Vec<u8>,
    ) -> Result<(), GossipError> {
        self.require_running()?;
        match route_dig_message(msg_type) {
            // Unicast strategies: the only ones `send_dig` accepts.
            RoutingStrategy::UnicastRequest | RoutingStrategy::UnicastResponse => {
                self.send_directed_message(peer_id, frame_dig_message(msg_type, body))
                    .await
            }
            // Fan-out strategies belong to `broadcast_dig`.
            RoutingStrategy::PlumtreeEager | RoutingStrategy::BroadcastFlood => {
                Err(GossipError::WrongDispatchShape)
            }
            other => Err(deferred_dispatch_error(other, msg_type)),
        }
    }

    /// Typed request/response — **stub** implements `RequestPeers → RespondPeers` via [`TypeId`];
    /// other pairs time out after [`DEFAULT_GOSSIP_REQUEST_TIMEOUT_SECS`].
    pub async fn request<T, B>(&self, peer_id: PeerId, body: B) -> Result<T, GossipError>
    where
        T: Streamable + ChiaProtocolMessage + Send + 'static,
        B: Streamable + ChiaProtocolMessage + Send + 'static,
    {
        self.require_running()?;
        let _ = encode_message(&body)?;
        if self
            .inner
            .is_peer_id_banned_at(peer_id, metric_unix_timestamp_secs())
            .await
        {
            return Err(GossipError::PeerBanned(peer_id));
        }
        let maybe_live = {
            let peers = self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            match peers.get(&peer_id) {
                None => return Err(GossipError::PeerNotConnected(peer_id)),
                Some(PeerSlot::Live(l)) => Some(l.peer.clone()),
                // Stub + POOL-* `dig-nat` members have no WebSocket `DigLink`; the typed WS
                // send/request path treats them like a stub (the dig-node phase adds the mux RPC).
                Some(PeerSlot::Stub(_)) | Some(PeerSlot::Nat(_)) => None,
            }
        };
        if let Some(p) = maybe_live {
            return p.request_infallible(body).await.map_err(GossipError::from);
        }

        if TypeId::of::<B>() == TypeId::of::<RequestPeers>()
            && TypeId::of::<T>() == TypeId::of::<RespondPeers>()
        {
            let resp = empty_respond_peers()?;
            let bytes = resp
                .to_bytes()
                .map_err(|e| GossipError::from(dig_peer_protocol::ClientError::Streamable(e)))?;
            return T::from_bytes(&bytes)
                .map_err(|e| GossipError::from(dig_peer_protocol::ClientError::Streamable(e)));
        }

        // Unimplemented request/response pairs for stub peers — live peers handled above.
        Err(GossipError::RequestTimeout)
    }

    /// Always empty until CON-001 builds [`PeerConnection`] from live peers (see module docs).
    pub async fn connected_peers(&self) -> Vec<PeerConnection> {
        let _ = self.require_running();
        Vec::new()
    }

    /// How many connected peers a [`broadcast`](Self::broadcast) currently CANNOT reach.
    ///
    /// A caller comparing this against [`peer_count`](Self::peer_count) and the value a broadcast
    /// returns can tell three states apart that a delivery count alone conflates: nobody is
    /// connected, everybody was reached, and peers are connected but silent. The last one is the
    /// live configuration that hid dig_ecosystem#3061/#3062 — a node reporting a successful announce
    /// while the only peer that could act on it received nothing.
    ///
    /// Counts `dig-nat` mux peers (no gossip transport wired over the mux in this crate) and
    /// Plumtree-lazy peers (no `LazyAnnounce` producer yet). Returns 0 if the peer map is poisoned.
    #[must_use]
    pub fn unreachable_peer_count(&self) -> usize {
        let Ok(peers) = self.inner.peers.lock() else {
            return 0;
        };
        let Ok(plumtree) = self.inner.plumtree.lock() else {
            return 0;
        };
        peers
            .iter()
            .filter(|(pid, slot)| match slot {
                PeerSlot::Nat(_) => true,
                PeerSlot::Live(_) => !plumtree.is_eager(pid),
                PeerSlot::Stub(_) => false,
            })
            .count()
    }

    pub async fn peer_count(&self) -> usize {
        self.inner.peers.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub async fn get_connections(
        &self,
        _node_type: Option<NodeType>,
        _outbound_only: bool,
    ) -> Vec<PeerConnection> {
        let _ = self.require_running();
        Vec::new()
    }

    /// Outbound TLS peer: [`crate::connection::outbound::connect_outbound_peer`] + `RequestPeers` (CON-001).
    ///
    /// **Spec:** [`CON-001.md`](../../../docs/requirements/domains/connection/specs/CON-001.md) — uses
    /// [`dig_peer_protocol::create_native_tls_connector`] / rustls equivalent, Chia [`Handshake`], then
    /// merges [`RespondPeers::peer_list`] via [`crate::discovery::address_manager::AddressManager::add_to_new_table`].
    ///
    /// **Tests without a WSS peer:** use [`Self::__connect_stub_peer_with_direction`] (deterministic
    /// [`peer_id_for_addr`] keys) so API-002 matrices stay offline.
    pub async fn connect_to(&self, addr: std::net::SocketAddr) -> Result<PeerId, GossipError> {
        self.require_running()?;
        if self.inner.dial_targets_local_listen(addr) {
            return Err(GossipError::SelfConnection);
        }
        // Reconnect symmetry (#1703) — the outbound mirror of the inbound #1691 newest-wins policy.
        //
        // A dropped outbound link leaves this endpoint's slot in `peers` (dig-gossip never reaps a
        // slot on disconnect), so `connect_to` must be able to re-establish it: no `DuplicateConnection`
        // reject, and the freshly mTLS-authenticated session supersedes the stale slot at insert time
        // below (keyed by the handshake-verified `peer_id`, replace-not-grow — mirroring
        // `negotiate_inbound_over_ws`).
        //
        // The one-outbound-per-/16 (INT-006) / one-per-AS (INT-007) diversity decision is DELIBERATELY
        // NOT made here on the dialed address. The pre-handshake address is unverified and a peer-map
        // slot at that address may be an INBOUND Live slot or a Nat slot (whose `remote` is sourced
        // from attacker-influenced `RespondPeers`) — neither of which consumes THIS node's outbound
        // diversity budget. Deciding diversity on address alone would let a peer bypass the cap and
        // widen an eclipse. The decision is instead made AFTER the handshake, against the VERIFIED
        // identity (see the diversity gate below). Only the max-connections admission is pre-checked
        // here (unchanged; the map stays bounded at one slot per `peer_id`).
        {
            let peers = self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            if peers.len() >= self.inner.config.max_connections {
                return Err(GossipError::MaxConnectionsReached(
                    self.inner.config.max_connections,
                ));
            }
        }

        let connector = crate::connection::outbound::tls_connector_for_cert(&self.inner.tls)
            .map_err(GossipError::from)?;
        let network_id =
            crate::connection::outbound::network_id_handshake_string(self.inner.config.network_id);
        let opts = self.inner.config.peer_options;

        let out = crate::connection::outbound::connect_outbound_peer(
            network_id,
            connector,
            addr,
            opts,
            self.inner.config.software_version.clone(),
        )
        .await
        .map_err(GossipError::from)?;

        let peer_id = peer_id_from_tls_spki_der(&out.remote_spki_der);
        // #1584: self-connection guard by verified identity. The address-based `dial_targets_local_listen`
        // check above only catches a dial to our OWN listen address; a relay introducer advertising this
        // node at its external IP slips past it, so re-check by the handshake-verified `peer_id` (mirrors
        // the inbound `precheck_inbound_peer` guard) before this peer is added to the pool + published as
        // `PoolEvent::PeerAdded`.
        if peer_id == self.inner.config.peer_id {
            let _ = out.peer.close().await;
            return Err(GossipError::SelfConnection);
        }
        let is_banned = self
            .inner
            .is_peer_id_banned_at(peer_id, metric_unix_timestamp_secs())
            .await;
        if is_banned {
            let _ = out.peer.close().await;
            return Err(GossipError::PeerBanned(peer_id));
        }
        // #1703: no `DuplicateConnection` reject — a re-dial to a peer whose stale slot survives a
        // dropped link supersedes it at insert time below (newest-wins, mTLS-gated — #1691). The
        // outbound diversity admission (INT-006/INT-007) is decided ATOMICALLY with that insert, under
        // one `peers`-lock hold, against the VERIFIED identity — see the gate at the insert below.

        let src = PeerInfo {
            host: addr.ip().to_string(),
            port: addr.port(),
        };
        // DSC-007: Request peers from the outbound peer and add to address manager.
        // SPEC §6.6, Chia node_discovery.py:135-136 — "send RequestPeers on outbound connect."
        let respond: RespondPeers = out
            .peer
            .request_infallible(RequestPeers::new())
            .await
            .map_err(GossipError::from)?;

        // DSC-007: Cap received peers per SPEC §1.6#10 (1000/request) and §1.6#11 (3000 total).
        // Always call add_to_new_table even with an empty list so the address-manager log records
        // that the RequestPeers exchange occurred — CON-001 test hook relies on this.
        let capped = crate::discovery::node_discovery::cap_received_peers(
            &respond.peer_list,
            &self.inner.total_peers_received,
        );
        self.inner.address_manager.add_to_new_table(capped, &src, 0);

        // CON-005: one inbound [`InboundRateLimiter`] per live slot (insert **before** the forwarder).
        let inbound_limiter = Arc::new(Mutex::new(
            crate::connection::inbound_limits::new_inbound_rate_limiter(
                self.inner.config.peer_options.rate_limit_factor,
            ),
        ));

        let meta = StubPeer {
            remote: addr,
            node_type: crate::connection::handshake::dig_node_type_of(
                out.their_handshake.node_type,
            ),
            is_outbound: true,
        };
        let peer = out.peer;
        let peer_for_keepalive = peer.clone();
        let lim = Arc::clone(&inbound_limiter);
        let opened_at = metric_unix_timestamp_secs();

        // Allocate this session's generation and start its keepalive BEFORE inserting the slot, so
        // the slot owns the keepalive `AbortHandle` and a stale task compare-and-removes against the
        // generation (#1691). The keepalive loop sleeps an interval before its first probe, so
        // spawning it just before the insert cannot race the map. The `AbortHandle` is `Clone`; the
        // slot takes a clone and we keep the original to abort the task if the admission is refused.
        let generation = self.inner.next_peer_generation();
        let keepalive_task = crate::connection::keepalive::spawn_keepalive_task(
            self.inner.clone(),
            peer_id,
            generation,
            peer_for_keepalive.clone(),
        );

        // #1703 eclipse-admission gate + newest-wins supersede, decided ATOMICALLY with the insert
        // under ONE `peers`-lock hold (the check→insert must not be split, or two concurrent net-new
        // dials into the same empty group could both pass — the TOCTOU). Occupancy is DERIVED FROM
        // `peers` — the single source of truth — via `outbound_diversity_conflict`, never a parallel
        // side-set that could drift and under-count. The decision keys on the VERIFIED `peer_id`:
        //
        // * A slot ALREADY outbound under THIS `peer_id` is a genuine reconnect whose group/AS the map
        //   already counts (it is excluded from the conflict scan), so it is admitted + superseded with
        //   no diversity check — a single identity reconnecting is not net-new occupancy (this also
        //   preserves the #1703 item-2 deferral: because occupancy is map-derived, a same-identity
        //   migration can no longer corrupt the accounting a later net-new dial sees).
        // * Otherwise (a net-new identity, or an admission that would replace an INBOUND/Nat slot at
        //   this address — neither of which occupies the OUTBOUND budget) it is net-new outbound
        //   occupancy and MUST satisfy INT-006/INT-007, else be refused. The pre-handshake dial address
        //   is never trusted for this; an attacker seeds it via `RespondPeers`.
        let admission = {
            let mut peers = self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            let is_outbound_reconnect =
                matches!(peers.get(&peer_id), Some(slot) if slot.is_outbound());
            let conflict = if is_outbound_reconnect {
                None
            } else {
                // A direct TLS dial always inserts `PeerSlot::Live` with a real remote (#1716):
                // never relayed, so the full /16//AS diversity cap applies.
                crate::service::state::outbound_diversity_conflict(
                    &peers,
                    &self.inner.as_table,
                    peer_id,
                    addr.ip(),
                    false,
                )
            };
            match conflict {
                Some(kind) => Err(kind),
                None => Ok(peers.insert(
                    peer_id,
                    PeerSlot::Live(LiveSlot {
                        meta,
                        peer,
                        remote_protocol_version: out.their_handshake.protocol_version.clone(),
                        remote_software_version_sanitized: out.remote_software_version_sanitized,
                        reputation: std::sync::Arc::new(std::sync::Mutex::new(
                            crate::types::reputation::PeerReputation::default(),
                        )),
                        inbound_rate_limiter: Arc::clone(&inbound_limiter),
                        traffic: Arc::new(Mutex::new(PeerConnectionWireMetrics::new(opened_at))),
                        generation,
                        keepalive_task: keepalive_task.clone(),
                    }),
                )),
            }
        };

        let superseded = match admission {
            Ok(superseded) => superseded,
            Err(kind) => {
                // Refused (diversity): the slot was NOT inserted. Abort the keepalive we optimistically
                // spawned for this never-admitted session and close the completed handshake stream.
                keepalive_task.abort();
                let _ = peer_for_keepalive.close().await;
                let ip = addr.ip();
                return Err(match kind {
                    crate::service::state::OutboundDiversityConflict::Subnet => {
                        GossipError::ConnectionFiltered(SafeText::from_untrusted(format!(
                            "INT-006: /16 subnet group already has an outbound connection for {ip}"
                        )))
                    }
                    crate::service::state::OutboundDiversityConflict::As => {
                        GossipError::ConnectionFiltered(SafeText::from_untrusted(format!(
                            "INT-007: AS already has an outbound connection for {ip}"
                        )))
                    }
                });
            }
        };

        // Newest-wins supersede (#1703) — the outbound counterpart of the inbound #1691 supersede.
        // Tear the displaced Live slot down AFTER releasing the `peers` lock: abort its keepalive so
        // it cannot fire a ghost teardown against this newer session, then close its WebSocket
        // (dropping a `LiveSlot` does not close the socket). The generation guard in
        // `disconnect_after_keepalive_failure` is the load-bearing invariant; this abort is the prompt
        // first line of defence. A displaced Stub/Nat slot carries no keepalive and is closed by being
        // dropped here (its dedicated transport teardown is #1703 items 2/4, out of scope). No
        // diversity-budget bookkeeping is needed on supersede — occupancy is derived from the map, so
        // removing the old slot and inserting the new one IS the accounting.
        if let Some(stale) = superseded {
            super::state::retire_slot(stale).await;
        }

        // INT-001: Register peer in Plumtree state (starts as eager per SPEC §8.1).
        if let Ok(mut pt) = self.inner.plumtree.lock() {
            pt.add_peer(peer_id);
        }

        // Answer inbound `RequestPeers` (keepalive / discovery) with correlated `RespondPeers`.
        // `DigLink` routes `id: Some` REPLIES through its local `RequestMap`; an inbound remote
        // REQUEST matches nothing there, so it is forwarded on `inbound_rx` and must be answered
        // explicitly with `DigLink::send_message` carrying the same correlation id.
        let peer_inbound_rpc = peer_for_keepalive.clone();
        if let Ok(g) = self.inner.inbound_tx.lock() {
            if let Some(tx) = g.as_ref() {
                let tx = tx.clone();
                let mut inbound_rx = out.inbound_rx;
                let pid_task = peer_id;
                // This session's generation — so a rate-limit trip cannot penalize a later reconnect (#1691).
                let gen_task = generation;
                let peer_rpc = peer_inbound_rpc;
                let state_fwd = self.inner.clone();
                let lim_fwd = lim;
                tokio::spawn(async move {
                    while let Some(msg) = inbound_rx.recv().await {
                        let allowed = lim_fwd.lock().map(|mut g| g.allows(&msg)).unwrap_or(true);
                        if !allowed {
                            // Drop the frame unconditionally (the #1720 per-connection cap), but charge
                            // a reputation penalty only when attributable to this connection: a size-
                            // violating frame always, but an over-cap public flood (221/222) is exempt —
                            // its delivering peer is a forwarder, not the origin (#1626, #1796).
                            if crate::connection::inbound_limits::rejected_frame_incurs_penalty(
                                &msg,
                            ) {
                                apply_inbound_rate_limit_violation(&state_fwd, pid_task, gen_task);
                            }
                            continue;
                        }
                        {
                            let wl_in = message_wire_len(&msg);
                            record_live_peer_inbound_bytes(&state_fwd, pid_task, wl_in);
                        }
                        if msg.msg_type == chia_opcodes::REQUEST_PEERS {
                            if let Ok(body) = RespondPeers::new(vec![]).to_bytes() {
                                let reply = DigMessage::new(
                                    chia_opcodes::RESPOND_PEERS,
                                    msg.id,
                                    body.into(),
                                );
                                let wl_out = Some(message_wire_len(&reply));
                                let _ = peer_rpc.send_message(reply).await;
                                if let Some(w) = wl_out {
                                    record_live_peer_outbound_bytes(&state_fwd, pid_task, w);
                                }
                            }
                        }
                        let _ = tx.send((pid_task, msg));
                    }
                });
            }
        }

        // (Keepalive was started before the slot insert so the slot could own its `AbortHandle` —
        // #1691.)

        self.inner
            .total_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // #1581: feed the directly-connected peer into the pool-event stream exactly like the
        // relayed path (`adopt_nat_connection`) and the pool dial loop do. Without this a peer
        // reached by a direct WSS dial is invisible to every `PoolEvent` consumer — DHT routing
        // (#1574's `spawn_dht_routing_feed`), the peer-selector, and PEX — so direct-path DISCOVER
        // returns zero providers while the relayed path works. Same shape (verified `peer_id`,
        // DHT-reachable `addr`) `adopt_nat_connection` publishes, so downstream consumers behave
        // identically on both paths.
        self.inner
            .pool
            .publish(crate::service::peer_pool::PoolEvent::PeerAdded { peer_id, addr });
        Ok(peer_id)
    }

    // ------------------------------------------------------------------
    // Unified dig-nat transport (L7 peer-network) — reach peers over the
    // NAT-traversal ladder (direct → UPnP → NAT-PMP → PCP → hole-punch →
    // relay-last) instead of only a bespoke direct WSS dial. The gossip
    // ALGORITHMS ride unchanged on the resulting multiplexed transport.
    // ------------------------------------------------------------------

    /// This node's own `peer_id` = SHA-256(its TLS SPKI DER) — the identity peers verify it by.
    ///
    /// Derived from the service's loaded [`ChiaCertificate`], so it is stable for the life of the
    /// node's certificate and equal to what a remote computes from the cert this node presents.
    /// Gated on the running lifecycle like every handle method.
    pub fn local_peer_id(&self) -> Result<PeerId, GossipError> {
        self.require_running()?;
        let spki = crate::connection::outbound::spki_der_from_leaf_cert_der(&first_cert_der(
            &self.inner.tls.cert_pem,
        )?)
        .map_err(GossipError::from)?;
        Ok(peer_id_from_tls_spki_der(&spki))
    }

    /// This node's CA-signed [`dig-tls`](dig_nat::NodeCert) identity for the unified `dig-nat`
    /// transport.
    ///
    /// The returned [`NatLocalIdentity`](crate::nat::NatLocalIdentity) is a
    /// [`NodeCert`](dig_nat::NodeCert): an mTLS leaf chained to the shipped DigNetwork CA carrying the
    /// #1204 BLS-G1 binding — what [`Self::connect_via_nat`] presents as the mTLS client certificate
    /// (#1268/#1280 self-signed→CA-signed cutover). Minted + cached on first use for a stable transport
    /// `peer_id`. This transport `peer_id` is derived from the NodeCert's SPKI; when the caller injects
    /// its persistent identity via [`GossipConfig::nat_identity`](crate::types::config::GossipConfig::nat_identity)
    /// (#1541), it equals [`Self::local_peer_id`] (the chia-ssl WebSocket-path id) — ONE identity across
    /// all transports. Absent injection it falls back to a per-process ephemeral id (tests /
    /// identity-less services only). Gated on the running lifecycle.
    pub fn nat_identity(
        &self,
    ) -> Result<std::sync::Arc<crate::nat::NatLocalIdentity>, GossipError> {
        self.require_running()?;
        self.inner.nat_node_cert()
    }

    /// Establish a peer connection over the unified `dig-nat` NAT-traversal ladder.
    ///
    /// Unlike [`Self::connect_to`] (a single direct WSS dial), this reaches peers that are only
    /// reachable via UPnP/NAT-PMP/PCP mappings, a relay-coordinated hole punch, or — last resort —
    /// relayed transport, exactly as the L7 peer-network spec prescribes. mTLS + `peer_id`
    /// verification are performed by `dig-nat` against `peer_id`, so the returned
    /// [`NatPeerConnection`](crate::nat::NatPeerConnection)'s remote identity is already confirmed.
    ///
    /// `methods` restricts which traversal tiers are enabled (still tried in canonical rank order —
    /// direct-first, relay-last); pass all of them for production, or e.g. just
    /// [`TraversalKind::Direct`](dig_nat::TraversalKind) in a test. `per_method_timeout` bounds each
    /// tier so the call never hangs (a `dig-nat` guarantee).
    ///
    /// This returns the multiplexed connection for the caller (the next integration phase, `dig-node`)
    /// to open gossip channels / range streams on; it does not itself insert the peer into the gossip
    /// peer map (that wiring — mapping mux streams to the message loop — lands with the node
    /// integration, keeping this change additive and the existing `connect_to` path intact).
    pub async fn connect_via_nat(
        &self,
        peer_id: PeerId,
        direct_addr: Option<std::net::SocketAddr>,
        methods: &[dig_nat::TraversalKind],
        per_method_timeout: Duration,
    ) -> Result<crate::nat::NatPeerConnection, GossipError> {
        self.require_running()?;
        let identity = self.nat_identity()?;
        let network_id =
            crate::connection::outbound::network_id_handshake_string(self.inner.config.network_id);
        let target = crate::nat::peer_target_for(peer_id, direct_addr, network_id);
        let config = dig_nat::NatConfig::builder()
            .enabled_methods(methods.to_vec())
            .per_method_timeout(per_method_timeout)
            .build();
        crate::nat::nat_connect(&target, &identity, &config)
            .await
            .map_err(|e| GossipError::NatError(SafeText::from_untrusted(e.to_string())))
    }

    /// Establish a pool auto-dial over the **FULL** `dig-nat` traversal ladder (#1517 defect 2).
    ///
    /// Unlike [`Self::connect_via_nat`] (which enables a caller-chosen tier set over a default
    /// runtime), this enables [`pool_auto_dial_traversal_methods`] — Direct … Relayed — AND supplies a
    /// [`Self::pool_dial_runtime`] carrying the relay dialer, so after every direct / port-mapping /
    /// hole-punch tier fails the strategy still reaches the peer over the SPKI-pinned relay circuit
    /// rather than stopping at Direct. `peer_id` pins the mTLS SPKI (defect 1); `direct_addr` seeds the
    /// direct/mapping tiers (a relay-only peer passes `None`).
    async fn connect_via_nat_full_ladder(
        &self,
        peer_id: PeerId,
        direct_addr: Option<std::net::SocketAddr>,
        per_method_timeout: Duration,
    ) -> Result<crate::nat::NatPeerConnection, GossipError> {
        self.require_running()?;
        let identity = self.nat_identity()?;
        let network_id =
            crate::connection::outbound::network_id_handshake_string(self.inner.config.network_id);
        let target = crate::nat::peer_target_for(peer_id, direct_addr, network_id);
        let config = dig_nat::NatConfig::builder()
            .enabled_methods(pool_auto_dial_traversal_methods())
            .per_method_timeout(per_method_timeout)
            .build();
        let runtime = self.pool_dial_runtime();
        crate::nat::nat_connect_with_runtime(&target, &identity, &config, &runtime)
            .await
            .map_err(|e| GossipError::NatError(SafeText::from_untrusted(e.to_string())))
    }

    /// Build the [`dig_nat::NatRuntime`] the pool auto-dial composes the full ladder from (#1517
    /// defect 2): the local listen port (enables the UPnP mapping tier) and — when a live relay
    /// reservation is attached ([`Self::attach_relay_status`]) — a
    /// [`ReservationRelayedTransport`](dig_nat::ReservationRelayedTransport) relay dialer, so the
    /// Relayed tier can actually COMPOSE (dig-nat silently drops the relay tier when no relay dialer is
    /// present, which is why the old default-runtime dial never exercised it). Tiers whose runtime
    /// inputs are absent are skipped by dig-nat — the composition stays honest.
    fn pool_dial_runtime(&self) -> dig_nat::NatRuntime {
        let mut builder = dig_nat::NatRuntime::builder();
        if let Some(port) = self
            .inner
            .listen_bound_addr
            .lock()
            .ok()
            .and_then(|g| *g)
            .map(|a| a.port())
        {
            builder = builder.local_port(port);
        }
        #[cfg(feature = "relay")]
        {
            if let Some(status) = self.inner.relay_status.lock().ok().and_then(|g| g.clone()) {
                // The endpoint is observability-only for the relayed tier (the byte path is the held
                // reservation's WebSocket, reached via `status.open_tunnel`), so an unspecified addr is
                // sufficient here.
                let relay_endpoint =
                    std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0));
                let dialer: std::sync::Arc<dyn dig_nat::RelayedDialer> = std::sync::Arc::new(
                    dig_nat::ReservationRelayedTransport::new(status, relay_endpoint),
                );
                builder = builder.relayed(dialer);
            }
        }
        builder.build()
    }

    // ------------------------------------------------------------------
    // Connected peer POOL (POOL-*) — the maintained set of ready, CONNECTED
    // peers dig-node's peer-RPC + downloads consume. See `crate::service::peer_pool`.
    // ------------------------------------------------------------------

    /// Adopt a `dig-nat`-dialed [`NatPeerConnection`](crate::nat::NatPeerConnection) into the connected
    /// peer pool, so it counts as a connected peer (`peer_count` / `stats` / dedup / churn) and its
    /// multiplexed transport is retained for dig-node to open gossip channels + range streams on.
    ///
    /// Returns `Ok(peer_id)` on adoption. Refuses (and drops the connection) if the peer is this node
    /// itself ([`GossipError::SelfConnection`]), is banned ([`GossipError::PeerBanned`]), the pool is
    /// full ([`GossipError::MaxConnectionsReached`] against [`GossipConfig::max_connections`]), or an
    /// outbound diversity budget is exhausted ([`GossipError::ConnectionFiltered`]). Emits a
    /// [`PoolEvent::PeerAdded`](crate::service::peer_pool::PoolEvent) on success.
    ///
    /// This is the single place a `dig-nat` connection becomes a pool member; the pool maintenance loop
    /// and a manual dial both go through it, so the dedup + cap + churn rules hold uniformly.
    ///
    /// # Re-adoption policy — newest-wins (dig_ecosystem#1762)
    ///
    /// A slot already held for `peer_id` does **not** refuse this adoption; the freshly
    /// mTLS-authenticated session SUPERSEDES it, exactly as the inbound path (#1691) and
    /// [`Self::connect_to`] (#1703) do. The map keeps one slot per `peer_id` (`HashMap::insert`
    /// replaces, never grows), so re-adoption churn cannot grow it.
    ///
    /// The rule is stated over the CLASS of stale slots, not one cause. A peer-map slot carries no
    /// liveness value to consult — dig-gossip never reaps a slot on disconnect — so a
    /// `contains_key` refusal cannot distinguish a live peer from a dead relay circuit whose mTLS
    /// failed (#1761), a half-open TCP link, a vanished peer, or a timed-out mapping. That was the
    /// #1762 defect: because this is the ONE path both the relayed and the direct tier are adopted
    /// through, a dead relayed slot refused the direct adoption that would have worked, leaving the
    /// peer unreachable while the other side reported zero connections. Refusing only a
    /// *demonstrably live* slot would have to enumerate the ways a slot dies; superseding instead is
    /// correct for every one of them.
    ///
    /// Safe because `peer_id` comes from the **completed, SPKI-pinned mTLS handshake** dig-nat
    /// performed (see [`crate::nat::NatPeerConnection::peer_id`]): only the holder of that identity's
    /// private key can produce a connection that reaches here, so no third party can displace a live
    /// peer. The self (#1584) and ban (CON-007) guards run BEFORE the insert and are unaffected — a
    /// re-adoption is not a route around them.
    pub async fn adopt_nat_connection(
        &self,
        conn: crate::nat::NatPeerConnection,
    ) -> Result<PeerId, GossipError> {
        self.require_running()?;
        let peer_id = conn.peer_id();
        let remote = conn.remote_addr();
        let method = conn.method();

        // #1584: self-connection guard on the OUTBOUND pool-add path, mirroring the inbound
        // `precheck_inbound_peer` guard. A relay introducer can advertise this node to itself; without
        // this check the self entry is adopted, published as `PoolEvent::PeerAdded`, and fed to the DHT
        // routing table + peer selector as a provider — so a reader "discovers" itself, self-dials on a
        // content read, and dead-ends (HTTP 404) instead of fetching from the real holder.
        if peer_id == self.inner.config.peer_id {
            return Err(GossipError::SelfConnection);
        }

        if self
            .inner
            .is_peer_id_banned_at(peer_id, metric_unix_timestamp_secs())
            .await
        {
            return Err(GossipError::PeerBanned(peer_id));
        }

        // Both admission budgets and the insert are decided under ONE `peers`-lock hold, so the
        // check→insert is atomic (no TOCTOU where two concurrent net-new adoptions into the same empty
        // group both pass). The displaced slot leaves the lock scope in `superseded` and is torn down
        // after the lock is released.
        let superseded = {
            let mut peers = self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;

            // #1762: no `DuplicateConnection` refusal — the held slot is superseded by the insert
            // below (newest-wins, mTLS-gated; see the policy on this function). What a held slot DOES
            // decide is how much of each budget this adoption consumes:
            //
            // * `replaces_held_slot` — the insert replaces an entry rather than adding one, so the map
            //   does not grow and `max_connections` is already satisfied. Charging the cap here would
            //   strand a peer behind its own stale slot whenever the pool is full — the same class of
            //   defect as the refusal itself, one budget further in.
            // * `is_outbound_reconnect` — the peer already occupies THIS node's outbound diversity
            //   budget (its /16, its AS, or one relayed slot), so re-dialling it is not net-new
            //   occupancy; counting it would be an off-by-one that refuses the last relayed peer's
            //   own recovery. Mirrors the #1703 `connect_to` exemption. An INBOUND or non-outbound
            //   held slot does NOT occupy the outbound budget, so it earns no diversity exemption.
            //
            // Every NET-NEW identity still faces both budgets in full — the eclipse caps below are
            // unchanged for the attacker-influenceable case (#1710/#1716).
            let held = peers.get(&peer_id);
            let replaces_held_slot = held.is_some();
            let is_outbound_reconnect = matches!(held, Some(slot) if slot.is_outbound());

            if !replaces_held_slot && peers.len() >= self.inner.config.max_connections {
                return Err(GossipError::MaxConnectionsReached(
                    self.inner.config.max_connections,
                ));
            }
            // #1710: the INT-006 (/16) + INT-007 (AS) outbound eclipse caps must gate the AUTO-POOL
            // adoption path too, not only manual `connect_to`. This is the attacker-influenceable
            // surface — pool candidates originate from `RespondPeers`, so an adversary can seed many
            // same-/16 (or same-AS) reservations and, absent this gate, occupy the outbound budget the
            // diversity caps exist to protect. Every NET-NEW identity — that is, every adoption except
            // the `is_outbound_reconnect` case carved out above (#1762) — is net-new outbound occupancy
            // that MUST satisfy the caps. Occupancy is derived from `peers` (the #1703 single source of
            // truth), never a parallel side-set that could drift and under-count.
            let candidate_is_relayed = matches!(method, dig_nat::TraversalKind::Relayed);
            if is_outbound_reconnect {
                // Not net-new occupancy — see `is_outbound_reconnect` above (#1762).
            } else if candidate_is_relayed {
                // #1716 (INT-006a): the relayed tier is EXEMPT from the /16//AS cap (the relay
                // endpoint carries no peer address) and is instead bounded by `max_relayed_outbound`,
                // so a relayed-Sybil flood cannot occupy the whole outbound budget. Counted + enforced
                // under the same `peers`-lock hold as the insert below (atomic, no TOCTOU).
                let relayed_outbound = peers
                    .values()
                    .filter(|s| crate::service::state::is_relayed(s) && s.is_outbound())
                    .count();
                let cap = crate::service::peer_pool::max_relayed_outbound(
                    self.inner.config.target_outbound_count,
                );
                if relayed_outbound >= cap {
                    return Err(GossipError::ConnectionFiltered(SafeText::from_untrusted(
                        format!("INT-006a: relayed outbound cap reached ({cap})"),
                    )));
                }
            } else if let Some(kind) = crate::service::state::outbound_diversity_conflict(
                &peers,
                &self.inner.as_table,
                peer_id,
                remote.ip(),
                false,
            ) {
                let ip = remote.ip();
                return Err(match kind {
                    crate::service::state::OutboundDiversityConflict::Subnet => {
                        GossipError::ConnectionFiltered(SafeText::from_untrusted(format!(
                            "INT-006: /16 subnet group already has an outbound connection for {ip}"
                        )))
                    }
                    crate::service::state::OutboundDiversityConflict::As => {
                        GossipError::ConnectionFiltered(SafeText::from_untrusted(format!(
                            "INT-007: AS already has an outbound connection for {ip}"
                        )))
                    }
                });
            }
            peers.insert(
                peer_id,
                PeerSlot::Nat(super::state::NatSlot {
                    conn: super::state::NatTransport::Owned(Box::new(conn)),
                    sink: None,
                    remote,
                    is_outbound: true,
                    method,
                }),
            )
        };

        // Newest-wins supersede (#1762) — tear the displaced slot down AFTER releasing the `peers`
        // lock. A displaced `Live` slot needs its keepalive aborted first, or that stale task's
        // teardown could fire against this newer session (the #1691 ghost-keepalive race; the
        // generation guard in `disconnect_after_keepalive_failure` is the load-bearing invariant, this
        // abort is the prompt first line of defence), then its WebSocket closed — dropping a `LiveSlot`
        // does not close the socket. A displaced `Nat`/`Stub` slot owns no keepalive and its transport
        // is closed by being dropped here (`Nat` drop tears down the mux session — the #1717
        // invariant), which is exactly what frees the dead relay circuit this fix supersedes.
        if let Some(PeerSlot::Live(stale)) = superseded {
            stale.keepalive_task.abort();
            let _ = stale.peer.close().await;
        }

        // INT-001: a pool member participates in Plumtree like any connected peer (starts eager).
        if let Ok(mut pt) = self.inner.plumtree.lock() {
            pt.add_peer(peer_id);
        }
        self.inner
            .total_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner
            .pool
            .publish(crate::service::peer_pool::PoolEvent::PeerAdded {
                peer_id,
                addr: remote,
            });
        // #2176: mirror dig-nat's "peer connection established" so a pooled connection's WHOLE
        // lifecycle — establish here, teardown at `disconnect` / `reap_departed_peers` — is visible in
        // logs. The silent drop is why 10k+ redundant re-dials churned invisibly for days.
        tracing::info!(peer_id = %peer_id, remote = %remote, ?method, "pool connection established");
        Ok(peer_id)
    }

    /// Snapshot each connected peer's ADVERTISED SOFTWARE BUILD: `(peer_id, software_version)`
    /// for every connected peer (dig_ecosystem#2215).
    ///
    /// The string is the peer's Chia `Handshake.software_version` after CON-008 Cc/Cf sanitization
    /// — the raw value it advertised, carried verbatim. This crate deliberately does NOT interpret
    /// it: the string-to-`PeerSoftware` mapping (including the legacy `"0.0.0"` sentinel that every
    /// pre-#2215 peer advertises) belongs at the control boundary, in
    /// `dig-node-control-interface`, so it is defined once and this transport gains no dependency
    /// on an RPC schema.
    ///
    /// # Peers with no handshake
    ///
    /// Stub and adopted `dig-nat` slots never performed a Chia handshake, so they report the empty
    /// string — the same value a peer that advertises nothing sends, and the same "unknown"
    /// reading. They are INCLUDED rather than filtered out, because a census that silently omits
    /// peers reports a smaller network than the one that is connected.
    pub fn connected_pool_peers_with_software(&self) -> Vec<(PeerId, String)> {
        let Ok(peers) = self.inner.peers.lock() else {
            return Vec::new();
        };
        peers
            .iter()
            .map(|(pid, slot)| {
                let software = match slot {
                    PeerSlot::Live(l) => l.remote_software_version_sanitized.clone(),
                    PeerSlot::Stub(_) | PeerSlot::Nat(_) => String::new(),
                };
                (*pid, software)
            })
            .collect()
    }

    /// Register the RESPONDER half of an authenticated relayed circuit into the connected pool
    /// (**#870 / #1871**) — relay-typed, inbound, and structurally non-dialable.
    ///
    /// The reservation holder does not dial: `dig-nat`'s
    /// [`RelayAcceptor`](dig_nat::RelayAcceptor) hands it a circuit a peer opened THROUGH the relay,
    /// already carrying the identical mTLS a direct link gets. Before this path existed, that peer
    /// entered no pool at all — so a node actively serving it reported `connected_peers = 0`, and
    /// every subsystem that answers "am I connected" from the pool (health, metrics, peer selection)
    /// saw an isolated node while bytes were flowing.
    ///
    /// # Authenticated only
    ///
    /// The caller MUST pass a connection whose `peer_id` came from a completed mTLS handshake — which
    /// is what `dig-nat` hands the reservation holder, its verifier having captured the peer's
    /// certificate-derived id. A relay therefore cannot inflate this node's peer count with peers it
    /// never authenticated: it is not in this process and cannot call this at all. The guarantee is
    /// that of the CALLER, not of the type — `dig_nat::PeerConnection` has public fields, so an
    /// in-process caller could stamp any id it liked (this crate's own test harness does exactly that).
    ///
    /// # Non-dialable by type
    ///
    /// The registered slot carries [`TraversalKind::Relayed`](dig_nat::TraversalKind), so
    /// [`Self::dialable_pool_peers`] cannot return it and
    /// [`ConnectedPoolPeer::dial_addr`](crate::service::peer_pool::ConnectedPoolPeer::dial_addr) is
    /// `None`. That is deliberate rather than conventional: the peer answers at no address, so a
    /// selection path that dialed it would fail every attempt and might evict the working circuit.
    ///
    /// # Admission
    ///
    /// Refuses this node itself ([`GossipError::SelfConnection`]), a banned peer
    /// ([`GossipError::PeerBanned`]), a full pool ([`GossipError::MaxConnectionsReached`]), a
    /// non-relayed connection (that is [`Self::adopt_nat_connection`]'s job), a peer already holding a
    /// NON-relayed slot (a circuit never demotes a dialable peer to a non-dialable one), and more than
    /// [`max_relayed_inbound`](crate::service::peer_pool::max_relayed_inbound) accepted circuits —
    /// the last so a single relay cannot fill the pool with peers of its choosing. No OUTBOUND
    /// diversity budget is charged: the responder dialed nothing, so it occupies no outbound group.
    ///
    /// A held slot exempts an adoption only from a budget it ALREADY occupies: re-adopting an accepted
    /// circuit is free, while converting a relayed OUTBOUND slot into an accepted one still pays the
    /// accepted-relayed cap. Exempting every held slot would make that cap a formality — any peer the
    /// relay could get admitted by another path could then be converted into a circuit.
    /// Re-adoption is otherwise newest-wins for the same reasons as [`Self::adopt_nat_connection`].
    pub async fn adopt_relayed_inbound(
        &self,
        conn: crate::nat::NatPeerConnection,
    ) -> Result<PeerId, GossipError> {
        let peer_id = conn.peer_id();
        let remote = conn.remote_addr();
        let method = conn.method();
        self.adopt_relayed_inbound_inner(
            peer_id,
            remote,
            method,
            super::state::NatTransport::Owned(Box::new(conn)),
            None,
        )
        .await
    }

    /// Register an authenticated relayed circuit whose session the CALLER keeps (**#1871**) — the
    /// same admission as [`Self::adopt_relayed_inbound`], taking a cheap liveness observer instead of
    /// the connection.
    ///
    /// # Why this exists
    ///
    /// [`Self::adopt_relayed_inbound`] takes the connection BY VALUE, and
    /// [`PeerSession`](dig_nat::PeerSession) is not `Clone` — it owns the inbound-stream receiver. A
    /// node that is SERVING the relayed peer (dig-node's L7 peer-RPC loop needs `&mut PeerSession`)
    /// therefore cannot call it without giving the session up: it would buy the connection count and
    /// stop answering the peer. Because that trade is unacceptable, the call was simply never made,
    /// and a NAT'd peer — most people — formed zero COUNTED connections while being served fine.
    ///
    /// The pool never sends over a relayed slot's transport; the one thing it asks is whether the peer
    /// is still up, for the #1703 departed-peer reaper. A
    /// [`ClosedHandle`](dig_nat::ClosedHandle) answers exactly that, is `Clone`, and costs one atomic
    /// load — so ownership stays with the server loop and the peer is both COUNTED and STILL SERVED.
    ///
    /// # Caller obligations
    ///
    /// * `peer_id` MUST come from the completed mTLS handshake (as in [`Self::adopt_relayed_inbound`] —
    ///   the guarantee is the caller's, not the type's). `dig-nat` reports it as a
    ///   [`dig_nat::PeerId`]; the pool keys on the gossip [`PeerId`] (chia `Bytes32`) over the same 32
    ///   bytes — convert with `PeerId::from(*nat_peer_id.as_bytes())`.
    /// * `remote` is the RELAY endpoint the circuit arrived over, never a peer address; it is reported
    ///   as the session address and is never dialed (the slot is [`TraversalKind::Relayed`]).
    /// * `session` pairs the liveness observer with the notice that reaches the session's owner — see
    ///   [`ObservedSession::new`](crate::ObservedSession::new). The observer is the slot's only
    ///   departure signal, so one for a different (or already-dead) session makes the peer reap
    ///   immediately or never.
    /// * Teardown stays the CALLER's. Unlike the by-value path, dropping this slot does not close the
    ///   transport — deliberately, so the pool cannot hang up on a peer the caller is still serving,
    ///   and [`Self::disconnect`] likewise only stops ACCOUNTING for it.
    /// * **Supersede is different, and the pool now tells you (#71).** A later circuit for the same
    ///   `peer_id` displaces this slot newest-wins, and so does a discovery displacement
    ///   ([`Self::adopt_discovered_nat_connection`]). The displaced session is then obsolete —
    ///   uncounted, unreplaceable, and closable only by its owner — so the pool fires the notice
    ///   registered above rather than dropping an observer that closes nothing. Ownership is
    ///   unchanged: the pool runs the caller's callback and the caller ends the session.
    ///
    /// Admission, budgets, supersede semantics and errors are identical to
    /// [`Self::adopt_relayed_inbound`].
    pub async fn adopt_relayed_inbound_handle(
        &self,
        peer_id: PeerId,
        remote: std::net::SocketAddr,
        session: crate::ObservedSession,
        sink: Option<crate::NatBroadcastSink>,
    ) -> Result<PeerId, GossipError> {
        self.adopt_relayed_inbound_inner(
            peer_id,
            remote,
            dig_nat::TraversalKind::Relayed,
            super::state::NatTransport::Observed(session),
            sink,
        )
        .await
    }

    /// Attach (or replace) the broadcast sink of an already-registered `dig-nat` peer (**#69**).
    ///
    /// The dialer path ([`Self::adopt_nat_connection`]) is a published signature that cannot grow a
    /// parameter, and a caller may only begin serving a peer some time after adopting it. This is the
    /// seam for both. Until a peer has a sink, this node's broadcasts cannot reach it and it is
    /// reported unreachable rather than counted as delivered.
    ///
    /// # Errors
    ///
    /// [`GossipError::PeerNotConnected`] when `peer_id` holds no `dig-nat` slot — a WebSocket peer
    /// already receives broadcasts over its `DigLink` and needs no sink.
    pub fn set_nat_broadcast_sink(
        &self,
        peer_id: PeerId,
        sink: crate::NatBroadcastSink,
    ) -> Result<(), GossipError> {
        let mut peers = self
            .inner
            .peers
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?;
        match peers.get_mut(&peer_id) {
            Some(PeerSlot::Nat(slot)) => {
                slot.sink = Some(sink);
                Ok(())
            }
            _ => Err(GossipError::PeerNotConnected(peer_id)),
        }
    }

    /// The ONE admission path shared by both relayed-inbound entry points, so the two can never drift.
    async fn adopt_relayed_inbound_inner(
        &self,
        peer_id: PeerId,
        remote: std::net::SocketAddr,
        method: dig_nat::TraversalKind,
        transport: super::state::NatTransport,
        sink: Option<crate::NatBroadcastSink>,
    ) -> Result<PeerId, GossipError> {
        self.require_running()?;
        if !matches!(method, dig_nat::TraversalKind::Relayed) {
            return Err(GossipError::ConnectionFiltered(SafeText::from_untrusted(
                format!("adopt_relayed_inbound: not a relayed circuit ({method:?})"),
            )));
        }
        if peer_id == self.inner.config.peer_id {
            return Err(GossipError::SelfConnection);
        }
        if self
            .inner
            .is_peer_id_banned_at(peer_id, metric_unix_timestamp_secs())
            .await
        {
            return Err(GossipError::PeerBanned(peer_id));
        }

        // Both budgets and the insert are decided under ONE `peers`-lock hold, so no two concurrent
        // circuits can both pass the last free slot (the #1710 atomicity rule).
        let superseded = {
            let mut peers = self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;

            // A held slot exempts this adoption ONLY from a budget it already occupies — the narrower
            // #1762 shape `adopt_nat_connection` uses, not a blanket exemption. A blanket one is a
            // bypass: hold any slot for an identity and its circuit is charged nothing, so a relay
            // that can get a peer admitted by ANY other path can then convert it into a circuit and
            // fill `max_connections` entirely with peers of its own choosing — the eclipse the
            // reserved quarter exists to prevent.
            let held = peers.get(&peer_id);

            // A circuit NEVER supersedes a direct link. Doing so would demote a dialable peer to a
            // non-dialable one and drop its dial address, at the peer's own initiative — and the
            // direct link is strictly the better path anyway. The peer keeps the slot it has.
            if matches!(held, Some(slot) if !crate::service::state::is_relayed(slot)) {
                return Err(GossipError::ConnectionFiltered(SafeText::from_untrusted(
                    format!("#870: {peer_id} holds a direct slot; a circuit does not supersede it"),
                )));
            }

            // The map grows only for an identity holding no slot at all.
            if held.is_none() && peers.len() >= self.inner.config.max_connections {
                return Err(GossipError::MaxConnectionsReached(
                    self.inner.config.max_connections,
                ));
            }
            // The accepted-relayed budget is occupied only by a slot that is ITSELF an accepted
            // circuit. A relayed OUTBOUND held slot occupies the map but not this budget, so
            // converting it into an accepted circuit is net-new occupancy and is charged.
            let replaces_accepted_circuit = matches!(
                held,
                Some(slot) if crate::service::state::is_relayed(slot) && !slot.is_outbound()
            );
            if !replaces_accepted_circuit {
                let accepted_relayed = peers
                    .values()
                    .filter(|s| crate::service::state::is_relayed(s) && !s.is_outbound())
                    .count();
                let cap = crate::service::peer_pool::max_relayed_inbound(
                    self.inner.config.max_connections,
                );
                if accepted_relayed >= cap {
                    return Err(GossipError::ConnectionFiltered(SafeText::from_untrusted(
                        format!("#870: accepted relayed circuit cap reached ({cap})"),
                    )));
                }
            }

            peers.insert(
                peer_id,
                PeerSlot::Nat(super::state::NatSlot {
                    conn: transport,
                    sink,
                    remote,
                    is_outbound: false,
                    method,
                }),
            )
        };

        // Newest-wins supersede. The admission above refuses a circuit that would displace a
        // non-relayed slot, so anything displaced here is a `dig-nat` relayed slot, which owns no
        // keepalive task — the #1691 ghost-keepalive teardown `adopt_nat_connection` performs has
        // nothing to do on this path.
        //
        // What retiring does to the transport depends on which arm the displaced slot held, and the
        // two are not symmetric. An `Owned` slot drops the mux session's sole `cmd_tx` and the
        // transport closes with it (#1717). An `Observed` slot holds no transport to drop, so the
        // displaced session would otherwise survive with its owner un-notified — served by a caller
        // the pool no longer counts (#71). `retire_slot` fires that owner's notice instead.
        if let Some(stale) = superseded {
            super::state::retire_slot(stale).await;
        }

        // INT-001: a pool member participates in Plumtree like any connected peer (starts eager).
        if let Ok(mut pt) = self.inner.plumtree.lock() {
            pt.add_peer(peer_id);
        }
        self.inner
            .total_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner
            .pool
            .publish(crate::service::peer_pool::PoolEvent::PeerAdded {
                peer_id,
                addr: remote,
            });
        Ok(peer_id)
    }

    /// Snapshot every connected pool member with the facts a peer SELECTOR needs — identity,
    /// [`Via`](crate::nat::peer_record::Via), direction, and whether it may be dialed at all.
    ///
    /// Prefer this over [`Self::connected_pool_peers`] when the address is going to be USED: this view
    /// separates the endpoint a session runs over from an address the peer can be reached at, which
    /// are different things for every relayed peer.
    pub fn connected_pool_peers_detailed(
        &self,
    ) -> Vec<crate::service::peer_pool::ConnectedPoolPeer> {
        use crate::nat::peer_record::Via;
        use crate::service::peer_pool::ConnectedPoolPeer;
        let Ok(peers) = self.inner.peers.lock() else {
            return Vec::new();
        };
        peers
            .iter()
            .map(|(pid, slot)| {
                // Stub / live TLS peers are direct by construction: their remote IS the peer.
                let via = match slot {
                    super::state::PeerSlot::Nat(n) => n.via(),
                    _ => Via::Direct,
                };
                ConnectedPoolPeer {
                    peer_id: *pid,
                    via,
                    is_outbound: slot.is_outbound(),
                    dial_addr: slot.dial_addr(),
                    session_addr: slot.remote(),
                }
            })
            .collect()
    }

    /// The connected peers that may be DIALED, with the address to dial them at.
    ///
    /// Relayed peers are absent — in either direction, since a relayed link's endpoint is the relay's,
    /// not the peer's. This is the surface a peer-selection or reconnect path should read; reading
    /// [`Self::connected_pool_peers`] instead would hand it relay endpoints as if they were peers.
    pub fn dialable_pool_peers(&self) -> Vec<(PeerId, std::net::SocketAddr)> {
        self.connected_pool_peers_detailed()
            .into_iter()
            .filter_map(|p| p.dial_addr.map(|a| (p.peer_id, a)))
            .collect()
    }

    /// Snapshot the connected pool: `(peer_id, remote_addr, is_outbound)` for every connected peer
    /// (live TLS, adopted `dig-nat`, or stub). This is the "list connected peers" surface dig-node uses
    /// to choose a peer for an RPC or to plan a multi-source download.
    pub fn connected_pool_peers(&self) -> Vec<(PeerId, std::net::SocketAddr, bool)> {
        let Ok(peers) = self.inner.peers.lock() else {
            return Vec::new();
        };
        peers
            .iter()
            .map(|(pid, slot)| (*pid, slot.remote(), slot.is_outbound()))
            .collect()
    }

    /// **#924 B2** — snapshot each connected pool peer with HOW this node reaches it
    /// ([`Via`](crate::nat::peer_record::Via)): a peer over dig-nat's relayed transport
    /// ([`TraversalKind::Relayed`](dig_nat::TraversalKind)) reports [`Via::Relay`] — its gossip is
    /// routed through the relay's RLY-002 forwarder rather than a direct link — while every other
    /// peer reports [`Via::Direct`]. This is the "relay-transport peer-kind alongside the direct-TLS
    /// peer" surface: it lets dig-node see which connected peers ride the relay without exposing the
    /// transport internals. Non-nat slots (stub/live TLS) are direct by construction.
    pub fn connected_pool_peers_with_via(&self) -> Vec<(PeerId, crate::nat::peer_record::Via)> {
        use crate::nat::peer_record::Via;
        let Ok(peers) = self.inner.peers.lock() else {
            return Vec::new();
        };
        peers
            .iter()
            .map(|(pid, slot)| {
                let via = match slot {
                    super::state::PeerSlot::Nat(n) => n.via(),
                    _ => Via::Direct,
                };
                (*pid, via)
            })
            .collect()
    }

    /// Whether `peer_id` is currently a connected pool member (ready to communicate with).
    pub fn is_pool_peer(&self, peer_id: &PeerId) -> bool {
        self.inner
            .peers
            .lock()
            .map(|g| g.contains_key(peer_id))
            .unwrap_or(false)
    }

    /// Health snapshot of the pool — connected / in-flight / target / min / max / backed-off — for
    /// dig-node dashboards + "am I under-connected?" checks
    /// ([`PoolStats::is_under_connected`](crate::service::peer_pool::PoolStats::is_under_connected)).
    pub fn pool_stats(&self) -> crate::service::peer_pool::PoolStats {
        let connected = self.inner.peers.lock().map(|g| g.len()).unwrap_or(0);
        let in_flight = self.inner.pool.in_flight_count();
        let cfg = self
            .inner
            .config
            .peer_pool
            .clone()
            .unwrap_or_default()
            .normalized();
        let backed_off = self
            .inner
            .pool
            .backoff_snapshot()
            .values()
            .filter(|b| {
                b.is_dead(cfg.max_dial_failures) || !b.is_ready(metric_unix_timestamp_secs())
            })
            .count();
        crate::service::peer_pool::PoolStats {
            connected,
            in_flight,
            target: cfg.target_peers,
            min: cfg.min_peers,
            max: cfg.max_peers,
            backed_off,
        }
    }

    /// Subscribe to pool churn ([`PoolEvent`](crate::service::peer_pool::PoolEvent)) — peers added /
    /// removed. Returns a fresh [`broadcast::Receiver`]; each subscriber sees every event published
    /// after it subscribes. dig-node uses this to react to holders joining/leaving mid-download.
    ///
    /// # Errors
    /// [`GossipError::ServiceNotStarted`] if the pool event channel is not wired (service not started).
    pub fn subscribe_pool_events(
        &self,
    ) -> Result<broadcast::Receiver<crate::service::peer_pool::PoolEvent>, GossipError> {
        self.require_running()?;
        let g = self
            .inner
            .pool
            .events_tx
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?;
        let tx = g.as_ref().ok_or(GossipError::ServiceNotStarted)?;
        Ok(tx.subscribe())
    }

    /// Gather dialable pool candidates from the [`AddressManager`](crate::discovery::address_manager::AddressManager)
    /// (the known-address set), most-preferred first, up to `want` distinct addresses.
    ///
    /// This is the CONNECT phase's candidate source: it pulls addresses the discovery phase (relay
    /// introducer + node peer-exchange) folded into the address manager and turns them into
    /// [`PoolCandidate`](crate::service::peer_pool::PoolCandidate)s the pool planner ranks + dials.
    /// Self-dials and already-connected remotes are skipped here as a fast pre-filter (the planner
    /// dedups by identity too). `select_peer` biases toward tried-then-new, so preferred peers surface
    /// first.
    ///
    /// **IPv6-first + local∩candidate intersection (ecosystem hard rule, CLAUDE.md §5.2 /
    /// [`SPEC.md`](../../docs/resources/SPEC.md) §1.10):** the raw draw from `select_peer` is
    /// family-blind (weighted-random over the whole address book), so the result is passed through
    /// [`order_by_local_stack`](crate::util::ip_address::order_by_local_stack) — the canonical
    /// [`dig_ip`]-backed ordering — against the host's live [`dig_ip::LocalStack`]. Every IPv6
    /// candidate is dialed before any IPv4 candidate, and any candidate of a family THIS host cannot
    /// originate on is dropped (an IPv4-only host never emits an IPv6 SYN, and vice-versa).
    fn gather_pool_candidates(&self, want: usize) -> Vec<crate::service::peer_pool::PoolCandidate> {
        self.gather_pool_candidates_with_local(want, &dig_ip::LocalStack::cached())
    }

    /// [`Self::gather_pool_candidates`] with an explicit [`dig_ip::LocalStack`], so the local∩candidate
    /// intersection can be exercised deterministically (production passes [`dig_ip::LocalStack::cached`]).
    fn gather_pool_candidates_with_local(
        &self,
        want: usize,
        local: &dig_ip::LocalStack,
    ) -> Vec<crate::service::peer_pool::PoolCandidate> {
        use crate::service::peer_pool::PoolCandidate;
        let mut out: Vec<std::net::SocketAddr> = Vec::with_capacity(want);
        let mut seen: std::collections::HashSet<std::net::SocketAddr> =
            std::collections::HashSet::new();
        let connected_remotes: std::collections::HashSet<std::net::SocketAddr> = self
            .inner
            .peers
            .lock()
            .map(|g| g.values().map(|s| s.remote()).collect())
            .unwrap_or_default();

        // Draw a bounded number of candidates; `select_peer` is randomized, so cap the attempts to
        // avoid spinning when the address book is small.
        let max_attempts = want.saturating_mul(8).max(16);
        for i in 0..max_attempts {
            if out.len() >= want {
                break;
            }
            // Alternate tried/new so a fresh node (only new addresses) still yields candidates.
            let ext = match self.inner.address_manager.select_peer(i % 2 == 1) {
                Some(e) => e,
                None => break,
            };
            let host = ext.peer_info.host.clone();
            let port = ext.peer_info.port;
            // Parse the host as an `IpAddr` first, THEN combine with the port -- do not
            // `format!("{host}:{port}")` and parse that as a `SocketAddr` string: an unbracketed
            // IPv6 literal (`"2001:db8::1:9444"`) is not a valid `SocketAddr` string (IPv6 requires
            // `[host]:port` bracketing) and silently fails to parse, which previously dropped every
            // IPv6 candidate here regardless of the IPv6-first ordering below.
            let Ok(ip) = host.parse::<std::net::IpAddr>() else {
                continue;
            };
            let addr = std::net::SocketAddr::new(ip, port);
            if seen.contains(&addr) || connected_remotes.contains(&addr) {
                continue;
            }
            if self.inner.dial_targets_local_listen(addr) {
                continue;
            }
            seen.insert(addr);
            out.push(addr);
        }
        // #1517 defect 1: when discovery resolved this address's `peer_id` (relay introducer /
        // dig-nat reservation), pin it into the candidate so the auto-dialer authenticates the SPKI
        // against the real id — never the all-zeros pin. An address-only candidate (peer-exchange)
        // keeps `peer_id: None`.
        crate::util::ip_address::order_by_local_stack(local, &out)
            .into_iter()
            .map(|addr| match self.inner.discovered_peer_id(&addr) {
                Some(pid) => PoolCandidate::with_id(pid, addr),
                None => PoolCandidate::from_addr(addr),
            })
            .collect()
    }
    /// #1517 defect-2 test hook: the [`dig_nat::NatRuntime`] the pool auto-dial composes its full
    /// ladder from ([`Self::pool_dial_runtime`]). Exposed so a unit test can prove the relay circuit
    /// is ACTUALLY wired — a runtime built with a relay reservation attached composes the Relayed
    /// tier, whereas the default relay-less runtime composes it away — WITHOUT a live relay. Never a
    /// public contract.
    #[doc(hidden)]
    pub fn __pool_dial_runtime_for_tests(&self) -> dig_nat::NatRuntime {
        self.pool_dial_runtime()
    }

    /// IPv6-first / intersection test hook: run [`Self::gather_pool_candidates`] against an EXPLICIT
    /// local stack (`has_v6`, `has_v4`), so a test can assert the local∩candidate intersection
    /// (drop-a-family-the-host-lacks) deterministically regardless of the CI runner's real stack.
    #[doc(hidden)]
    pub fn __pool_gathered_candidates_with_stack_for_tests(
        &self,
        want: usize,
        has_v6: bool,
        has_v4: bool,
    ) -> Vec<crate::service::peer_pool::PoolCandidate> {
        self.gather_pool_candidates_with_local(
            want,
            &dig_ip::LocalStack::from_flags(has_v6, has_v4),
        )
    }

    /// IPv6-first test hook: seed the address manager's **new** table directly (bypasses the
    /// `connect_to` + `RequestPeers` round trip) so tests can populate a mixed IPv4/IPv6 address
    /// book and observe the `__pool_gathered_candidates_with_stack_for_tests` hook ordering deterministically.
    #[doc(hidden)]
    pub fn __seed_address_book_for_tests(&self, peers: &[(String, u16)]) {
        // Pin the address manager's bucket-hash key to a FIXED value FIRST so the new-table bucket
        // placement is deterministic. The production key is random (`randbits(256)`), which can make
        // two seeded addresses collide into one bucket slot on unlucky runs — the later address then
        // evicts the earlier and `size()` comes back short, the root cause of the dig-gossip #9
        // flake. A fixed key makes seeding collision-free + reproducible (verified for the test
        // fixtures). Safe here because the seed is the manager's first mutation (empty book).
        const FIXED_TEST_BUCKET_KEY: [u8; 32] = [0x11; 32];
        self.inner
            .address_manager
            .__set_fixed_bucket_key_for_tests(FIXED_TEST_BUCKET_KEY);
        let src = PeerInfo {
            host: "127.0.0.1".to_string(),
            port: 0,
        };
        let now = metric_unix_timestamp_secs();
        let batch: Vec<TimestampedPeerInfo> = peers
            .iter()
            .map(|(host, port)| TimestampedPeerInfo::new(host.clone(), *port, now))
            .collect();
        self.inner.address_manager.add_to_new_table(&batch, &src, 0);
    }

    /// Run ONE pool maintenance pass now (DISCOVER-fold is done by the loop / caller; this does the
    /// REPLENISH + record-outcome step): plan dials toward target from the address book and execute
    /// them via `dig-nat`, adopting each successful connection into the pool. Returns peers added.
    ///
    /// Exposed so dig-node (and tests) can drive a pass on demand; the periodic loop calls it every
    /// [`PeerPoolConfig::maintenance_interval_secs`](crate::types::config::PeerPoolConfig). A no-op
    /// (returns 0) when the pool is not configured. Bounded — each dial is bounded by `dig-nat`'s
    /// per-method timeout.
    pub async fn run_pool_maintenance_once(&self) -> usize {
        let Some(cfg) = self.inner.config.peer_pool.clone() else {
            return 0;
        };
        let cfg = cfg.normalized();
        // Health first: evict slots keepalive already removed is implicit (they're gone from the map);
        // prune expired bans so a cooled-off peer becomes dialable again.
        self.inner
            .prune_expired_dig_bans(metric_unix_timestamp_secs())
            .await;

        // Count relay-reachable peers (#870) toward "connected": a peer this node can already talk to
        // through dig-nat's relay reservation is connected, so it shrinks the free-slot dial budget
        // like a direct peer — without it the pool would keep dialing for slots it has already filled
        // via the relay. Two accounting rules apply (review findings on #870):
        //  1. Count the UNION, not the sum — a peer reachable BOTH directly and via the relay counts
        //     once, so `relay_reachable_excluding_connected` drops peers already in the direct pool.
        //  2. A direct-dial FLOOR (see `free_slot_budget_with_direct_floor`) keeps direct dialing alive
        //     regardless of how many peers a relay advertises, so a compromised relay can't suppress it.
        let direct_connected = self.peer_count().await;
        let relay_reachable = self.inner.relay_reachable_excluding_connected();
        let connected = direct_connected + relay_reachable;
        let connected_keys = self.inner.connected_pool_keys();
        let now = metric_unix_timestamp_secs();
        let budget = crate::service::peer_pool::free_slot_budget_with_direct_floor(
            direct_connected,
            relay_reachable,
            self.inner.pool.in_flight_count(),
            &cfg,
        );
        // Gather a few more candidates than the budget so backed-off/duplicate ones can be skipped.
        let candidates = self.gather_pool_candidates(budget.saturating_mul(2).max(budget));

        let dialer = HandleDialer {
            handle: self.clone(),
        };
        crate::service::peer_pool::run_maintenance_pass(
            &self.inner.pool,
            &cfg,
            connected,
            direct_connected,
            &connected_keys,
            &candidates,
            now,
            &dialer,
        )
        .await
    }

    /// **POOL-*** — spawn the periodic pool maintenance loop (DISCOVER → REPLENISH → HEALTH every
    /// `maintenance_interval_secs`), returning its [`tokio::task::JoinHandle`]. Called by
    /// [`GossipService::start`](super::gossip_service::GossipService::start) when the pool is
    /// configured. The loop exits when the lifecycle leaves `RUNNING` (i.e. `stop()`), so the task is
    /// self-terminating in addition to being aborted at teardown.
    /// **#1703 item 2** — spawn the departed-peer reaper loop.
    ///
    /// Wakes every [`GossipConfig::reaper_interval_secs`](crate::types::config::GossipConfig::reaper_interval_secs)
    /// (or [`REAPER_INTERVAL_SECS`](crate::constants::REAPER_INTERVAL_SECS)) and evicts peer slots whose
    /// transport is provably closed ([`ServiceState::reap_departed_peers`](crate::service::state::ServiceState::reap_departed_peers)).
    /// The first (immediate) tick is skipped so the sweep never fires the instant the service starts.
    /// The loop exits once the lifecycle leaves `RUNNING`; `stop()` also aborts + joins it.
    pub(crate) fn spawn_reaper(&self) -> tokio::task::JoinHandle<()> {
        let handle = self.clone();
        let interval_secs = handle
            .inner
            .config
            .reaper_interval_secs
            .unwrap_or(crate::constants::REAPER_INTERVAL_SECS)
            .max(1);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // Consume the immediate first tick.
            loop {
                ticker.tick().await;
                if !handle.inner.is_running() {
                    break;
                }
                handle.inner.reap_departed_peers();
            }
        })
    }

    pub(crate) fn spawn_pool_maintenance(&self) -> tokio::task::JoinHandle<()> {
        let handle = self.clone();
        let interval_secs = handle
            .inner
            .config
            .peer_pool
            .as_ref()
            .map(|c| c.maintenance_interval_secs.max(1))
            .unwrap_or(crate::constants::DEFAULT_POOL_MAINTENANCE_INTERVAL_SECS);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                if !handle.inner.is_running() {
                    break;
                }
                // DISCOVER: fold the relay introducer's peer list into the address book (soft — a
                // relay outage never blocks the pass). Node peer-exchange (§4b) already folds via the
                // connect path; this adds the §4a introducer source continuously.
                #[cfg(feature = "relay")]
                handle.pool_discover_from_relay().await;
                // REPLENISH + HEALTH.
                let _added = handle.run_pool_maintenance_once().await;
            }
        })
    }

    /// DISCOVER (§4a, #870): fold the peers `dig-nat`'s **live persistent reservation** has discovered
    /// into the address book, and let the relay-only ones count as connected-via-relay.
    ///
    /// `dig-nat` OWNS the relay transport: its `run_relay_connection` loop holds ONE long-lived
    /// WebSocket that both keeps this node reachable AND — since dig-nat 0.2.0 — discovers peers over
    /// the SAME socket (RLY-005 `GetPeers` + pushed `PeerConnected`/`PeerDisconnected`), exposing them
    /// via [`RelayStatus::known_peers`](dig_nat::relay::RelayStatus::known_peers). We READ that set
    /// here instead of opening an ephemeral relay socket per pass. The old ephemeral
    /// open-register-getpeers-close path (removed) reconnected every maintenance interval, so two
    /// nodes' sub-second registration windows never overlapped and neither ever appeared in the
    /// other's `get_peers` — the proven root cause of `connected_peers` staying `0`. Holding ONE
    /// reservation live (in dig-nat) makes the relay advertise each node to the other's discovery.
    ///
    /// Soft — does nothing until the node attaches its reservation status via
    /// [`Self::attach_relay_status`], and an empty/relay-down set is a no-op (never stalls the pass).
    #[cfg(feature = "relay")]
    async fn pool_discover_from_relay(&self) {
        // Snapshot the discovered set (cloned — we hold no lock across the fold below).
        let known = {
            let Ok(guard) = self.inner.relay_status.lock() else {
                return;
            };
            match guard.as_ref() {
                Some(status) => status.known_peers(),
                None => return,
            }
        };
        self.fold_relay_known_peers(&known);
    }

    /// Fold `dig-nat`'s discovered relay peers (#870) into dig-gossip's address book + relay-reachable
    /// set. The pool-maintenance loop calls this each pass with the attached reservation's
    /// [`RelayStatus::known_peers`](dig_nat::relay::RelayStatus::known_peers); it is also the pure,
    /// synchronous consumption seam a caller (or a test) can drive directly with synthetic
    /// [`RelayPeerInfo`](dig_nat::wire::RelayPeerInfo)s — dig-nat's discovery internals are private, so
    /// this is the supported way to inject a known-peer set without a live relay socket.
    ///
    /// Relay-discovered peers are identity-only ([`Via::Relay`](crate::nat::peer_record::Via::Relay),
    /// no dialable address), so the address-book merge places none of them by-address — instead they
    /// SURVIVE as relay-reachable (counted via
    /// [`ServiceState::relay_reachable_count`](crate::service::state::ServiceState)) rather than being
    /// DROPPED. Any relay record that ever carries a dialable candidate is still placed through the
    /// SAME shared, capped merge node peer-exchange uses (audit #179 MEDIUM finding 4): the untrusted
    /// relay source can never add more peers, cumulatively across passes, than the combined
    /// per-request/global budget allows.
    #[cfg(feature = "relay")]
    pub fn fold_relay_known_peers(&self, known: &[dig_nat::wire::RelayPeerInfo]) {
        // Refresh the relay-reachable set (a wholesale replace, so dropped peers disappear) — this is
        // what makes two relay-introduced nodes each count the other as connected.
        let self_hex = self.local_peer_id().ok().map(|id| id.to_string());
        self.inner.set_relay_reachable(
            known.iter().map(|p| p.peer_id.as_str()),
            self_hex.as_deref(),
        );

        if known.is_empty() {
            return;
        }
        let records: Vec<_> = known
            .iter()
            .map(crate::nat::peer_record::PeerRecord::from_nat_relay_peer_info)
            .collect();
        // #1517 defect 1: the address book stores only `host:port`, so remember each dialable
        // candidate's discovered `peer_id` here — the pool auto-dialer reads it back to PIN the mTLS
        // SPKI instead of dialing the all-zeros pin the verifier (correctly) rejects.
        for rec in &records {
            if rec.peer_id.is_empty() {
                continue;
            }
            let Some(pid) = crate::service::state::peer_id_from_hex(&rec.peer_id) else {
                continue;
            };
            for a in &rec.addresses {
                if !a.kind.is_dialable() {
                    continue;
                }
                if let Ok(ip) = a.host.parse::<std::net::IpAddr>() {
                    self.inner
                        .record_discovered_peer_id(std::net::SocketAddr::new(ip, a.port), pid);
                }
            }
        }
        let bound = self
            .inner
            .listen_bound_addr
            .lock()
            .ok()
            .and_then(|g| *g)
            .unwrap_or(self.inner.config.listen_addr);
        crate::nat::merge_records_into_address_manager_capped(
            &self.inner.address_manager,
            &records,
            &bound.ip().to_string(),
            bound.port(),
            &self.inner.total_peers_received,
        );
    }

    /// **RLY-* / #870** — whether `dig-nat`'s persistent relay reservation is currently held (a live
    /// WebSocket to the relay). `false` when no reservation is attached or the relay is down.
    fn relay_connected(&self) -> bool {
        self.inner
            .relay_status
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.is_connected()))
            .unwrap_or(false)
    }

    /// **RLY-* / #870** — attach `dig-nat`'s live persistent-reservation status so the pool consumes
    /// its discovered peer set (see [`Self::pool_discover_from_relay`]).
    ///
    /// The node calls this once at startup with the `Arc<RelayStatus>` it hands to
    /// [`dig_nat::relay::run_relay_connection`], so dig-gossip and the reservation loop share ONE
    /// status. Idempotent — a later call replaces the handle (e.g. a re-attached reservation).
    #[cfg(feature = "relay")]
    pub fn attach_relay_status(&self, status: std::sync::Arc<dig_nat::relay::RelayStatus>) {
        if let Ok(mut guard) = self.inner.relay_status.lock() {
            *guard = Some(status);
        }
    }

    /// Insert an ungated [`PeerSlot::Stub`] for a peer address (no real TLS/WSS handshake).
    ///
    /// Test-only: gated behind `cfg(any(test, feature = "test-util"))` so it is never compiled into
    /// the production library. Its sole caller is [`Self::__connect_stub_peer_with_direction`].
    #[cfg(any(test, feature = "test-util"))]
    async fn connect_stub_inner(
        &self,
        addr: std::net::SocketAddr,
        node_type: NodeType,
        is_outbound: bool,
    ) -> Result<PeerId, GossipError> {
        self.require_running()?;
        if self.inner.dial_targets_local_listen(addr) {
            return Err(GossipError::SelfConnection);
        }
        let pid = peer_id_for_addr(addr);
        if self
            .inner
            .is_peer_id_banned_at(pid, metric_unix_timestamp_secs())
            .await
        {
            return Err(GossipError::PeerBanned(pid));
        }
        let mut peers = self
            .inner
            .peers
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?;
        if peers.contains_key(&pid) {
            return Err(GossipError::DuplicateConnection(pid));
        }
        if peers.len() >= self.inner.config.max_connections {
            return Err(GossipError::MaxConnectionsReached(
                self.inner.config.max_connections,
            ));
        }
        peers.insert(
            pid,
            PeerSlot::Stub(StubPeer {
                remote: addr,
                node_type,
                is_outbound,
            }),
        );
        drop(peers);
        self.inner
            .total_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(pid)
    }

    /// Test hook (#870 finding 1): count of relay-reachable peers NOT already directly connected — the
    /// deduped contribution that actually feeds the dial budget (a peer reachable both ways counts once).
    #[doc(hidden)]
    pub fn __relay_reachable_excluding_connected_for_tests(&self) -> usize {
        self.inner.relay_reachable_excluding_connected()
    }

    /// Test hook (#870 finding 2): the free-slot dial budget the pool would use right now — the same
    /// `direct_connected` + de-duplicated relay + direct-floor math [`Self::run_pool_maintenance_once`]
    /// applies. Returns `0` when no pool is configured. Lets tests assert the direct-dial floor without
    /// standing up real dial targets.
    #[doc(hidden)]
    pub async fn __pool_free_slot_budget_for_tests(&self) -> usize {
        let Some(cfg) = self.inner.config.peer_pool.clone() else {
            return 0;
        };
        let cfg = cfg.normalized();
        let direct_connected = self.peer_count().await;
        let relay_reachable = self.inner.relay_reachable_excluding_connected();
        crate::service::peer_pool::free_slot_budget_with_direct_floor(
            direct_connected,
            relay_reachable,
            self.inner.pool.in_flight_count(),
            &cfg,
        )
    }

    /// Test hook: model an **inbound** stub (different [`NodeType`] / direction) without real TCP.
    ///
    /// Gated behind `cfg(any(test, feature = "test-util"))` so it is excluded from the production
    /// library; integration tests enable the `test-util` feature (see `Cargo.toml`).
    #[cfg(any(test, feature = "test-util"))]
    #[doc(hidden)]
    pub async fn __connect_stub_peer_with_direction(
        &self,
        addr: std::net::SocketAddr,
        node_type: NodeType,
        is_outbound: bool,
    ) -> Result<PeerId, GossipError> {
        self.connect_stub_inner(addr, node_type, is_outbound).await
    }

    /// How many stub rows match [`Self::get_connections`] filters (until CON-001 returns real [`PeerConnection`]s).
    #[doc(hidden)]
    pub async fn __stub_filter_count_for_tests(
        &self,
        node_type: Option<NodeType>,
        outbound_only: bool,
    ) -> usize {
        let peers = match self.inner.peers.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        peers
            .values()
            .filter(|p| {
                node_type.is_none_or(|nt| nt == p.node_type())
                    && (!outbound_only || p.is_outbound())
            })
            .count()
    }

    pub async fn disconnect(&self, peer_id: &PeerId) -> Result<(), GossipError> {
        self.require_running()?;
        let removed = self
            .inner
            .peers
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .remove(peer_id);
        let was_present = removed.is_some();
        if let Some(PeerSlot::Live(l)) = removed {
            l.keepalive_task.abort();
            let _ = l.peer.close().await;
        }
        // POOL-*: publish churn so dig-node's pool consumers (and the maintenance loop) learn the peer
        // left and the pool can replenish toward target.
        if was_present {
            // #2176: log the teardown at the same level/shape as the "pool connection established"
            // line so a pooled connection ending is never silent (the invisible churn's root cause).
            tracing::info!(
                peer_id = %peer_id,
                reason = ?crate::service::peer_pool::PoolRemovalReason::Disconnected,
                "pool connection closed",
            );
            self.inner
                .pool
                .publish(crate::service::peer_pool::PoolEvent::PeerRemoved {
                    peer_id: *peer_id,
                    reason: crate::service::peer_pool::PoolRemovalReason::Disconnected,
                });
        }
        // INT-001: Remove peer from Plumtree state (PLT-006 tree self-healing), UNLESS a concurrent
        // reconnect re-inserted this id in the map→plumtree gap (#1792) — see
        // `ServiceState::remove_from_plumtree_unless_reconnected`.
        self.inner.remove_from_plumtree_unless_reconnected(peer_id);

        // INT-006/INT-007: no diversity-budget bookkeeping here (#1703). Outbound diversity occupancy
        // is derived from the live peer map, so removing the slot above already frees its /16 + AS for
        // a future dial. (The previous unconditional `remove_outbound` on a refcount-free side-set
        // could delete a /16 still occupied by ANOTHER outbound peer — an under-count that re-admitted
        // a second outbound into an occupied group; deriving from the map cannot under-count.)
        Ok(())
    }

    /// Force-disconnect a peer and record a **timed DIG ban** (**CON-007**).
    ///
    /// This mirrors Chia [`dig_peer_protocol::ClientState::ban`] on the peer's remote IP (when known),
    /// inserts a [`super::state::DigBanEntry`] so [`Self::connect_to`] / inbound accept reject
    /// the [`PeerId`] until [`super::state::ServiceState::prune_expired_dig_bans`] fires.
    pub async fn ban_peer(
        &self,
        peer_id: &PeerId,
        _reason: PenaltyReason,
    ) -> Result<(), GossipError> {
        self.require_running()?;
        let now = metric_unix_timestamp_secs();
        self.inner
            .enforce_timed_ban_and_disconnect(*peer_id, now, None)
            .await;
        Ok(())
    }

    /// Increment [`PenaltyReason`] weights, mirror into [`PeerReputation`] for live slots, and
    /// auto-ban per **CON-007** when cumulative points reach [`PENALTY_BAN_THRESHOLD`].
    pub async fn penalize_peer(
        &self,
        peer_id: &PeerId,
        reason: PenaltyReason,
    ) -> Result<(), GossipError> {
        self.require_running()?;
        let now = metric_unix_timestamp_secs();
        self.inner.prune_expired_dig_bans(now).await;

        let already_banned = self
            .inner
            .banned
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .contains_key(peer_id);

        let should_enforce = {
            let peers = self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            match peers.get(peer_id) {
                Some(PeerSlot::Live(live)) => {
                    let (crossed, pts) = {
                        let mut r = live
                            .reputation
                            .lock()
                            .map_err(|_| GossipError::ChannelClosed)?;
                        let c = r.apply_penalty(reason, now);
                        (c, r.penalty_points)
                    };
                    drop(peers);
                    if let Ok(mut p) = self.inner.penalties.lock() {
                        p.insert(*peer_id, pts);
                    }
                    crossed
                }
                // Stub + POOL-* `dig-nat` members carry no per-slot reputation struct, so penalties
                // accumulate on the service-wide `penalties` map exactly like an unknown peer id.
                Some(PeerSlot::Stub(_)) | Some(PeerSlot::Nat(_)) => {
                    drop(peers);
                    let mut p = self
                        .inner
                        .penalties
                        .lock()
                        .map_err(|_| GossipError::ChannelClosed)?;
                    let e = p.entry(*peer_id).or_insert(0);
                    *e = e.saturating_add(reason.penalty_points());
                    *e >= PENALTY_BAN_THRESHOLD
                }
                None => {
                    drop(peers);
                    let mut p = self
                        .inner
                        .penalties
                        .lock()
                        .map_err(|_| GossipError::ChannelClosed)?;
                    let e = p.entry(*peer_id).or_insert(0);
                    *e = e.saturating_add(reason.penalty_points());
                    *e >= PENALTY_BAN_THRESHOLD
                }
            }
        };

        if should_enforce && !already_banned {
            self.inner
                .enforce_timed_ban_and_disconnect(*peer_id, now, None)
                .await;
        }
        Ok(())
    }

    /// **CON-007 test hook:** [`dig_peer_protocol::ClientState::is_banned`] for `ip` on the service's
    /// shadow [`super::state::ServiceState::chia_ip_bans`] table.
    #[doc(hidden)]
    pub async fn __con007_chia_client_is_ip_banned_for_tests(&self, ip: std::net::IpAddr) -> bool {
        self.inner.chia_ip_bans.lock().await.is_banned(&ip)
    }

    /// **CON-007 test hook:** advance the ban clock to `now_unix_secs` and expire rows whose
    /// [`super::state::DigBanEntry::until`] timestamp has passed (also calls [`ClientState::unban`]).
    #[doc(hidden)]
    pub async fn __con007_prune_expired_bans_for_tests(&self, now_unix_secs: u64) {
        self.inner.prune_expired_dig_bans(now_unix_secs).await;
    }

    pub async fn discover_from_introducer(&self) -> Result<Vec<TimestampedPeerInfo>, GossipError> {
        self.require_running()?;
        let intro = self
            .inner
            .config
            .introducer
            .as_ref()
            .ok_or(GossipError::IntroducerNotConfigured)?;
        let endpoint = intro.endpoint.trim();
        if endpoint.is_empty() {
            return Err(GossipError::InvalidConfig(
                "introducer.endpoint is empty; set a wss:// URL to query an introducer (DSC-004)"
                    .into(),
            ));
        }
        let cert = load_local_certificate_for_introducer(
            &self.inner.config.cert_path,
            &self.inner.config.key_path,
        )?;
        let timeout = Duration::from_secs(intro.request_timeout_secs.max(1));
        IntroducerClient::query_peers(
            endpoint,
            &cert,
            self.inner.config.network_id,
            self.inner.config.peer_options,
            timeout,
            &self.inner.config.software_version,
        )
        .await
    }

    /// Register [`GossipConfig::listen_addr`](crate::types::config::GossipConfig::listen_addr) with the configured introducer (**DSC-005**).
    ///
    /// Uses [`IntroducerClient::register_with_introducer`] — same TLS + [`Handshake`] rules as
    /// [`Self::discover_from_introducer`]. An **empty** trimmed [`IntroducerConfig::endpoint`](crate::types::config::IntroducerConfig::endpoint)
    /// fails with [`GossipError::InvalidConfig`] without opening a socket (mirrors DSC-004 ergonomics).
    ///
    /// **Policy:** `RegisterAck.success == false` is still `Ok` — the introducer explicitly declined;
    /// only transport/protocol failures become [`GossipError`].
    pub async fn register_with_introducer(&self) -> Result<RegisterAck, GossipError> {
        self.require_running()?;
        let intro = self
            .inner
            .config
            .introducer
            .as_ref()
            .ok_or(GossipError::IntroducerNotConfigured)?;
        let endpoint = intro.endpoint.trim();
        if endpoint.is_empty() {
            return Err(GossipError::InvalidConfig(
                "introducer.endpoint is empty; set a wss:// URL to register with an introducer (DSC-005)"
                    .into(),
            ));
        }
        let cert = load_local_certificate_for_introducer(
            &self.inner.config.cert_path,
            &self.inner.config.key_path,
        )?;
        let timeout = Duration::from_secs(intro.request_timeout_secs.max(1));
        let registration = PeerRegistration {
            ip: self.inner.config.listen_addr.ip().to_string(),
            port: self.inner.config.listen_addr.port(),
            node_type: NodeType::FullNode,
        };
        IntroducerClient::register_with_introducer(
            endpoint,
            &cert,
            self.inner.config.network_id,
            self.inner.config.peer_options,
            timeout,
            &registration,
            &self.inner.config.software_version,
        )
        .await
    }

    pub async fn request_peers_from(&self, peer_id: &PeerId) -> Result<RespondPeers, GossipError> {
        self.request(*peer_id, RequestPeers::new()).await
    }

    /// Snapshot gossip observability (API-008 / SPEC §3.4).
    ///
    /// **CON-006:** `messages_*` / `bytes_*` are **`sum(live per-slot [`PeerConnectionWireMetrics`]) +
    /// stub/synthetic atomics`** on [`ServiceState`] — live TLS paths meter exact serialized
    /// [`DigMessage`] sizes; stub [`PeerSlot::Stub`] rows and [`__inject_inbound_for_tests`] still
    /// use the lock-free counters (API-008 pre-CON-006 behaviour preserved for tests).
    pub async fn stats(&self) -> GossipStats {
        let (live_ms, live_mr, live_bw, live_br) = sum_live_peer_wire_metrics(&self.inner);
        let messages_sent = live_ms
            + self
                .inner
                .messages_sent
                .load(std::sync::atomic::Ordering::Relaxed);
        let messages_received = live_mr
            + self
                .inner
                .messages_received
                .load(std::sync::atomic::Ordering::Relaxed);
        let bytes_sent = live_bw
            + self
                .inner
                .bytes_sent
                .load(std::sync::atomic::Ordering::Relaxed);
        let bytes_received = live_br
            + self
                .inner
                .bytes_received
                .load(std::sync::atomic::Ordering::Relaxed);
        let total_connections = self
            .inner
            .total_connections
            .load(std::sync::atomic::Ordering::Relaxed) as usize;

        let (
            connected_peers,
            inbound_connections,
            outbound_connections,
            relay_transport_peers,
            seen_messages,
        ) = {
            let peers = match self.inner.peers.lock() {
                Ok(g) => g,
                Err(_) => {
                    return GossipStats {
                        total_connections,
                        messages_sent,
                        messages_received,
                        bytes_sent,
                        bytes_received,
                        ..Default::default()
                    };
                }
            };
            let mut inb = 0usize;
            let mut out = 0usize;
            let mut relay_transport = 0usize;
            for p in peers.values() {
                if p.is_outbound() {
                    out += 1;
                } else {
                    inb += 1;
                }
                // #924 B2: a peer reached over dig-nat's relayed transport still counts as connected,
                // and is ALSO tallied separately so a NAT-blocked last-resort peer is visible as such.
                if let super::state::PeerSlot::Nat(n) = p {
                    if matches!(n.via(), crate::nat::peer_record::Via::Relay) {
                        relay_transport += 1;
                    }
                }
            }
            let connected = peers.len();
            drop(peers);
            let seen = self
                .inner
                .seen_messages
                .lock()
                .map(|c| c.len())
                .unwrap_or(0);
            (connected, inb, out, relay_transport, seen)
        };

        GossipStats {
            total_connections,
            connected_peers,
            inbound_connections,
            outbound_connections,
            messages_sent,
            messages_received,
            bytes_sent,
            bytes_received,
            known_addresses: self.inner.address_manager.size(),
            seen_messages,
            // #870: reflect dig-nat's live persistent reservation. `relay_connected` is whether a
            // reservation socket is currently held; `relay_peer_count` is how many peers it has
            // discovered (reachable via relay). Both read `0`/`false` when no reservation is attached.
            relay_connected: self.relay_connected(),
            relay_peer_count: self.inner.relay_reachable_count(),
            relay_transport_peer_count: relay_transport_peers,
        }
    }

    /// `Some(RelayStats)` only when [`GossipConfig::relay`](crate::types::config::GossipConfig::relay) is set;
    /// values are stubs (`Default`) until RLY-* implements the relay client.
    pub async fn relay_stats(&self) -> Option<RelayStats> {
        if self.inner.config.relay.is_none() {
            None
        } else {
            Some(RelayStats::default())
        }
    }

    /// CON-001 test hook: last [`AddressManager::add_to_new_table`](crate::discovery::address_manager::AddressManager::add_to_new_table) batch.
    #[doc(hidden)]
    pub fn __con001_last_address_batch_for_tests(
        &self,
    ) -> Option<(Vec<TimestampedPeerInfo>, PeerInfo)> {
        self.inner
            .address_manager
            .__last_new_table_batch_for_tests()
    }

    /// CON-002: resolved listen socket after [`crate::service::gossip_service::GossipService::start`] (port `0` → OS assignment).
    #[doc(hidden)]
    pub fn __listen_bound_addr_for_tests(&self) -> Option<std::net::SocketAddr> {
        self.inner.listen_bound_addr.lock().ok().and_then(|g| *g)
    }

    /// CON-002: live peer metadata — `(remote_addr, is_outbound)` for TLS-derived [`PeerId`] keys.
    #[doc(hidden)]
    pub fn __con002_live_peer_meta_for_tests(
        &self,
        peer_id: PeerId,
    ) -> Option<(std::net::SocketAddr, bool)> {
        let peers = self.inner.peers.lock().ok()?;
        let slot = peers.get(&peer_id)?;
        Some((slot.remote(), slot.is_outbound()))
    }

    /// CON-003 / **CON-008**: `(remote_protocol_version, remote_software_version_sanitized)` after
    /// [`crate::connection::handshake::validate_remote_handshake`] (second tuple element is Cc/Cf-sanitized).
    #[doc(hidden)]
    pub fn __con003_peer_versions_for_tests(&self, peer_id: PeerId) -> Option<(String, String)> {
        let peers = self.inner.peers.lock().ok()?;
        match peers.get(&peer_id)? {
            PeerSlot::Live(l) => Some((
                l.remote_protocol_version.clone(),
                l.remote_software_version_sanitized.clone(),
            )),
            PeerSlot::Stub(_) | PeerSlot::Nat(_) => None,
        }
    }

    /// CON-004: clone of per-connection [`PeerReputation`] (RTT window + penalties on that struct).
    #[doc(hidden)]
    pub fn __con004_peer_reputation_for_tests(&self, peer_id: PeerId) -> Option<PeerReputation> {
        let peers = self.inner.peers.lock().ok()?;
        match peers.get(&peer_id)? {
            PeerSlot::Live(l) => l.reputation.lock().ok().map(|g| g.clone()),
            PeerSlot::Stub(_) | PeerSlot::Nat(_) => None,
        }
    }

    /// CON-004 / CON-007: accumulated penalty points (includes keepalive disconnect path).
    #[doc(hidden)]
    pub fn __con004_penalty_points_for_tests(&self, peer_id: PeerId) -> Option<u32> {
        self.inner.penalties.lock().ok()?.get(&peer_id).copied()
    }

    /// #1691: the current live slot's monotonic session [`generation`](super::state::LiveSlot::generation).
    #[doc(hidden)]
    pub fn __peer_generation_for_tests(&self, peer_id: PeerId) -> Option<u64> {
        let peers = self.inner.peers.lock().ok()?;
        match peers.get(&peer_id)? {
            PeerSlot::Live(l) => Some(l.generation),
            PeerSlot::Stub(_) | PeerSlot::Nat(_) => None,
        }
    }

    /// #1691: clone the shared [`ServiceState`] `Arc` so a test can drive the per-session teardown
    /// guards (`apply_inbound_rate_limit_violation`) directly with a chosen generation.
    #[doc(hidden)]
    pub fn __state_arc_for_tests(&self) -> std::sync::Arc<super::state::ServiceState> {
        self.inner.clone()
    }

    /// CON-002: snapshot of [`PeerId`] keys in the live/stub map (order not stable — use for single-peer asserts).
    #[doc(hidden)]
    pub fn __peer_ids_for_tests(&self) -> Vec<PeerId> {
        self.inner
            .peers
            .lock()
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default()
    }

    /// #1703 item 2: run one departed-peer reaper sweep synchronously and return the number of slots
    /// reaped. Lets tests exercise the reap logic deterministically without waiting on the timer loop.
    #[doc(hidden)]
    pub fn __reap_departed_peers_for_tests(&self) -> usize {
        self.inner.reap_departed_peers()
    }

    /// #1703 item 2: whether `peer_id` is currently a member of Plumtree state (eager OR lazy). Lets a
    /// test assert the reaper mirrors `disconnect()`'s `plumtree.remove_peer` cleanup.
    #[doc(hidden)]
    pub fn __plumtree_contains_for_tests(&self, peer_id: &PeerId) -> bool {
        self.inner
            .plumtree
            .lock()
            .map(|pt| pt.is_eager(peer_id) || pt.is_lazy(peer_id))
            .unwrap_or(false)
    }

    /// #1792 test hook: register `peer_id` in Plumtree state (starts eager, PLT-001) without a real
    /// transport, so a test can drive the reconnect-guard helper deterministically.
    #[doc(hidden)]
    pub fn __plumtree_add_peer_for_tests(&self, peer_id: PeerId) {
        if let Ok(mut pt) = self.inner.plumtree.lock() {
            pt.add_peer(peer_id);
        }
    }

    /// #1792 test hook: invoke the shared reconnect-guard cleanup
    /// ([`ServiceState::remove_from_plumtree_unless_reconnected`](super::state::ServiceState::remove_from_plumtree_unless_reconnected))
    /// exactly as both departure paths (`disconnect` + the reaper) do, so a test can prove the guard
    /// SKIPS the Plumtree removal when the id is once again present in the peer map.
    #[doc(hidden)]
    pub fn __remove_from_plumtree_unless_reconnected_for_tests(&self, peer_id: &PeerId) {
        self.inner.remove_from_plumtree_unless_reconnected(peer_id);
    }

    /// Test helper: push a synthetic inbound event into the broadcast hub.
    #[doc(hidden)]
    pub fn __inject_inbound_for_tests(
        &self,
        sender: PeerId,
        message: DigMessage,
    ) -> Result<(), GossipError> {
        self.require_running()?;
        let g = self
            .inner
            .inbound_tx
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?;
        let tx = g.as_ref().ok_or(GossipError::ServiceNotStarted)?;
        let wl = message_wire_len(&message);
        let _ = tx.send((sender, message));
        self.inner
            .messages_received
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner
            .bytes_received
            .fetch_add(wl, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

/// Production [`Dialer`](crate::service::peer_pool::Dialer): dial a candidate over `dig-nat`'s
/// NAT-traversal ladder and adopt the verified connection into the pool.
///
/// The pool maintenance loop drives this; on success the peer is already a pool member (adopted via
/// [`GossipHandle::adopt_nat_connection`]) and its `peer_id` is returned so the loop records the
/// success + churn. A dead/unreachable candidate returns an `Err` string (used only for backoff/logs)
/// — never panics or hangs (bounded by `dig-nat`'s per-method timeout).
struct HandleDialer {
    handle: GossipHandle,
}

impl crate::service::peer_pool::Dialer for HandleDialer {
    async fn dial(
        &self,
        candidate: &crate::service::peer_pool::PoolCandidate,
    ) -> Result<PeerId, String> {
        // #1517 defect 1: the mTLS SPKI pin MUST be the discovered `peer_id`. An address-only
        // candidate (node peer-exchange never carries an id) cannot be pinned — the dig-nat verifier
        // would reject ANY pin — so it is skipped here rather than dialed with the all-zeros pin the
        // verifier (correctly) rejected (`expected 0000… got <real>`, the #1062 Leg B failure).
        let target_peer_id = candidate.peer_id.ok_or_else(|| {
            "candidate has no discovered peer_id to pin the mTLS SPKI; skipping".to_string()
        })?;
        let per_method = Duration::from_secs(5);
        // #1517 defect 2: dial the FULL ladder (Direct … Relayed) over a runtime carrying the relay
        // dialer, so a peer unreachable by every direct tier is still reached over the relay circuit
        // rather than the strategy stopping at Direct. `candidate.addr` seeds the direct/mapping tiers;
        // a relay-only candidate (no address) still reaches the relay tier.
        let conn = self
            .handle
            .connect_via_nat_full_ladder(target_peer_id, candidate.addr, per_method)
            .await
            .map_err(|e| e.to_string())?;
        self.handle
            .adopt_nat_connection(conn)
            .await
            .map_err(|e| e.to_string())
    }
}

/// The traversal ladder the pool auto-dialer enables (#1517 defect 2): the FULL ladder —
/// Direct → UPnP → NAT-PMP → PCP → hole-punch → **Relayed** — so a peer that fails every direct /
/// port-mapping / hole-punch tier is still reached over the SPKI-pinned relay circuit. The dig-nat
/// strategy ranks these direct-first, relay-last regardless of order, and silently omits any tier
/// whose runtime inputs are absent. Previously the pool dialer enabled only
/// [`Direct`](dig_nat::TraversalKind::Direct), so after Direct failed the strategy stopped and the
/// relay transport was never exercised (the #1062 Leg B `falling through kind=Direct` dead-end).
pub fn pool_auto_dial_traversal_methods() -> Vec<dig_nat::TraversalKind> {
    use dig_nat::TraversalKind::{Direct, HolePunch, NatPmp, Pcp, Relayed, Upnp};
    vec![Direct, Upnp, NatPmp, Pcp, HolePunch, Relayed]
}

fn encode_message<T: Streamable + ChiaProtocolMessage>(
    body: &T,
) -> Result<DigMessage, GossipError> {
    let to_gossip_error = |e| GossipError::from(dig_peer_protocol::ClientError::Streamable(e));
    // A Chia opcode's wire byte is the single-byte `Streamable` encoding of its
    // `ProtocolMessageTypes` discriminant -- the same derivation `DigLink::send` uses, so a
    // frame built here is indistinguishable from one the link builds itself.
    let opcode = *T::msg_type()
        .to_bytes()
        .map_err(to_gossip_error)?
        .first()
        .ok_or_else(|| {
            GossipError::IoError("protocol message type encoded to zero bytes".into())
        })?;
    Ok(DigMessage::new(
        opcode,
        None,
        body.to_bytes().map_err(to_gossip_error)?.into(),
    ))
}

fn empty_respond_peers() -> Result<RespondPeers, GossipError> {
    Ok(RespondPeers::new(vec![]))
}

/// Extract the DER of the first `CERTIFICATE` PEM block from a [`ChiaCertificate::cert_pem`] string.
///
/// Used by [`GossipHandle::local_peer_id`] to lift the node's own SPKI (via
/// [`spki_der_from_leaf_cert_der`](crate::connection::outbound::spki_der_from_leaf_cert_der)) so its
/// `peer_id` is derived the SAME way a remote derives it from the presented cert.
fn first_cert_der(cert_pem: &str) -> Result<Vec<u8>, GossipError> {
    x509_parser::pem::Pem::iter_from_buffer(cert_pem.as_bytes())
        .flatten()
        .find(|p| p.label == "CERTIFICATE")
        .map(|p| p.contents)
        .ok_or_else(|| {
            GossipError::InvalidConfig("node certificate PEM has no CERTIFICATE block".to_string())
        })
}
