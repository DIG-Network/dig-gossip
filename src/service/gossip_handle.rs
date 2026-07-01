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
//!   [`dig_protocol::Peer`] handles inside [`super::state::PeerSlot::Live`] while these RPCs
//!   stay empty until a snapshot API lands. In the meantime,
//!   [`__stub_filter_count_for_tests`](GossipHandle::__stub_filter_count_for_tests) gives tests a
//!   way to verify filter semantics.
//!
//! # Chia equivalence
//!
//! This module loosely maps to the `FullNode` peer-handling surface in Chia's Python code
//! (`full_node.py`, `server.py`). The key difference is that Chia's `Server` object is not
//! `Clone` — callers must borrow it. Our `Arc` wrapper avoids lifetime gymnastics in async code.

use dig_protocol::Peer;
use dig_protocol::{
    ChiaProtocolMessage, Message, NodeType, ProtocolMessageTypes, RequestPeers, RespondPeers,
    TimestampedPeerInfo,
};

use crate::discovery::introducer_client::{
    load_local_certificate_for_introducer, IntroducerClient, PeerRegistration,
};
use crate::discovery::introducer_register_wire::RegisterAck;
use dig_protocol::Streamable;
use std::any::TypeId;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;

use crate::constants::PENALTY_BAN_THRESHOLD;
use crate::error::GossipError;
use crate::types::peer::{
    message_wire_len, metric_unix_timestamp_secs, peer_id_from_tls_spki_der, PeerConnection,
    PeerConnectionWireMetrics, PeerId, PeerInfo,
};
use crate::types::reputation::PeerReputation;
use crate::types::reputation::PenaltyReason;
use crate::types::stats::{GossipStats, RelayStats};

use super::state::{
    apply_inbound_rate_limit_violation, peer_id_for_addr, record_live_peer_inbound_bytes,
    record_live_peer_outbound_bytes, sum_live_peer_wire_metrics, LiveSlot, PeerSlot, ServiceState,
    StubPeer,
};

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
    pub fn inbound_receiver(&self) -> Result<broadcast::Receiver<(PeerId, Message)>, GossipError> {
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

    /// Broadcast a wire [`Message`] to every connected peer (optionally excluding one).
    ///
    /// Returns the number of peers that **would** receive the message. With zero connected
    /// peers the return value is `Ok(0)` — this is explicitly **not** an error (API-002
    /// implementation notes: "broadcast with zero connected peers should return `Ok(0)`").
    ///
    /// # Wire behaviour (CON-001+ / CON-006)
    ///
    /// **Live** peers receive [`Peer::send_protocol_message`](dig_protocol::Peer::send_protocol_message)
    /// with a cloned [`Message`]; each successful send increments that slot’s CON-006 counters by the
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
        message: Message,
        exclude: Option<PeerId>,
    ) -> Result<usize, GossipError> {
        self.require_running()?;
        let wire_len = message_wire_len(&message).map_err(GossipError::from)?;

        // -- INT-001: Plumtree dedup via seen set --
        // SPEC §8.1 step 2: "if seen_set.contains(hash) → return 0"
        let msg_hash =
            crate::gossip::seen_set::SeenSet::compute_hash(message.msg_type as u8, &message.data);
        {
            let mut seen = self
                .inner
                .seen_messages
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            if seen.contains(&msg_hash) {
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
            cache.insert(msg_hash, message.msg_type as u8, message.data.to_vec());
        }

        // -- INT-001: Route through Plumtree eager/lazy sets (SPEC §8.1) --
        // Eager peers get full message. Lazy peers get hash-only (LazyAnnounce).
        // Stubs (test-only) always get counted as delivered.
        let (stub_deliveries, eager_jobs, lazy_pids): (
            usize,
            Vec<(Peer, PeerId, u64)>,
            Vec<PeerId>,
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
            let mut lazy = Vec::new();

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
                            // Lazy: hash-only announcement (SPEC §8.1 step 6)
                            lazy.push(*pid);
                        }
                    }
                    // POOL-*: a `dig-nat`-dialed pool member has a multiplexed transport but its
                    // gossip message loop over that mux lands with the dig-node integration phase, so
                    // `broadcast` (the WebSocket-`Peer` fan-out) does not push to it yet. It still
                    // COUNTS as a connected peer everywhere else (peer_count / stats / pool).
                    PeerSlot::Nat(_) => {}
                }
            }
            (stub_n, eager, lazy)
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
            peer.send_protocol_message(message.clone())
                .await
                .map_err(GossipError::from)?;
            record_live_peer_outbound_bytes(&self.inner, *pid, *wl);
        }

        // INT-001: Lazy push — for now, lazy peers don't get anything
        // (LazyAnnounce wire sending will be added when the full Plumtree
        // message dispatch is integrated). The count still reflects delivery.
        // TODO(INT-001): Send LazyAnnounce { hash, msg_type } to lazy peers.
        let _lazy_count = lazy_pids.len();

        Ok(stub_deliveries + eager_jobs.len() + lazy_pids.len())
    }

    /// Type-safe broadcast: serialize `body` via [`Streamable`] then delegate to [`Self::broadcast`].
    ///
    /// This is the recommended entry point for application-level broadcasts — callers work with
    /// concrete Chia protocol types (e.g. `NewPeak`, `NewTransaction`) rather than raw
    /// [`Message`] bytes.
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
    /// [`dig_protocol::Peer::send`] WebSocket channel. For **stub** peers (pre-CON-001
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
        let wire_len = message_wire_len(&msg).map_err(GossipError::from)?;

        // Ban check before touching the peer map — avoids leaking message data to a banned peer.
        if self
            .inner
            .is_peer_id_banned_at(peer_id, metric_unix_timestamp_secs())
            .await
        {
            return Err(GossipError::PeerBanned(peer_id));
        }

        // Clone the live `Peer` handle (Arc-backed, cheap) while the lock is held,
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
                // Stub + POOL-* `dig-nat` members have no WebSocket `Peer`; the typed WS
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
                // Stub + POOL-* `dig-nat` members have no WebSocket `Peer`; the typed WS
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
                .map_err(|e| GossipError::from(dig_protocol::ClientError::Streamable(e)))?;
            return T::from_bytes(&bytes)
                .map_err(|e| GossipError::from(dig_protocol::ClientError::Streamable(e)));
        }

        // Unimplemented request/response pairs for stub peers — live peers handled above.
        Err(GossipError::RequestTimeout)
    }

    /// Always empty until CON-001 builds [`PeerConnection`] from live peers (see module docs).
    pub async fn connected_peers(&self) -> Vec<PeerConnection> {
        let _ = self.require_running();
        Vec::new()
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
    /// [`dig_protocol::create_native_tls_connector`] / rustls equivalent, Chia [`Handshake`], then
    /// merges [`RespondPeers::peer_list`] via [`crate::discovery::address_manager::AddressManager::add_to_new_table`].
    ///
    /// **Tests without a WSS peer:** use [`Self::__connect_stub_peer_with_direction`] (deterministic
    /// [`peer_id_for_addr`] keys) so API-002 matrices stay offline.
    pub async fn connect_to(&self, addr: std::net::SocketAddr) -> Result<PeerId, GossipError> {
        self.require_running()?;
        if self.inner.dial_targets_local_listen(addr) {
            return Err(GossipError::SelfConnection);
        }
        {
            let peers = self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            for (k, slot) in peers.iter() {
                if slot.remote() == addr {
                    return Err(GossipError::DuplicateConnection(*k));
                }
            }
            if peers.len() >= self.inner.config.max_connections {
                return Err(GossipError::MaxConnectionsReached(
                    self.inner.config.max_connections,
                ));
            }
        }

        // INT-006: /16 subnet group filter — one outbound per /16.
        if let Ok(sf) = self.inner.subnet_filter.lock() {
            if !sf.is_allowed(&addr.ip()) {
                return Err(GossipError::ConnectionFiltered(format!(
                    "INT-006: /16 subnet group already has an outbound connection for {}",
                    addr.ip()
                )));
            }
        }

        // INT-007: AS diversity filter — one outbound per AS.
        if let Ok(af) = self.inner.as_filter.lock() {
            if !af.is_allowed(&addr.ip()) {
                return Err(GossipError::ConnectionFiltered(format!(
                    "INT-007: AS already has an outbound connection for {}",
                    addr.ip()
                )));
            }
        }

        let connector = crate::connection::outbound::tls_connector_for_cert(&self.inner.tls)
            .map_err(GossipError::from)?;
        let network_id =
            crate::connection::outbound::network_id_handshake_string(self.inner.config.network_id);
        let opts = self.inner.config.peer_options;

        let out =
            crate::connection::outbound::connect_outbound_peer(network_id, connector, addr, opts)
                .await
                .map_err(GossipError::from)?;

        let peer_id = peer_id_from_tls_spki_der(&out.remote_spki_der);
        let is_banned = self
            .inner
            .is_peer_id_banned_at(peer_id, metric_unix_timestamp_secs())
            .await;
        if is_banned {
            let _ = out.peer.close().await;
            return Err(GossipError::PeerBanned(peer_id));
        }
        let duplicate = self
            .inner
            .peers
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .contains_key(&peer_id);
        if duplicate {
            let _ = out.peer.close().await;
            return Err(GossipError::DuplicateConnection(peer_id));
        }

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

        // CON-005: one inbound [`RateLimiter`] per live slot (insert **before** the forwarder).
        let inbound_limiter = Arc::new(Mutex::new(
            crate::connection::inbound_limits::new_inbound_rate_limiter(
                self.inner.config.peer_options.rate_limit_factor,
            ),
        ));

        let meta = StubPeer {
            remote: addr,
            node_type: out.their_handshake.node_type,
            is_outbound: true,
        };
        let peer = out.peer;
        let peer_for_keepalive = peer.clone();
        let lim = Arc::clone(&inbound_limiter);
        let mut peers = self
            .inner
            .peers
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?;
        let opened_at = metric_unix_timestamp_secs();
        peers.insert(
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
            }),
        );
        drop(peers);

        // INT-001: Register peer in Plumtree state (starts as eager per SPEC §8.1).
        if let Ok(mut pt) = self.inner.plumtree.lock() {
            pt.add_peer(peer_id);
        }

        // INT-006: Record outbound /16 group.
        if let Ok(mut sf) = self.inner.subnet_filter.lock() {
            sf.add_outbound(&addr.ip());
        }

        // INT-007: Record outbound AS.
        if let Ok(mut af) = self.inner.as_filter.lock() {
            af.add_outbound(&addr.ip());
        }

        // Answer inbound `RequestPeers` (keepalive / discovery) with correlated `RespondPeers`.
        // Upstream `Peer` routes `id: Some` messages through a local `RequestMap`; remote request
        // ids are forwarded on `inbound_rx` (see `vendor/chia-sdk-client` patch) and must be
        // replied to with [`Peer::send_protocol_message`].
        let peer_inbound_rpc = peer_for_keepalive.clone();
        if let Ok(g) = self.inner.inbound_tx.lock() {
            if let Some(tx) = g.as_ref() {
                let tx = tx.clone();
                let mut inbound_rx = out.inbound_rx;
                let pid_task = peer_id;
                let peer_rpc = peer_inbound_rpc;
                let state_fwd = self.inner.clone();
                let lim_fwd = lim;
                tokio::spawn(async move {
                    while let Some(msg) = inbound_rx.recv().await {
                        let allowed = lim_fwd
                            .lock()
                            .map(|mut g| g.handle_message(&msg))
                            .unwrap_or(true);
                        if !allowed {
                            apply_inbound_rate_limit_violation(&state_fwd, pid_task);
                            continue;
                        }
                        if let Ok(wl_in) = message_wire_len(&msg) {
                            record_live_peer_inbound_bytes(&state_fwd, pid_task, wl_in);
                        }
                        if msg.msg_type == ProtocolMessageTypes::RequestPeers {
                            if let Ok(body) = RespondPeers::new(vec![]).to_bytes() {
                                let reply = Message {
                                    msg_type: ProtocolMessageTypes::RespondPeers,
                                    id: msg.id,
                                    data: body.into(),
                                };
                                let wl_out = message_wire_len(&reply).ok();
                                let _ = peer_rpc.send_protocol_message(reply).await;
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

        crate::connection::keepalive::spawn_keepalive_task(
            self.inner.clone(),
            peer_id,
            peer_for_keepalive,
        );

        self.inner
            .total_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    /// Bridge this node's TLS material to a [`dig-nat`](dig_nat) identity for the unified transport.
    ///
    /// The returned [`NatLocalIdentity`](crate::nat::NatLocalIdentity) carries the DER cert + key and
    /// the derived `peer_id` (== [`Self::local_peer_id`]); it is what
    /// [`Self::connect_via_nat`] presents as the mTLS client certificate. Gated on the running
    /// lifecycle.
    pub fn nat_identity(&self) -> Result<crate::nat::NatLocalIdentity, GossipError> {
        self.require_running()?;
        crate::nat::chia_cert_to_nat_identity(&self.inner.tls).ok_or_else(|| {
            GossipError::InvalidConfig(
                "node TLS certificate could not be bridged to a dig-nat identity".to_string(),
            )
        })
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
            .map_err(|e| GossipError::NatError(e.to_string()))
    }

    // ------------------------------------------------------------------
    // Connected peer POOL (POOL-*) — the maintained set of ready, CONNECTED
    // peers dig-node's peer-RPC + downloads consume. See `crate::service::peer_pool`.
    // ------------------------------------------------------------------

    /// Adopt a `dig-nat`-dialed [`NatPeerConnection`](crate::nat::NatPeerConnection) into the connected
    /// peer pool, so it counts as a connected peer (`peer_count` / `stats` / dedup / churn) and its
    /// multiplexed transport is retained for dig-node to open gossip channels + range streams on.
    ///
    /// Returns `Ok(peer_id)` on adoption. Refuses (and drops the connection) if the peer is banned, is
    /// already in the pool ([`GossipError::DuplicateConnection`]), or the pool is full
    /// ([`GossipError::MaxConnectionsReached`] against [`GossipConfig::max_connections`]). Emits a
    /// [`PoolEvent::PeerAdded`](crate::service::peer_pool::PoolEvent) on success.
    ///
    /// This is the single place a `dig-nat` connection becomes a pool member; the pool maintenance loop
    /// and a manual dial both go through it, so the dedup + cap + churn rules hold uniformly.
    pub async fn adopt_nat_connection(
        &self,
        conn: crate::nat::NatPeerConnection,
    ) -> Result<PeerId, GossipError> {
        self.require_running()?;
        let peer_id = conn.peer_id();
        let remote = conn.remote_addr();

        if self
            .inner
            .is_peer_id_banned_at(peer_id, metric_unix_timestamp_secs())
            .await
        {
            return Err(GossipError::PeerBanned(peer_id));
        }

        {
            let mut peers = self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            if peers.contains_key(&peer_id) {
                return Err(GossipError::DuplicateConnection(peer_id));
            }
            if peers.len() >= self.inner.config.max_connections {
                return Err(GossipError::MaxConnectionsReached(
                    self.inner.config.max_connections,
                ));
            }
            peers.insert(
                peer_id,
                PeerSlot::Nat(super::state::NatSlot {
                    conn,
                    remote,
                    is_outbound: true,
                }),
            );
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
    fn gather_pool_candidates(&self, want: usize) -> Vec<crate::service::peer_pool::PoolCandidate> {
        use crate::service::peer_pool::PoolCandidate;
        let mut out = Vec::with_capacity(want);
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
            let Ok(addr) = format!("{host}:{port}").parse::<std::net::SocketAddr>() else {
                continue;
            };
            if seen.contains(&addr) || connected_remotes.contains(&addr) {
                continue;
            }
            if self.inner.dial_targets_local_listen(addr) {
                continue;
            }
            seen.insert(addr);
            out.push(PoolCandidate::from_addr(addr));
        }
        out
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

        let connected = self.peer_count().await;
        let connected_keys = self.inner.connected_pool_keys();
        let now = metric_unix_timestamp_secs();
        let budget = crate::service::peer_pool::free_slot_budget(
            connected,
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

    /// DISCOVER (§4a): query the relay introducer for peers and fold the dialable ones into the
    /// address book. Soft-fails (logs, no error) so a relay outage never stalls the pool.
    #[cfg(feature = "relay")]
    async fn pool_discover_from_relay(&self) {
        let Some(relay) = self.inner.config.relay.as_ref() else {
            return;
        };
        if !relay.enabled || relay.endpoint.trim().is_empty() {
            return;
        }
        let self_hex = match self.local_peer_id() {
            Ok(id) => id.to_string(),
            Err(_) => return,
        };
        let network_id =
            crate::connection::outbound::network_id_handshake_string(self.inner.config.network_id);
        let cfg = crate::nat::UnifiedDiscoveryConfig {
            relay_endpoint: relay.endpoint.clone(),
            self_peer_id_hex: self_hex,
            network_id,
            timeout: Duration::from_secs(relay.connection_timeout_secs.max(1)),
        };
        let records = crate::nat::unified_discover(&cfg).await;
        if !records.is_empty() {
            let bound = self
                .inner
                .listen_bound_addr
                .lock()
                .ok()
                .and_then(|g| *g)
                .unwrap_or(self.inner.config.listen_addr);
            crate::nat::merge_records_into_address_manager(
                &self.inner.address_manager,
                &records,
                &bound.ip().to_string(),
                bound.port(),
            );
        }
    }

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

    /// Test hook: model an **inbound** stub (different [`NodeType`] / direction) without real TCP.
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
        let remote_ip = removed.as_ref().map(|s| s.remote().ip());
        let was_present = removed.is_some();
        if let Some(PeerSlot::Live(l)) = removed {
            let _ = l.peer.close().await;
        }
        // POOL-*: publish churn so dig-node's pool consumers (and the maintenance loop) learn the peer
        // left and the pool can replenish toward target.
        if was_present {
            self.inner
                .pool
                .publish(crate::service::peer_pool::PoolEvent::PeerRemoved {
                    peer_id: *peer_id,
                    reason: crate::service::peer_pool::PoolRemovalReason::Disconnected,
                });
        }
        // INT-001: Remove peer from Plumtree state (PLT-006 tree self-healing).
        if let Ok(mut pt) = self.inner.plumtree.lock() {
            pt.remove_peer(peer_id);
        }

        // INT-006: Remove outbound /16 group on disconnect.
        if let Some(ip) = remote_ip {
            if let Ok(mut sf) = self.inner.subnet_filter.lock() {
                sf.remove_outbound(&ip);
            }
            // INT-007: Remove outbound AS on disconnect.
            if let Ok(mut af) = self.inner.as_filter.lock() {
                af.remove_outbound(&ip);
            }
        }
        Ok(())
    }

    /// Force-disconnect a peer and record a **timed DIG ban** (**CON-007**).
    ///
    /// This mirrors Chia [`dig_protocol::ClientState::ban`] on the peer's remote IP (when known),
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
            .enforce_timed_ban_and_disconnect(*peer_id, now)
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
                .enforce_timed_ban_and_disconnect(*peer_id, now)
                .await;
        }
        Ok(())
    }

    /// **CON-007 test hook:** [`dig_protocol::ClientState::is_banned`] for `ip` on the service's
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
    /// [`Message`] sizes; stub [`PeerSlot::Stub`] rows and [`__inject_inbound_for_tests`] still
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

        let (connected_peers, inbound_connections, outbound_connections, seen_messages) = {
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
            for p in peers.values() {
                if p.is_outbound() {
                    out += 1;
                } else {
                    inb += 1;
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
            (connected, inb, out, seen)
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
            // Stub until RLY-*: mirror [`RelayStats::connected`] (always false with `RelayStats::default()`).
            relay_connected: false,
            relay_peer_count: 0,
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

    /// CON-002: snapshot of [`PeerId`] keys in the live/stub map (order not stable — use for single-peer asserts).
    #[doc(hidden)]
    pub fn __peer_ids_for_tests(&self) -> Vec<PeerId> {
        self.inner
            .peers
            .lock()
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Test helper: push a synthetic inbound event into the broadcast hub.
    #[doc(hidden)]
    pub fn __inject_inbound_for_tests(
        &self,
        sender: PeerId,
        message: Message,
    ) -> Result<(), GossipError> {
        self.require_running()?;
        let g = self
            .inner
            .inbound_tx
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?;
        let tx = g.as_ref().ok_or(GossipError::ServiceNotStarted)?;
        let wl = message_wire_len(&message).unwrap_or(0);
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
        // A candidate must carry an address for the pool's direct/mapping dial; a relay-only candidate
        // (peer_id, no address) is reached over the relay tier — reserved for the dig-node phase that
        // holds the relay coordinator context, so the pool loop skips it here.
        let addr = candidate
            .addr
            .ok_or_else(|| "relay-only candidate; no direct address to dial".to_string())?;
        // Address-only candidate: we do not yet know its peer_id, so use a placeholder target. The
        // mTLS handshake still authenticates whoever answers; a future refinement can pin the id
        // learned from discovery. When the id IS known (relay introducer path) we pin it.
        let target_peer_id = candidate.peer_id.unwrap_or_else(|| PeerId::from([0u8; 32]));
        let per_method = Duration::from_secs(5);
        let conn = self
            .handle
            .connect_via_nat(
                target_peer_id,
                Some(addr),
                &[dig_nat::TraversalKind::Direct],
                per_method,
            )
            .await
            .map_err(|e| e.to_string())?;
        self.handle
            .adopt_nat_connection(conn)
            .await
            .map_err(|e| e.to_string())
    }
}

fn encode_message<T: Streamable + ChiaProtocolMessage>(body: &T) -> Result<Message, GossipError> {
    Ok(Message {
        msg_type: T::msg_type(),
        id: None,
        data: body
            .to_bytes()
            .map_err(|e| GossipError::from(dig_protocol::ClientError::Streamable(e)))?
            .into(),
    })
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
