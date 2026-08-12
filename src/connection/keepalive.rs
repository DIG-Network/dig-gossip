//! CON-004 — per-connection keepalive and RTT sampling.
//!
//! SPEC §5.1 step 7 — "Spawn per-connection message loop task" includes the keepalive
//! responsibility. This module implements that loop: periodic probes, timeout-based
//! teardown, and RTT sampling for latency-aware scoring.
//!
//! Maintains connection liveness by sending periodic probes to every connected peer.
//! When a peer fails to respond within the configured timeout, the connection is torn
//! down and a reputation penalty is applied. Successful probes also feed round-trip
//! time (RTT) samples into [`crate::types::reputation::PeerReputation`] for latency-aware
//! peer scoring (PRF-001 / PRF-002).
//!
//! ## Chia equivalents
//!
//! SPEC §1.6 #7 — "Timestamp update on message": outbound peer timestamps updated in the
//! address manager on message receipt (`node_discovery.py:139-154`). DIG’s keepalive loop
//! mirrors this dual purpose (liveness + address book refresh).
//!
//! In Chia’s Python networking stack the keepalive responsibility is split:
//!
//! - **`ws_connection.py`** — the `WsConnection` class manages a per-peer WebSocket
//!   connection and relies on the transport library’s WS Ping/Pong control frames for
//!   liveness detection.  There is no application-level Ping message in Chia’s
//!   `ProtocolMessageTypes`.
//! - **`node_discovery.py` lines 139-154** — `PeerManager._periodically_peer_exchange`
//!   performs periodic `RequestPeers`/`RespondPeers` exchanges with all connected peers,
//!   both to refresh the address book *and* to verify that the peer is still responsive.
//!   DIG’s keepalive loop mirrors this dual purpose.
//!
//! ## Normative trace
//!
//! - [`CON-004.md`](../../../docs/requirements/domains/connection/specs/CON-004.md)
//! - [`NORMATIVE.md`](../../../docs/requirements/domains/connection/NORMATIVE.md) §CON-004
//! - [`SPEC.md`](../../../docs/resources/SPEC.md) §2.13 (`PING_INTERVAL_SECS`, `PEER_TIMEOUT_SECS`)
//!
//! ## Why not `chia_protocol::Ping` / `Pong`?
//!
//! The published [`chia_protocol`](https://docs.rs/chia-protocol/0.26.0/chia_protocol/) **0.26** wire
//! enum [`ProtocolMessageTypes`](chia_protocol::ProtocolMessageTypes) does **not** define separate
//! application-level Ping/Pong message types — Chia’s networking docs describe **WebSocket** library
//! heartbeats for transport liveness. Upstream [`dig_peer_protocol::DigLink`](dig_peer_protocol::DigLink)’s
//! inbound loop discards raw WS control frames (`Ping`/`Pong`) before they become [`DigMessage`](chia_protocol::DigMessage)s.
//!
//! **DIG policy:** we treat a successful **`RequestPeers` → `RespondPeers`** round-trip as the
//! observable keepalive probe (same Chia types already used right after outbound connect in
//! [`crate::service::gossip_handle::GossipHandle::connect_to`]). RTT is measured from send to
//! response, matching CON-004’s “Ping send time to Pong receive time” *semantics* on the only
//! request/response pair we control without forked protocol IDs.
//!
//! Using `RequestPeers` instead of a raw WebSocket Ping has a second benefit: each
//! successful response also delivers fresh peer addresses, so the address manager stays
//! populated without a separate peer-exchange timer.
//!
//! ## Timing overrides
//!
//! [`crate::types::config::GossipConfig::keepalive_ping_interval_secs`] and
//! [`crate::types::config::GossipConfig::keepalive_peer_timeout_secs`] default to `None` so production
//! uses [`crate::constants::PING_INTERVAL_SECS`] / [`crate::constants::PEER_TIMEOUT_SECS`]. Integration
//! tests set small values so `con_004_tests` finishes quickly.
//!
//! ## The probe is UNCORRELATED (#2767)
//!
//! The probe is sent with [`DigLink::send`] (`id: None`) and the reply is observed on the
//! service-wide application inbound broadcast — **not** on a correlation waiter.
//!
//! A correlated probe collides with the peer's identically-allocated id. Both peers allocate
//! correlation ids from a counter that starts at zero, and both keepalive loops start at handshake
//! on the same interval, so two probes can carry the same id. Each link matches inbound frames on
//! correlation id *before* forwarding, so each side's waiter receives the **peer's `RequestPeers`**
//! instead of a `RespondPeers`. The peer's request never reaches the forwarder, its auto-reply
//! never fires, neither side records a success, and both tear the link down at the staleness check
//! — logging a timeout that names the wrong cause. An `id: None` frame skips the id-match arm
//! entirely, so the lockstep cannot exist.
//!
//! This fails **loose**: a peer that is alive but silent on the broadcast is kept. That is the
//! correct direction for a probe whose only action is to disconnect.
//!
//! ## Per-probe deadline
//!
//! A dead TCP peer would otherwise leave the reply wait pending forever. Each probe's wait is
//! wrapped in [`tokio::time::timeout`] for `keepalive_peer_timeout_secs` (or [`PEER_TIMEOUT_SECS`])
//! so we surface failure and disconnect (same path as transport errors) without blocking the
//! keepalive task indefinitely.
//!
//! ## Design decisions
//!
//! - **One task per connection:** spawned via [`spawn_keepalive_task`] at connection setup
//!   (both outbound in [`crate::service::gossip_handle::GossipHandle::connect_to`] and
//!   inbound in [`crate::connection::listener::negotiate_inbound_over_ws`]). This keeps
//!   the timer state local and avoids a central scheduler for N peers.
//! - **Disconnect penalty flows to global map:** on timeout, both the per-peer
//!   [`crate::types::reputation::PeerReputation`] *and* the shared `ServiceState::penalties`
//!   map are updated so that CON-007 ban logic sees the accumulated cost even after the
//!   [`crate::service::state::LiveSlot`] is removed.

#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::time::Duration;

use chia_protocol::RequestPeers;
use dig_peer_protocol::{DigLink, DigMessage};

use crate::connection::chia_opcodes;
// SPEC §2.13 — PING_INTERVAL_SECS (default 30) and PEER_TIMEOUT_SECS (default 90)
// are DIG-specific constants not present in Chia crates.
use crate::constants::{PEER_TIMEOUT_SECS, PING_INTERVAL_SECS};
use crate::service::state::{PeerSlot, ServiceState};
use crate::types::peer::PeerId;
use crate::types::reputation::PenaltyReason;

/// Return the current wall-clock time as Unix seconds.
///
/// Used only for penalty timestamps (`ban_until`), **not** for RTT measurement
/// (which uses [`std::time::Instant`] for monotonicity). Falls back to `0` on
/// clock error — acceptable because a zero timestamp merely makes the ban
/// expire immediately, which is the safe direction.
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Send one liveness probe to `peer`, **uncorrelated** (#2767).
///
/// [`DigLink::send`] frames the body with `id: None`. That is the load-bearing property, not the
/// choice of `RequestPeers`: both peers allocate correlation ids from a counter that starts at
/// zero, and both keepalive loops start at handshake on a shared interval, so two *correlated*
/// probes can carry the same id. Each link matches inbound frames on correlation id before
/// forwarding, so each side's waiter would receive the peer's **request** — the peer's request
/// would never reach the forwarder, its auto-reply would never fire, and both sides would tear the
/// link down. An `id: None` frame skips the id-match arm entirely.
async fn send_probe(peer: &DigLink) -> Result<(), dig_peer_protocol::LinkError> {
    peer.send(RequestPeers::new()).await
}

/// Subscribe to the service-wide inbound broadcast, or `None` while it is uninitialised.
///
/// The sender exists only between [`GossipService::start`](crate::service::GossipService::start)
/// and `stop`, so `None` means "the service is not fully up" — never "the peer is unreachable".
/// Callers MUST treat `None` as liveness-neutral (#2767).
fn subscribe_inbound(
    state: &ServiceState,
) -> Option<tokio::sync::broadcast::Receiver<(PeerId, DigMessage)>> {
    let guard = state.inbound_tx.lock().ok()?;
    Some(guard.as_ref()?.subscribe())
}

/// Wait for a `RespondPeers` frame published by `peer_id` on the application inbound stream.
///
/// Returns `true` when the peer answered, `false` when the broadcast closed (service shutdown).
/// Frames from other peers are skipped, and a
/// [`Lagged`](tokio::sync::broadcast::error::RecvError::Lagged) is **liveness-neutral** — lag means
/// the connection is carrying more traffic than this receiver drained, which is evidence of life,
/// not of death — so the wait simply continues. The caller bounds this with a `timeout`.
async fn await_respond_peers(
    inbound: &mut tokio::sync::broadcast::Receiver<(PeerId, DigMessage)>,
    peer_id: PeerId,
) -> bool {
    use tokio::sync::broadcast::error::RecvError;
    loop {
        match inbound.recv().await {
            Ok((pid, msg)) => {
                if pid == peer_id && msg.msg_type == chia_opcodes::RESPOND_PEERS {
                    return true;
                }
            }
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => return false,
        }
    }
}

/// Spawn a detached Tokio task that periodically probes `peer` and disconnects on
/// failure or staleness.
///
/// SPEC §5.1 step 7 — the per-connection message loop task includes keepalive.
/// SPEC §1.8 #6 — latency-aware peer scoring: RTT samples recorded here feed the
/// composite score `trust_score * (1 / avg_rtt_ms)` used for outbound peer preference.
///
/// # When it is called
///
/// Exactly once per live connection — spawned during the CNC-002 connection-setup
/// sequence:
///
/// - **Outbound:** [`GossipHandle::connect_to`](crate::service::gossip_handle::GossipHandle::connect_to)
/// - **Inbound:** [`crate::connection::listener::negotiate_inbound_over_ws`]
///
/// The task runs until the peer is disconnected (by timeout, transport error, or
/// service shutdown via [`ServiceState::is_running`](crate::service::state::ServiceState::is_running)).
///
/// # Side effects
///
/// - Records RTT samples on each successful probe via
///   [`PeerReputation::record_rtt_ms`](crate::types::reputation::PeerReputation::record_rtt_ms)
///   (feeds into PRF-001 latency-aware scoring).
/// - On failure, calls [`disconnect_after_keepalive_failure`] which applies a
///   [`PenaltyReason::ConnectionIssue`] penalty (10 points — CON-007) and closes
///   the TLS/WebSocket transport.
///
/// Returns the spawned task's [`AbortHandle`](tokio::task::AbortHandle) so the caller can store it on
/// the [`LiveSlot`] and abort it the instant the slot is superseded by a same-`peer_id` reconnect
/// (#1691) — a stale keepalive must not linger and fire a ghost teardown against the newer slot.
///
/// `generation` is the slot's session id ([`LiveSlot::generation`]); it is threaded into the teardown
/// so [`disconnect_after_keepalive_failure`] only evicts the map entry when it still belongs to THIS
/// session.
pub(crate) fn spawn_keepalive_task(
    state: Arc<ServiceState>,
    peer_id: PeerId,
    generation: u64,
    peer: DigLink,
) -> tokio::task::AbortHandle {
    tokio::spawn(async move { keepalive_loop(state, peer_id, generation, peer).await })
        .abort_handle()
}

/// Core keepalive loop: sleep -> check timeout -> send probe -> record RTT or disconnect.
///
/// See SPEC §2.13 for timing constants (`PING_INTERVAL_SECS = 30`, `PEER_TIMEOUT_SECS = 90`).
///
/// # Algorithm (CON-004 steps)
///
/// 1. Sleep for `PING_INTERVAL_SECS` (default 30 s, configurable for tests).
/// 2. If no successful probe has been received within `PEER_TIMEOUT_SECS` (default 90 s),
///    disconnect immediately — the 90 s window allows up to 3 missed 30 s intervals
///    before giving up, matching CON-004 acceptance criteria.
/// 3. Send an **uncorrelated** `RequestPeers` probe (#2767) and wait for the peer's
///    `RespondPeers` on the application inbound broadcast, wrapped in a `tokio::time::timeout` of
///    `PEER_TIMEOUT_SECS` so a half-open TCP socket cannot block this task forever. If the
///    broadcast is unavailable the round is skipped **without** taking the failure path.
/// 4. On success: record the RTT sample into the peer's
///    [`PeerReputation`](crate::types::reputation::PeerReputation) (windowed average,
///    feeds PRF-001 score).
/// 5. On transport error or timeout: call [`disconnect_after_keepalive_failure`] and
///    exit the loop.
///
/// # Cancellation safety
///
/// The loop checks [`ServiceState::is_running`](crate::service::state::ServiceState::is_running)
/// both before sleeping *and* after waking. This ensures prompt exit when the
/// service is shutting down even if the sleep was already in flight.
async fn keepalive_loop(state: Arc<ServiceState>, peer_id: PeerId, generation: u64, peer: DigLink) {
    // Resolve config overrides once — they are immutable for the connection lifetime.
    let ping_secs = state
        .config
        .keepalive_ping_interval_secs
        .unwrap_or(PING_INTERVAL_SECS);
    let timeout_secs = state
        .config
        .keepalive_peer_timeout_secs
        .unwrap_or(PEER_TIMEOUT_SECS);

    // Monotonic clock for RTT and staleness — not wall-clock, avoids NTP jump issues.
    let mut last_success = std::time::Instant::now();

    loop {
        // --- guard: service shutting down ---
        if !state.is_running() {
            break;
        }

        tokio::time::sleep(Duration::from_secs(ping_secs)).await;

        // Re-check after sleep: the service may have stopped while we were waiting.
        if !state.is_running() {
            break;
        }

        // --- staleness check (CON-004 step 2) ---
        // If we have not had any successful probe within the overall timeout window,
        // disconnect now rather than attempting another probe.
        if last_success.elapsed() > Duration::from_secs(timeout_secs) {
            tracing::warn!(
                target: "dig_gossip::keepalive",
                %peer_id,
                timeout_secs,
                "keepalive: no successful probe within PEER_TIMEOUT_SECS; disconnecting"
            );
            disconnect_after_keepalive_failure(&state, peer_id, generation).await;
            break;
        }

        // --- subscribe to the application inbound stream BEFORE probing (#2767) ---
        // The reply is observed on the service-wide broadcast, not on a correlation waiter, so the
        // subscription must exist before the probe goes out or a fast peer's reply races past us.
        let Some(mut inbound) = subscribe_inbound(&state) else {
            // Fail open: the broadcast is only absent while the service is starting or stopping.
            // A probe we cannot observe is not evidence the peer is dead, and the only action this
            // loop can take is to disconnect — so skip the round and leave the peer connected.
            tracing::debug!(
                target: "dig_gossip::keepalive",
                %peer_id,
                "keepalive: inbound broadcast unavailable; skipping this round (peer kept)"
            );
            continue;
        };

        // --- send probe (CON-004 step 3) ---
        // `Instant::now()` is taken *before* the send so that the elapsed time between `start` and
        // the observed reply includes serialization, network, and deserialization — giving a
        // realistic end-to-end RTT sample.
        let start = std::time::Instant::now();
        if let Err(e) = send_probe(&peer).await {
            tracing::warn!(
                target: "dig_gossip::keepalive",
                %peer_id,
                error = %e,
                "keepalive: RequestPeers probe failed to send; disconnecting"
            );
            disconnect_after_keepalive_failure(&state, peer_id, generation).await;
            break;
        }

        // --- await the peer's RespondPeers on the application stream (CON-004 step 4) ---
        // CON-006 metering is intentionally NOT done here: an uncorrelated reply reaches the
        // forwarder (`listener.rs` / `gossip_handle.rs`), which already charges `bytes_read`.
        // Metering it again would double-count every keepalive round.
        let observed = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            await_respond_peers(&mut inbound, peer_id),
        )
        .await;

        match observed {
            Ok(true) => {
                last_success = std::time::Instant::now();
                let rtt_ms = start.elapsed().as_millis() as u64;
                // Clone `Arc<Mutex<PeerReputation>>` while holding `peers`, then drop the
                // peer-map guard before locking reputation — avoids rustc E0597 when nesting
                // mutex guards derived from the same map lookup.
                let rep_mtx = {
                    let Ok(peers) = state.peers.lock() else {
                        continue;
                    };
                    let Some(PeerSlot::Live(live)) = peers.get(&peer_id) else {
                        continue;
                    };
                    Arc::clone(&live.reputation)
                };
                if let Ok(mut rep) = rep_mtx.lock() {
                    rep.record_rtt_ms(rtt_ms);
                };
            }
            // The broadcast closed: the service is stopping, not a peer failure.
            Ok(false) => break,
            // --- timeout: peer did not respond within PEER_TIMEOUT_SECS ---
            // This catches half-open TCP connections where the remote end has
            // crashed but the local OS has not yet detected the failure.
            Err(_elapsed) => {
                tracing::warn!(
                    target: "dig_gossip::keepalive",
                    %peer_id,
                    timeout_secs,
                    "keepalive: RequestPeers probe timed out; disconnecting"
                );
                disconnect_after_keepalive_failure(&state, peer_id, generation).await;
                break;
            }
        }
    }
}

/// Remove the peer from the active set, close the TLS/WebSocket transport, and
/// record a [`PenaltyReason::ConnectionIssue`] penalty in two places.
///
/// SPEC §1.5 #8 — peer ban/trust: `ClientState::ban()` / `is_banned()`. DIG extends
/// this with numeric penalty accumulation; keepalive failure contributes 10 penalty
/// points toward the SPEC §2.13 `PENALTY_BAN_THRESHOLD` (100).
///
/// # Penalty write + optional CON-007 ban (CON-004 / CON-007)
///
/// 1. Apply [`PenaltyReason::ConnectionIssue`] to the slot's [`PeerReputation`] **before**
///    closing — if this call is the first to cross [`PENALTY_BAN_THRESHOLD`](crate::constants::PENALTY_BAN_THRESHOLD),
///    [`PeerReputation::apply_penalty`] returns `true` and we schedule a timed DIG ban +
///    [`dig_peer_protocol::ClientState::ban`] via [`ServiceState::execute_dig_timed_ban`].
/// 2. Mirror the **exact** post-penalty `penalty_points` into `ServiceState::penalties` so
///    [`GossipHandle::penalize_peer`](crate::service::gossip_handle::GossipHandle::penalize_peer)
///    stays consistent with keepalive disconnects (single source of truth: no double add).
///
/// # Errors
///
/// All internal lock/close failures are silently ignored — this function is
/// best-effort cleanup on an already-failed connection, and propagating errors
/// would only complicate the caller for no recovery benefit.
///
/// # Pre-conditions
///
/// - `peer_id` should reference a [`PeerSlot::Live`] in `state.peers`. If the slot
///   has already been removed (race with another disconnect path), the function is
///   a no-op.
///
/// # Generation guard (#1691)
///
/// `generation` is the session id of the keepalive task that failed. The removal is a
/// **compare-and-remove**: the slot is evicted only when the entry currently in the map is `Live`
/// with the SAME `generation`. If a same-`peer_id` reconnect has already superseded this session, the
/// map holds a slot with a newer generation and this stale teardown becomes a no-op — so a lingering
/// keepalive from a dropped connection can never evict the reconnect (the #1691 self-inflicted race).
async fn disconnect_after_keepalive_failure(
    state: &ServiceState,
    peer_id: PeerId,
    generation: u64,
) {
    let now = unix_secs();

    // Step 1: compare-and-remove — evict the slot only if it is still THIS session's slot (same
    // generation). A superseding reconnect bumps the generation, so a stale task removes nothing.
    let removed = {
        let mut peers = match state.peers.lock() {
            Ok(g) => g,
            Err(_) => return, // Poisoned mutex — nothing safe to do.
        };
        match peers.get(&peer_id) {
            Some(PeerSlot::Live(l)) if l.generation == generation => peers.remove(&peer_id),
            _ => None, // Already superseded / gone / a different slot kind — do not touch it.
        }
    };

    // If the slot was already gone or superseded (guard above), bail out.
    let Some(PeerSlot::Live(live)) = removed else {
        return;
    };

    // Step 2: per-peer reputation penalty (ConnectionIssue = 10 pts, CON-007 table).
    let remote_ip = live.meta.remote.ip();
    let (triggered, pts) = match live.reputation.lock() {
        Ok(mut r) => {
            let t = r.apply_penalty(PenaltyReason::ConnectionIssue, now);
            (t, r.penalty_points)
        }
        Err(e) => {
            let mut r = e.into_inner();
            let t = r.apply_penalty(PenaltyReason::ConnectionIssue, now);
            (t, r.penalty_points)
        }
    };

    // Step 3: close the underlying WebSocket/TLS transport.
    // Ignoring the result — the remote may have already hung up.
    let _ = live.peer.close().await;

    // Step 4: mirror **total** points into the global map (same value `penalize_peer` would use).
    if let Ok(mut p) = state.penalties.lock() {
        p.insert(peer_id, pts);
    }

    // Step 5: if this failure was the straw that crossed the ban threshold, enforce CON-007
    // (timed ban + Chia IP ban) even though the slot is already removed.
    if triggered {
        state.execute_dig_timed_ban(peer_id, remote_ip, now).await;
    }
}

#[cfg(test)]
mod tests {
    //! #2767 — the probe must not park a correlation waiter.
    //!
    //! The mechanism test runs over a **real loopback WebSocket pair**, because the defect lives in
    //! [`DigLink`]'s inbound matcher: a symmetric in-memory double could not express a stolen frame.

    use super::*;
    use dig_peer_protocol::{LinkOptions, Streamable};
    use tokio::net::TcpListener;
    use tokio_tungstenite::{accept_async, connect_async, MaybeTlsStream};

    /// Both halves of a live loopback link, each with its application inbound receiver.
    async fn link_pair() -> (
        (DigLink, tokio::sync::mpsc::Receiver<DigMessage>),
        (DigLink, tokio::sync::mpsc::Receiver<DigMessage>),
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local_addr");

        let server = async {
            let (tcp, _) = listener.accept().await.expect("accept");
            let ws = accept_async(MaybeTlsStream::Plain(tcp))
                .await
                .expect("ws accept");
            DigLink::from_websocket(ws, LinkOptions::default()).expect("server link")
        };
        let client = async {
            let url = format!("ws://127.0.0.1:{}/", addr.port());
            let (ws, _) = connect_async(url.as_str()).await.expect("ws connect");
            DigLink::from_websocket(ws, LinkOptions::default()).expect("client link")
        };
        tokio::join!(server, client)
    }

    /// **#2767 mechanism.** The peer has an outstanding correlated waiter at id 0 — exactly the
    /// state a simultaneously-started keepalive loop is in. A correlated probe would carry id 0
    /// too, be swallowed by that waiter, and never reach the peer's application; the auto-reply
    /// that keeps the link alive would therefore never fire. The uncorrelated probe must arrive.
    ///
    /// The peer's own probe is a real `request_raw` rather than a hand-rolled frame so the waiter
    /// is registered by the same code path production uses.
    #[tokio::test]
    async fn probe_reaches_the_peer_application_despite_an_outstanding_correlated_waiter() {
        let ((a, _a_rx), (b, mut b_rx)) = link_pair().await;

        // The peer starts ITS probe first, parking a waiter at correlation id 0.
        let b_probe = tokio::spawn(async move { b.request_raw(RequestPeers::new()).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        send_probe(&a).await.expect("probe sends");

        let seen = tokio::time::timeout(Duration::from_secs(2), b_rx.recv())
            .await
            .expect("the peer's application must observe the probe within 2s")
            .expect("inbound channel open");
        assert_eq!(
            seen.msg_type,
            chia_opcodes::REQUEST_PEERS,
            "the probe must reach the peer's application, not its correlation waiter"
        );
        assert!(
            seen.id.is_none(),
            "the probe must be uncorrelated so no waiter can claim it"
        );
        assert!(
            RequestPeers::from_bytes(&seen.data).is_ok(),
            "the probe body must still be a RequestPeers the peer can auto-reply to"
        );
        b_probe.abort();
    }

    fn respond_peers_frame() -> DigMessage {
        DigMessage::new(
            chia_opcodes::RESPOND_PEERS,
            None,
            chia_protocol::RespondPeers::new(vec![])
                .to_bytes()
                .expect("encode")
                .into(),
        )
    }

    fn other_frame() -> DigMessage {
        DigMessage::new(chia_opcodes::REQUEST_PEERS, None, Vec::new().into())
    }

    /// A reply from a DIFFERENT peer must not be read as this peer's liveness. The control frame
    /// arrives afterwards so the test would fail — not hang — if the peer filter were dropped.
    #[tokio::test]
    async fn a_reply_from_another_peer_is_not_this_peer_s_liveness() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(8);
        let me = PeerId::from([1u8; 32]);
        let them = PeerId::from([2u8; 32]);

        tx.send((them, respond_peers_frame())).expect("send");
        tx.send((me, other_frame())).expect("send");
        drop(tx);

        assert!(
            !await_respond_peers(&mut rx, me).await,
            "only a RespondPeers from THIS peer counts; the stream then closed"
        );
    }

    /// `Lagged` means the connection carried more traffic than this receiver drained — evidence of
    /// life, not of death. The wait must continue and still see the reply queued behind it.
    #[tokio::test]
    async fn lag_is_liveness_neutral_and_the_wait_continues() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(2);
        let me = PeerId::from([7u8; 32]);

        // Overflow the buffer so the next `recv` yields `Lagged`, then queue the real reply.
        for _ in 0..4 {
            tx.send((me, other_frame())).expect("send");
        }
        tx.send((me, respond_peers_frame())).expect("send");

        assert!(
            await_respond_peers(&mut rx, me).await,
            "a lagged receiver must keep waiting and still observe the reply"
        );
    }

    /// A closed broadcast is service shutdown, not a peer failure — the caller breaks the loop
    /// rather than tearing the peer down.
    #[tokio::test]
    async fn a_closed_broadcast_reports_shutdown_rather_than_liveness() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(4);
        drop(tx);
        assert!(!await_respond_peers(&mut rx, PeerId::from([9u8; 32])).await);
    }
}
