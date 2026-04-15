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
//! heartbeats for transport liveness. Upstream [`chia_sdk_client::Peer`](chia_sdk_client::Peer)’s
//! inbound loop discards raw WS control frames (`Ping`/`Pong`) before they become [`Message`](chia_protocol::Message)s.
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
//! ## Per-probe deadline
//!
//! A dead TCP peer may leave [`Peer::request_infallible`] awaiting forever. Each probe is wrapped in
//! [`tokio::time::timeout`] for `keepalive_peer_timeout_secs` (or [`PEER_TIMEOUT_SECS`]) so we surface
//! failure and disconnect (same path as transport errors) without blocking the keepalive task
//! indefinitely.
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

use chia_protocol::{RequestPeers, RespondPeers};
use chia_sdk_client::Peer;
use chia_traits::Streamable;

// SPEC §2.13 — PING_INTERVAL_SECS (default 30) and PEER_TIMEOUT_SECS (default 90)
// are DIG-specific constants not present in Chia crates.
use crate::constants::{PEER_TIMEOUT_SECS, PING_INTERVAL_SECS};
use crate::service::state::{record_live_peer_inbound_bytes, PeerSlot, ServiceState};
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
pub(crate) fn spawn_keepalive_task(state: Arc<ServiceState>, peer_id: PeerId, peer: Peer) {
    tokio::spawn(async move { keepalive_loop(state, peer_id, peer).await });
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
/// 3. Send a `RequestPeers` probe wrapped in a `tokio::time::timeout` of
///    `PEER_TIMEOUT_SECS` so a half-open TCP socket cannot block this task forever.
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
async fn keepalive_loop(state: Arc<ServiceState>, peer_id: PeerId, peer: Peer) {
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
            disconnect_after_keepalive_failure(&state, peer_id).await;
            break;
        }

        // --- send probe (CON-004 step 3) ---
        // `Instant::now()` is taken *before* the request so that the elapsed time
        // between `start` and success includes serialization, network, and
        // deserialization — giving a realistic end-to-end RTT sample.
        let start = std::time::Instant::now();
        // `request_raw` returns the full wire [`Message`] so CON-006 can meter exact serialized
        // inbound bytes (same framing as the forwarder path). `request_infallible` only yields the
        // decoded body and would hide the length we need for `bytes_read`.
        let probe = peer.request_raw(RequestPeers::new());
        match tokio::time::timeout(Duration::from_secs(timeout_secs), probe).await {
            // --- success: record RTT into PeerReputation (CON-004 step 4) ---
            Ok(Ok(wire_msg)) => {
                if RespondPeers::from_bytes(&wire_msg.data).is_err() {
                    continue;
                }
                let wl = wire_msg
                    .to_bytes()
                    .map(|b| b.len() as u64)
                    .unwrap_or(0);
                record_live_peer_inbound_bytes(&state, peer_id, wl);
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
            // --- transport error: peer is alive but protocol failed ---
            Ok(Err(e)) => {
                tracing::warn!(
                    target: "dig_gossip::keepalive",
                    %peer_id,
                    error = %e,
                    "keepalive: RequestPeers probe failed; disconnecting"
                );
                disconnect_after_keepalive_failure(&state, peer_id).await;
                break;
            }
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
                disconnect_after_keepalive_failure(&state, peer_id).await;
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
/// # Penalty dual-write (CON-004 / CON-007)
///
/// The penalty is written to **both**:
///
/// 1. The per-peer [`PeerReputation`](crate::types::reputation::PeerReputation) inside
///    the [`LiveSlot`](crate::service::state::LiveSlot) (used for scoring while the
///    slot is still alive — unlikely here since we are removing it, but ensures the
///    struct is consistent if anything reads it before drop).
/// 2. The global `ServiceState::penalties` map keyed by [`PeerId`]. This map survives
///    slot removal so that reconnection logic and CON-007 ban checks can see
///    accumulated penalties even after the connection is gone.
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
async fn disconnect_after_keepalive_failure(state: &ServiceState, peer_id: PeerId) {
    let now = unix_secs();

    // Step 1: atomically remove the slot from the peer map so no other code path
    // can interact with it after this point.
    let removed = {
        let mut peers = match state.peers.lock() {
            Ok(g) => g,
            Err(_) => return, // Poisoned mutex — nothing safe to do.
        };
        peers.remove(&peer_id)
    };

    // If the slot was already gone (concurrent disconnect), bail out.
    let Some(PeerSlot::Live(live)) = removed else {
        return;
    };

    // Step 2: per-peer reputation penalty (ConnectionIssue = 10 pts, CON-007 table).
    if let Ok(mut r) = live.reputation.lock() {
        r.apply_penalty(PenaltyReason::ConnectionIssue, now);
    }

    // Step 3: close the underlying WebSocket/TLS transport.
    // Ignoring the result — the remote may have already hung up.
    let _ = live.peer.close().await;

    // Step 4: mirror the penalty into the global map so it persists past slot removal.
    // Uses saturating_add to prevent wraparound if a peer is repeatedly reconnecting
    // and failing (security: avoids u32 overflow resetting penalty to zero).
    if let Ok(mut p) = state.penalties.lock() {
        let e = p.entry(peer_id).or_insert(0);
        *e = e.saturating_add(PenaltyReason::ConnectionIssue.penalty_points());
    }
}
