//! Relay service lifecycle — auto-reconnect, NAT traversal, transport selection
//! (**RLY-004**, **RLY-007**, **RLY-008**).
//!
//! # Requirements
//!
//! - **RLY-004** — Auto-reconnect with configurable delay and max attempts
//! - **RLY-007** — NAT traversal hole punching via relay coordination
//! - **RLY-008** — Transport selection: direct P2P first, relay fallback, prefer_relay override
//! - **Master SPEC:** §7 (Relay Fallback), §7.1 (NAT Traversal Upgrade)
//!
//! # Design
//!
//! `RelayService` wraps `RelayClient` with lifecycle management:
//! - Auto-reconnect loop with configurable backoff (RLY-004)
//! - NAT traversal state machine (RLY-007)
//! - Transport selection logic (RLY-008)
//!
//! Actual WebSocket I/O is abstracted — the service manages state transitions
//! while I/O is plugged in via trait or callback.

use std::time::Duration;

use crate::types::config::RelayConfig;

/// Relay reconnection state (**RLY-004**).
///
/// Tracks consecutive failures and current backoff for auto-reconnect.
/// SPEC §7: "reconnect_delay_secs (5), max_reconnect_attempts (10)."
#[derive(Debug, Clone)]
pub struct ReconnectState {
    /// Consecutive failed reconnect attempts.
    pub consecutive_failures: u32,
    /// Current backoff delay.
    pub current_delay: Duration,
    /// Whether max attempts exceeded (should stop trying).
    pub exhausted: bool,
}

impl ReconnectState {
    /// Create from relay config defaults.
    pub fn new(config: &RelayConfig) -> Self {
        Self {
            consecutive_failures: 0,
            current_delay: Duration::from_secs(config.reconnect_delay_secs),
            exhausted: false,
        }
    }

    /// Record a failed reconnect attempt. Returns the delay to sleep before next try.
    ///
    /// SPEC §7 (RLY-004): "reconnect delay configurable, stop after max_reconnect_attempts."
    pub fn record_failure(&mut self, max_attempts: u32) -> Option<Duration> {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= max_attempts {
            self.exhausted = true;
            tracing::warn!(
                "RLY-004: max reconnect attempts ({}) exceeded",
                max_attempts
            );
            return None; // stop trying
        }
        let delay = self.current_delay;
        tracing::debug!(
            "RLY-004: reconnect attempt {}/{}, next in {:?}",
            self.consecutive_failures,
            max_attempts,
            delay
        );
        Some(delay)
    }

    /// Record a successful reconnect. Resets failure count.
    pub fn record_success(&mut self, config: &RelayConfig) {
        self.consecutive_failures = 0;
        self.current_delay = Duration::from_secs(config.reconnect_delay_secs);
        self.exhausted = false;
        tracing::info!("RLY-004: reconnect successful, reset failure count");
    }

    /// Whether reconnection attempts are exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }
}

/// NAT traversal hole punch state (**RLY-007**).
///
/// SPEC §7.1 — "HolePunchRequest → HolePunchCoordinate → simultaneous connect.
/// On success migrate to direct. On failure retry after 300s."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolePunchState {
    /// No hole punch in progress.
    Idle,
    /// Sent HolePunchRequest, waiting for coordination.
    WaitingForCoordination,
    /// Received coordination, attempting simultaneous connect.
    Connecting,
    /// Hole punch succeeded — traffic migrated to direct.
    Succeeded,
    /// Hole punch failed — will retry after `HOLE_PUNCH_RETRY_SECS`.
    Failed { retry_after_secs: u64 },
}

/// Default retry delay after failed hole punch (seconds).
/// SPEC §7.1: "failure retry after 300s."
pub const HOLE_PUNCH_RETRY_SECS: u64 = 300;

impl HolePunchState {
    /// Transition: request sent.
    pub fn request_sent(&mut self) {
        *self = Self::WaitingForCoordination;
    }

    /// Transition: coordination received, start connecting.
    pub fn coordination_received(&mut self) {
        *self = Self::Connecting;
    }

    /// Transition: connect succeeded.
    pub fn connect_succeeded(&mut self) {
        *self = Self::Succeeded;
    }

    /// Transition: connect failed.
    pub fn connect_failed(&mut self) {
        *self = Self::Failed {
            retry_after_secs: HOLE_PUNCH_RETRY_SECS,
        };
    }

    /// Whether a hole punch is actively in progress.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::WaitingForCoordination | Self::Connecting)
    }
}

/// Transport selection result (**RLY-008**).
///
/// SPEC §7: "direct P2P first, relay fallback, prefer_relay override."
/// SPEC §7.1: "On success migrate to direct."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportChoice {
    /// Use direct P2P connection.
    Direct,
    /// Use relay as fallback.
    Relay,
}

/// Select transport for sending to a peer (**RLY-008**).
///
/// Logic:
/// 1. If `prefer_relay` → always Relay
/// 2. If direct P2P connection exists → Direct
/// 3. If relay is connected → Relay
/// 4. Neither available → Relay (will queue for when relay reconnects)
///
/// SPEC §7: "direct P2P first, relay fallback, prefer_relay override."
pub fn select_transport(
    prefer_relay: bool,
    has_direct_connection: bool,
    relay_connected: bool,
) -> TransportChoice {
    if prefer_relay {
        return TransportChoice::Relay;
    }
    if has_direct_connection {
        return TransportChoice::Direct;
    }
    if relay_connected {
        return TransportChoice::Relay;
    }
    // Neither available — default to Relay (will be queued).
    TransportChoice::Relay
}
