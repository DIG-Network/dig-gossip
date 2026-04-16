//! Relay WebSocket client — connect, register, send, receive (**RLY-001** through **RLY-006**).
//!
//! # Requirements
//!
//! - **RLY-001** — Connect + Register
//! - **RLY-002** — Send to specific peer via RelayGossipMessage
//! - **RLY-003** — Broadcast to all relay peers
//! - **RLY-005** — GetPeers / Peers
//! - **RLY-006** — Ping / Pong keepalive
//! - **Master SPEC:** §7 (Relay Fallback), §5.1 relay fallback steps
//!
//! # Design
//!
//! `RelayClient` wraps a WebSocket connection to relay server. It tracks:
//! - Registration state (registered or not)
//! - Per-target sequence numbers (monotonic, for RelayGossipMessage)
//! - Known relay peers (from RegisterAck + PeerConnected/Disconnected)
//!
//! JSON serialization over WebSocket (not Chia binary protocol).

use std::collections::HashMap;

use super::relay_types::{RelayMessage, RelayPeerInfo};
use crate::error::GossipError;

/// Relay client state tracker.
///
/// In Phase 4 this tracks state without actual WebSocket I/O.
/// Real WebSocket send/receive will be added when integrating with
/// `tokio-tungstenite` in the relay service (RLY-004).
///
/// SPEC §7 — "Relay client connects via WebSocket, registers, forwards messages."
#[derive(Debug)]
pub struct RelayClient {
    /// Whether registered with relay (after RegisterAck success).
    registered: bool,
    /// Our peer ID (hex string for relay JSON protocol).
    peer_id: String,
    /// Network ID (hex string).
    network_id: String,
    /// Protocol version.
    protocol_version: u32,
    /// Per-target sequence numbers for RelayGossipMessage.
    /// SPEC §7 (RLY-002): "monotonically increasing per sender-receiver pair."
    seq_numbers: HashMap<String, u64>,
    /// Known peers on relay (from RegisterAck + notifications).
    known_peers: Vec<RelayPeerInfo>,
    /// Outbound message buffer (for testing without real WebSocket).
    outbound_buffer: Vec<RelayMessage>,
}

impl RelayClient {
    /// Create unconnected relay client.
    pub fn new(peer_id: String, network_id: String, protocol_version: u32) -> Self {
        Self {
            registered: false,
            peer_id,
            network_id,
            protocol_version,
            seq_numbers: HashMap::new(),
            known_peers: Vec::new(),
            outbound_buffer: Vec::new(),
        }
    }

    /// Build Register message for initial handshake (RLY-001).
    pub fn build_register(&self) -> RelayMessage {
        RelayMessage::Register {
            peer_id: self.peer_id.clone(),
            network_id: self.network_id.clone(),
            protocol_version: self.protocol_version,
        }
    }

    /// Process RegisterAck from relay (RLY-001).
    ///
    /// Sets registered state and stores initial peer list.
    /// Returns error if registration was rejected.
    pub fn handle_register_ack(
        &mut self,
        success: bool,
        message: &str,
        connected_peers: usize,
    ) -> Result<(), GossipError> {
        if success {
            self.registered = true;
            tracing::info!("RLY-001: registered with relay ({connected_peers} peers)");
            Ok(())
        } else {
            Err(GossipError::RelayError(format!(
                "registration rejected: {message}"
            )))
        }
    }

    /// Whether registered with relay.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Build RelayGossipMessage for targeted send (RLY-002).
    ///
    /// Auto-increments sequence number per target peer.
    /// SPEC §7 (RLY-002): "monotonically increasing seq per sender-receiver pair."
    pub fn build_send_to_peer(&mut self, target_peer_id: &str, payload: Vec<u8>) -> RelayMessage {
        let seq = self
            .seq_numbers
            .entry(target_peer_id.to_string())
            .or_insert(0);
        *seq += 1;

        RelayMessage::RelayGossipMessage {
            from: self.peer_id.clone(),
            to: target_peer_id.to_string(),
            payload,
            seq: *seq,
        }
    }

    /// Build Broadcast message (RLY-003).
    ///
    /// SPEC §7 (RLY-003): "Broadcast to all relay peers via Broadcast{from, payload, exclude}."
    pub fn build_broadcast(&self, payload: Vec<u8>, exclude: Vec<String>) -> RelayMessage {
        RelayMessage::Broadcast {
            from: self.peer_id.clone(),
            payload,
            exclude,
        }
    }

    /// Build GetPeers request (RLY-005).
    pub fn build_get_peers(&self) -> RelayMessage {
        RelayMessage::GetPeers {
            network_id: Some(self.network_id.clone()),
        }
    }

    /// Process Peers response (RLY-005).
    pub fn handle_peers(&mut self, peers: Vec<RelayPeerInfo>) {
        self.known_peers = peers;
    }

    /// Process PeerConnected notification.
    pub fn handle_peer_connected(&mut self, peer: RelayPeerInfo) {
        // Avoid duplicates by peer_id.
        if !self.known_peers.iter().any(|p| p.peer_id == peer.peer_id) {
            self.known_peers.push(peer);
        }
    }

    /// Process PeerDisconnected notification.
    pub fn handle_peer_disconnected(&mut self, peer_id: &str) {
        self.known_peers.retain(|p| p.peer_id != peer_id);
    }

    /// Build Ping message (RLY-006).
    pub fn build_ping(&self) -> RelayMessage {
        RelayMessage::Ping {
            timestamp: crate::types::peer::metric_unix_timestamp_secs(),
        }
    }

    /// Get current known relay peers.
    pub fn known_peers(&self) -> &[RelayPeerInfo] {
        &self.known_peers
    }

    /// Get known peer count.
    pub fn peer_count(&self) -> usize {
        self.known_peers.len()
    }

    /// Queue outbound message (for testing without real WebSocket).
    pub fn queue_outbound(&mut self, msg: RelayMessage) {
        self.outbound_buffer.push(msg);
    }

    /// Take all queued outbound messages.
    pub fn take_outbound(&mut self) -> Vec<RelayMessage> {
        std::mem::take(&mut self.outbound_buffer)
    }

    /// Get sequence number for target peer.
    pub fn seq_for_target(&self, target: &str) -> u64 {
        self.seq_numbers.get(target).copied().unwrap_or(0)
    }

    /// Mark as unregistered (on disconnect / reconnect).
    pub fn reset(&mut self) {
        self.registered = false;
        self.known_peers.clear();
        // Note: seq_numbers NOT reset — monotonic across reconnects.
    }
}
