//! Relay protocol wire types (**RLY-001** through **RLY-007**).
//!
//! # Requirements
//!
//! - **RLY-001** — Connect + Register / RegisterAck
//! - **RLY-002** — RelayGossipMessage (targeted forward)
//! - **RLY-003** — Broadcast (fan-out via relay)
//! - **RLY-005** — GetPeers / Peers
//! - **RLY-006** — Ping / Pong keepalive
//! - **RLY-007** — NAT traversal (HolePunch*)
//! - **Master SPEC:** §7 (Relay Fallback), §7.1 (NAT Traversal), §2.9 (RelayPeerInfo)
//!
//! # Wire format
//!
//! Relay messages use **JSON** over WebSocket (not Chia's binary protocol).
//! This matches `l2_driver_state_channel/src/services/relay/types.rs`.
//! The `#[serde(tag = "type")]` attribute produces `{"type": "register", ...}`.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Complete relay protocol message enum.
///
/// JSON-serialized over WebSocket. `#[serde(tag = "type")]` uses the variant's
/// `#[serde(rename = "...")]` as the `type` discriminator field.
///
/// SPEC §7 — "Relay messages use JSON over WebSocket."
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    // -- RLY-001: Registration --
    /// Client → Relay: register after WebSocket connect.
    #[serde(rename = "register")]
    Register {
        peer_id: String,
        network_id: String,
        protocol_version: u32,
    },

    /// Relay → Client: registration acknowledgement.
    #[serde(rename = "register_ack")]
    RegisterAck {
        success: bool,
        message: String,
        connected_peers: usize,
    },

    /// Client → Relay: graceful disconnect.
    #[serde(rename = "unregister")]
    Unregister { peer_id: String },

    // -- RLY-002: Targeted message forwarding --
    /// Client → Relay → Client: forward to specific peer.
    #[serde(rename = "relay_message")]
    RelayGossipMessage {
        from: String,
        to: String,
        payload: Vec<u8>,
        seq: u64,
    },

    // -- RLY-003: Broadcast --
    /// Client → Relay → All: broadcast to all relay peers.
    #[serde(rename = "broadcast")]
    Broadcast {
        from: String,
        payload: Vec<u8>,
        exclude: Vec<String>,
    },

    // -- Peer notifications --
    /// Relay → Client: new peer connected to relay.
    #[serde(rename = "peer_connected")]
    PeerConnected { peer: RelayPeerInfo },

    /// Relay → Client: peer disconnected from relay.
    #[serde(rename = "peer_disconnected")]
    PeerDisconnected { peer_id: String },

    // -- RLY-005: Peer list --
    /// Client → Relay: request connected peer list.
    #[serde(rename = "get_peers")]
    GetPeers { network_id: Option<String> },

    /// Relay → Client: peer list response.
    #[serde(rename = "peers")]
    Peers { peers: Vec<RelayPeerInfo> },

    // -- RLY-006: Keepalive --
    /// Bidirectional keepalive.
    #[serde(rename = "ping")]
    Ping { timestamp: u64 },

    /// Keepalive response.
    #[serde(rename = "pong")]
    Pong { timestamp: u64 },

    // -- RLY-007: NAT traversal --
    /// Client → Relay: request hole punch coordination.
    #[serde(rename = "hole_punch_request")]
    HolePunchRequest {
        peer_id: String,
        target_peer_id: String,
        external_addr: SocketAddr,
    },

    /// Relay → Client: hole punch coordination.
    #[serde(rename = "hole_punch_coordinate")]
    HolePunchCoordinate {
        peer_id: String,
        external_addr: SocketAddr,
    },

    /// Client → Relay: hole punch result.
    #[serde(rename = "hole_punch_result")]
    HolePunchResult { peer_id: String, success: bool },

    // -- Error --
    /// Relay → Client: error notification.
    #[serde(rename = "error")]
    Error { code: u32, message: String },
}

/// Peer info as tracked by relay server.
///
/// SPEC §2.9 — `RelayPeerInfo`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayPeerInfo {
    pub peer_id: String,
    pub network_id: String,
    pub protocol_version: u32,
    pub connected_at: u64,
    pub last_seen: u64,
}

impl RelayPeerInfo {
    pub fn new(peer_id: String, network_id: String, protocol_version: u32) -> Self {
        let now = crate::types::peer::metric_unix_timestamp_secs();
        Self {
            peer_id,
            network_id,
            protocol_version,
            connected_at: now,
            last_seen: now,
        }
    }
}
