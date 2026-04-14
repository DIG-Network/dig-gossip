//! Configuration types for the gossip service, introducer, and relay.
//!
//! **Re-export:** STR-003; **full field set:** API-003 /
//! [`docs/requirements/domains/crate_api/specs/API-003.md`](../../../docs/requirements/domains/crate_api/specs/API-003.md).
//!
//! STR-005 (`tests/common`, `test_gossip_config`) needs a **concrete** `GossipConfig` so
//! integration tests can build configs without waiting on API-001. Fields here follow API-003
//! and SPEC Section 2.10; optional nested configs from the API-003 sketch (`dandelion`, `tor`,
//! `erlay`, `backpressure`, …) land when those domains add types — see TRACKING notes.

use std::net::SocketAddr;
use std::path::PathBuf;

use chia_protocol::Bytes32;
use chia_sdk_client::{Network, PeerOptions};

use super::peer::PeerId;
use crate::constants::{
    DEFAULT_MAX_SEEN_MESSAGES, DEFAULT_P2P_PORT, DEFAULT_TARGET_OUTBOUND_COUNT,
};

/// Top-level knobs: listen address, network id, bootstrap targets, TLS paths, etc.
///
/// **Normative shape:** API-003 / [`SPEC.md`](../../../docs/resources/SPEC.md) Section 2.10.
/// Defaults mirror Chia/DIG conventions (`DEFAULT_P2P_PORT`, `DEFAULT_TARGET_OUTBOUND_COUNT`, …).
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Listen address for inbound P2P connections.
    pub listen_addr: SocketAddr,
    /// This node’s stable [`PeerId`](super::peer::PeerId) (BLS / identity layer).
    pub peer_id: PeerId,
    /// Network genesis id (e.g. SHA256("dig_mainnet")) — must match peers (CON-003).
    pub network_id: Bytes32,
    /// DNS introducer / network parameters (`chia_sdk_client::Network`).
    pub network: Network,
    /// Target outbound connection count (Chia `node_discovery.py` lineage).
    pub target_outbound_count: usize,
    /// Maximum simultaneous connections (inbound + outbound).
    pub max_connections: usize,
    /// Bootstrap peer socket addresses (empty in tests unless DSC-* seeds).
    pub bootstrap_peers: Vec<SocketAddr>,
    /// Optional introducer client configuration (DSC-004 / DSC-005).
    pub introducer: Option<IntroducerConfig>,
    /// Optional relay client configuration (relay domain).
    pub relay: Option<RelayConfig>,
    /// PEM path for the node TLS certificate (`load_ssl_cert`, CON-009).
    pub cert_path: String,
    /// PEM path for the node TLS private key.
    pub key_path: String,
    /// Seconds between outbound connection attempts in the discovery loop.
    pub peer_connect_interval: u64,
    /// Plumtree / flood fanout target (PLT-*).
    pub gossip_fanout: usize,
    /// Capacity of the seen-message LRU / dedup set (PLT-008).
    pub max_seen_messages: usize,
    /// Persistent address-manager file (DSC-002).
    pub peers_file_path: PathBuf,
    /// Per-connection rate limiter factor (`PeerOptions::rate_limit_factor`).
    pub peer_options: PeerOptions,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_P2P_PORT)),
            peer_id: PeerId::default(),
            network_id: Bytes32::default(),
            network: Network::default_mainnet(),
            target_outbound_count: DEFAULT_TARGET_OUTBOUND_COUNT,
            max_connections: 50,
            bootstrap_peers: Vec::new(),
            introducer: None,
            relay: None,
            cert_path: String::new(),
            key_path: String::new(),
            peer_connect_interval: 10,
            gossip_fanout: 8,
            max_seen_messages: DEFAULT_MAX_SEEN_MESSAGES,
            peers_file_path: PathBuf::new(),
            peer_options: PeerOptions::default(),
        }
    }
}

/// Introducer host, registration policy, retry cadence.
#[derive(Debug, Clone, Default)]
pub struct IntroducerConfig {}

/// Relay URL, credentials, reconnect policy.
#[derive(Debug, Clone, Default)]
pub struct RelayConfig {}
