//! Configuration types for the gossip service, introducer, and relay.
//!
//! **Re-export:** STR-003; **normative field set:** API-003 /
//! [`docs/requirements/domains/crate_api/specs/API-003.md`](../../../docs/requirements/domains/crate_api/specs/API-003.md)
//! and [`SPEC.md`](../../../docs/resources/SPEC.md) §2.10.
//!
//! **Introducer / relay slots:** API-010 /
//! [`docs/requirements/domains/crate_api/specs/API-010.md`](../../../docs/requirements/domains/crate_api/specs/API-010.md)
//! ([`IntroducerConfig`], [`RelayConfig`]) — serde-friendly knobs for DSC-* and RLY-* clients.
//!
//! ## Feature-gated fields
//!
//! Optional subsystems attach to [`GossipConfig`] only when their Cargo features are enabled
//! (STR-004), matching the API-003 sketch: `dandelion`, `tor`, `erlay`. That keeps
//! `--no-default-features` TLS-only graphs free of those fields and of `privacy` / `erlay`
//! module edges (see `tests/str_004_tests.rs`).

use std::net::SocketAddr;
use std::path::PathBuf;

use chia_protocol::Bytes32;
use chia_sdk_client::{Network, PeerOptions};
use serde::{Deserialize, Serialize};

use super::peer::PeerId;
use crate::constants::{
    DEFAULT_MAX_SEEN_MESSAGES, DEFAULT_P2P_PORT, DEFAULT_TARGET_OUTBOUND_COUNT, PING_INTERVAL_SECS,
};
use crate::gossip::backpressure::BackpressureConfig;

#[cfg(feature = "erlay")]
pub use crate::gossip::erlay::ErlayConfig;
#[cfg(feature = "dandelion")]
pub use crate::privacy::dandelion::DandelionConfig;
#[cfg(feature = "tor")]
pub use crate::privacy::tor::TorConfig;

/// Ephemeral [`PeerId`] rotation policy (privacy / fingerprinting — SPEC §1.9.2).
///
/// Expanded under PRV-006; API-003 only requires the option slot on [`GossipConfig`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerIdRotationConfig {}

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
    /// Dandelion++ stem/fluff configuration (feature `dandelion`).
    #[cfg(feature = "dandelion")]
    pub dandelion: Option<DandelionConfig>,
    /// Optional ephemeral peer-id rotation (PRV-006).
    pub peer_id_rotation: Option<PeerIdRotationConfig>,
    /// Tor / SOCKS5 transport (feature `tor`).
    #[cfg(feature = "tor")]
    pub tor: Option<TorConfig>,
    /// ERLAY reconciliation parameters (feature `erlay`).
    #[cfg(feature = "erlay")]
    pub erlay: Option<ErlayConfig>,
    /// Adaptive outbound backpressure (PRI-*).
    pub backpressure: Option<BackpressureConfig>,
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
            #[cfg(feature = "dandelion")]
            dandelion: None,
            peer_id_rotation: None,
            #[cfg(feature = "tor")]
            tor: None,
            #[cfg(feature = "erlay")]
            erlay: None,
            backpressure: None,
        }
    }
}

/// Default `network_id` string sent to the introducer (SPEC §2.11 / API-010).
pub const DEFAULT_INTRODUCER_NETWORK_ID: &str = "DIG_MAINNET";

/// Introducer client configuration (bootstrap + registration — DSC-004 / DSC-005).
///
/// **`endpoint`** is deployment-specific; [`Default`] uses an empty string as a **sentinel** — callers
/// must validate non-empty before dialing (API-010 implementation notes). Other fields match SPEC §2.11
/// defaults so `..Default::default()` fills timeouts and `network_id` when only the URL is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IntroducerConfig {
    /// WebSocket URL (e.g. `ws://introducer.example.com:9448`).
    pub endpoint: String,
    /// Outbound connect timeout (seconds). Default **10**.
    pub connection_timeout_secs: u64,
    /// Per-request timeout (seconds). Default **10**.
    pub request_timeout_secs: u64,
    /// Logical network label for introducer registration. Default **`DIG_MAINNET`**.
    pub network_id: String,
}

impl Default for IntroducerConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            connection_timeout_secs: 10,
            request_timeout_secs: 10,
            network_id: DEFAULT_INTRODUCER_NETWORK_ID.to_string(),
        }
    }
}

/// Relay fallback client configuration (RLY-* — SPEC §2.12 / API-010).
///
/// **`endpoint`** uses the same empty sentinel pattern as [`IntroducerConfig`]. **`enabled`** defaults
/// to **`true`** so `Some(RelayConfig::default())` in tests represents “relay feature present” while
/// still requiring a real URL in production. **`prefer_relay`** implements SPEC Design Decision 8
/// (default direct P2P first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayConfig {
    /// WebSocket URL (e.g. `wss://relay.example.com:9450`).
    pub endpoint: String,
    /// Master switch: when `false`, the client must not open a relay session even if `endpoint` is set.
    pub enabled: bool,
    /// Connect timeout (seconds). Default **10**.
    pub connection_timeout_secs: u64,
    /// Base delay between reconnect attempts (seconds). Default **5** (RLY-004 lineage).
    pub reconnect_delay_secs: u64,
    /// Cap on consecutive reconnect attempts (`0` = give up immediately per API-010 notes).
    pub max_reconnect_attempts: u32,
    /// Keepalive ping period — aligned with [`PING_INTERVAL_SECS`](crate::constants::PING_INTERVAL_SECS) (**30**).
    pub ping_interval_secs: u64,
    /// When `true`, prefer relay transport even if direct peers exist (RLY-008).
    pub prefer_relay: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            enabled: true,
            connection_timeout_secs: 10,
            reconnect_delay_secs: 5,
            max_reconnect_attempts: 10,
            ping_interval_secs: PING_INTERVAL_SECS,
            prefer_relay: false,
        }
    }
}
