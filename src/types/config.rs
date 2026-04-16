//! Configuration types for the gossip service, introducer, and relay.
//!
//! This module defines the three user-facing configuration structs that drive the entire gossip
//! subsystem at startup. [`GossipConfig`] is the top-level knob bag consumed by
//! [`crate::service::gossip_service::GossipService::new`]; [`IntroducerConfig`] and
//! [`RelayConfig`] are optional children that activate the bootstrap and NAT-fallback paths
//! respectively.
//!
//! # Requirements traceability
//!
//! | Requirement | Struct | Spec section |
//! |-------------|--------|--------------|
//! | API-003 | [`GossipConfig`] | SPEC §2.10 (includes DSC-003 DNS seed knobs on [`GossipConfig`]) |
//! | API-010 | [`IntroducerConfig`], [`RelayConfig`] | SPEC §2.11, §2.12 |
//! | STR-003 | re-export at crate root | SPEC §10.2 |
//! | STR-004 | feature-gated fields | SPEC §10.3 |
//!
//! - **API-003:** [`docs/requirements/domains/crate_api/specs/API-003.md`](../../../docs/requirements/domains/crate_api/specs/API-003.md)
//! - **API-010:** [`docs/requirements/domains/crate_api/specs/API-010.md`](../../../docs/requirements/domains/crate_api/specs/API-010.md)
//!
//! # Feature-gated fields
//!
//! Optional subsystems attach to [`GossipConfig`] only when their Cargo features are enabled
//! (STR-004), matching the API-003 sketch: `dandelion`, `tor`, `erlay`. That keeps
//! `--no-default-features` TLS-only graphs free of those fields and of `privacy` / `erlay`
//! module edges (see `tests/str_004_tests.rs`).
//!
//! # Chia context
//!
//! Several fields in [`GossipConfig`] originate from Chia's Python `node_discovery.py` and
//! `server_api.py`: target outbound count, connect interval, and the `PeerOptions` rate limit
//! factor. The [`Network`](dig_protocol::Network) field delegates DNS seed lookup to
//! `chia-sdk-client`'s `Network::lookup_all()`, avoiding reimplementation.
//!
//! # Design decisions
//!
//! - **Empty-string sentinel for URLs:** Both [`IntroducerConfig::endpoint`] and
//!   [`RelayConfig::endpoint`] use an empty string as a default sentinel rather than `Option<String>`,
//!   so that `serde(default)` produces a valid struct and callers can validate non-empty before dialing.
//! - **`Default` values mirror Chia/DIG conventions:** `DEFAULT_P2P_PORT` (9444), `DEFAULT_TARGET_OUTBOUND_COUNT` (8),
//!   `PING_INTERVAL_SECS` (30 s) — these come from `constants.rs` to keep a single source of truth.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use dig_protocol::Bytes32;
use dig_protocol::{Network, PeerOptions};
use serde::{Deserialize, Serialize};

use super::peer::PeerId;
use crate::constants::{
    DEFAULT_DNS_SEED_BATCH_SIZE, DEFAULT_DNS_SEED_TIMEOUT_SECS, DEFAULT_MAX_SEEN_MESSAGES,
    DEFAULT_P2P_PORT, DEFAULT_TARGET_OUTBOUND_COUNT, PING_INTERVAL_SECS,
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
/// Chia nodes use a permanent `PeerId` derived from a static TLS certificate, enabling long-term
/// tracking across sessions and IP changes. DIG rotates certificates periodically so the
/// network-layer identity is unlinkable across rotation boundaries while consensus-layer BLS
/// keys remain stable.
///
/// # Invariants (PRV-006)
///
/// - `rotation_interval_secs == 0` disables rotation (PRV-008).
/// - After rotation, all peer connections are torn down and re-established with the new certificate
///   if `reconnect_on_rotation` is `true`.
/// - The address manager tracks peers by `IP:port`, not `PeerId`, so rotation does not cause churn.
///
/// **Requirement:** [`docs/requirements/domains/privacy/specs/PRV-006.md`](../../../docs/requirements/domains/privacy/specs/PRV-006.md)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdRotationConfig {
    /// Enable periodic PeerId rotation. Default: `true`.
    pub enabled: bool,
    /// Rotation interval in seconds. Default: `86400` (24 hours).
    /// Set to `0` to disable rotation entirely (PRV-008).
    pub rotation_interval_secs: u64,
    /// Whether to reconnect to all peers after rotation. Default: `true`.
    /// If `false`, only new connections use the new identity; existing connections
    /// retain the old PeerId until they naturally close.
    pub reconnect_on_rotation: bool,
}

impl Default for PeerIdRotationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rotation_interval_secs: 86400,
            reconnect_on_rotation: true,
        }
    }
}

impl PeerIdRotationConfig {
    /// Returns `true` if rotation is effectively disabled (**PRV-008**).
    ///
    /// Rotation is disabled when:
    /// - `enabled` is `false`, OR
    /// - `rotation_interval_secs` is `0` (zero interval is nonsensical)
    pub fn is_rotation_disabled(&self) -> bool {
        !self.enabled || self.rotation_interval_secs == 0
    }
}

/// Top-level gossip service configuration, consumed by
/// [`GossipService::new`](crate::service::gossip_service::GossipService::new).
///
/// This struct is the single source of truth for every tunable in the gossip subsystem.
/// Optional sub-configs ([`IntroducerConfig`], [`RelayConfig`], [`BackpressureConfig`], and the
/// feature-gated privacy/ERLAY configs) are `None` by default so a minimal `GossipConfig::default()`
/// starts a functioning node with only direct P2P.
///
/// # Normative shape
///
/// API-003 / [`SPEC.md`](../../../docs/resources/SPEC.md) §2.10.
///
/// # Ownership
///
/// Stored inside [`crate::service::state::ServiceState`] as the authoritative runtime config
/// snapshot. Cloned once at startup; not mutated after construction.
///
/// # Defaults
///
/// Defaults mirror Chia/DIG conventions. Key values:
/// - `listen_addr`: `0.0.0.0:9444` (`DEFAULT_P2P_PORT`)
/// - `target_outbound_count`: 8 (Chia `node_discovery.py:49`)
/// - `max_connections`: 50 (inbound + outbound combined)
/// - `gossip_fanout`: 8 (Plumtree eager-push peer count)
/// - `max_seen_messages`: 100 000 (PLT-008 LRU dedup capacity)
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Socket on which the inbound TCP/TLS listener binds (CON-002).
    /// Default `0.0.0.0:9444`. Set to `127.0.0.1:0` in integration tests for port 0 allocation.
    pub listen_addr: SocketAddr,

    /// This node’s identity. Derived from `SHA256(TLS SPKI DER)` via
    /// [`crate::types::peer::peer_id_from_tls_spki_der`]. The consensus layer may assign a
    /// different (BLS-based) identity; this is purely the network layer’s fingerprint.
    pub peer_id: PeerId,

    /// Network genesis hash — peers that present a different `network_id` during the Chia
    /// handshake are rejected (CON-003). Convention: `SHA256("dig_mainnet")` for production.
    pub network_id: Bytes32,

    /// DNS seed / network parameters delegated to
    /// [`dig_protocol::Network::lookup_all()`](dig_protocol::Network). Configures which DNS
    /// introducers are contacted first before the WebSocket introducer fallback (DSC-003).
    pub network: Network,

    /// Timeout forwarded to [`Network::lookup_all`](dig_protocol::Network::lookup_all) for each
    /// DNS introducer in the current batch (DSC-003). Default **30 s** per [`DEFAULT_DNS_SEED_TIMEOUT_SECS`].
    pub dns_seed_timeout: Duration,

    /// Parallel batch size for DNS introducer resolution (second argument to `lookup_all`, DSC-003).
    /// Default **2** ([`DEFAULT_DNS_SEED_BATCH_SIZE`]). Values below **1** are clamped to **1** at the
    /// call site so misconfiguration cannot trigger a panic in [`std::slice::chunks`]-based upstream code.
    pub dns_seed_batch_size: usize,

    /// How many outbound connections the discovery loop tries to maintain.
    /// Chia default is 8 (`node_discovery.py:49`); DIG inherits the same.
    /// The loop sleeps `peer_connect_interval` seconds between batches.
    pub target_outbound_count: usize,

    /// Hard cap on inbound + outbound connections. Inbound accept returns
    /// [`GossipError::MaxConnectionsReached`](crate::error::GossipError::MaxConnectionsReached)
    /// when this limit is hit. Default 50 matches Chia full-node practice.
    pub max_connections: usize,

    /// Explicit bootstrap peer addresses tried before DNS / introducer (useful for testnets
    /// and local clusters). Empty by default.
    pub bootstrap_peers: Vec<SocketAddr>,

    /// Introducer client config. `None` means no introducer bootstrap (tests, air-gapped nodes).
    /// When `Some`, DSC-004 queries and DSC-005 registration are enabled.
    pub introducer: Option<IntroducerConfig>,

    /// Relay fallback config. `None` disables the relay transport entirely.
    /// When `Some`, RLY-001..RLY-008 specs govern behaviour.
    pub relay: Option<RelayConfig>,

    /// Filesystem path to the PEM-encoded TLS certificate used for both inbound accept and
    /// outbound connect. Loaded via `dig_protocol::load_ssl_cert` (CON-009).
    pub cert_path: String,

    /// Filesystem path to the PEM-encoded TLS private key (paired with `cert_path`).
    pub key_path: String,

    /// Seconds the discovery loop waits between outbound connection attempt batches.
    /// Chia uses `select_peer_interval` with multi-second gaps (`node_discovery.py:244`);
    /// DIG defaults to 10 s but supports parallel batching (DSC-009 / PRF-004).
    pub peer_connect_interval: u64,

    /// Number of eager-push peers for Plumtree gossip (PLT-002). Also used as the "flood set"
    /// size when ERLAY is disabled. Default 8 matches the ERLAY flood peer count.
    pub gossip_fanout: usize,

    /// Maximum entries in the LRU seen-message dedup set (PLT-008). Messages beyond this
    /// capacity evict the oldest entry. Default 100 000.
    pub max_seen_messages: usize,

    /// File path for address-manager persistence (DSC-002 `peers.dat`-style). Empty `PathBuf`
    /// in tests means in-memory only; production should point to a durable location.
    pub peers_file_path: PathBuf,

    /// Per-connection options forwarded to `chia-sdk-client` when constructing a [`Peer`](dig_protocol::Peer).
    /// The main knob here is `rate_limit_factor` which scales the V2 rate limits (CON-005).
    pub peer_options: PeerOptions,

    /// Dandelion++ stem/fluff configuration (SPEC §1.9.1 / PRV-001).
    /// Only compiled when the `dandelion` feature flag is enabled (STR-004).
    #[cfg(feature = "dandelion")]
    pub dandelion: Option<DandelionConfig>,

    /// Ephemeral PeerId rotation policy (SPEC §1.9.2 / PRV-006).
    /// `None` means no rotation — the node keeps a stable network identity.
    pub peer_id_rotation: Option<PeerIdRotationConfig>,

    /// Tor / SOCKS5 proxy transport (SPEC §1.9.3 / PRV-009, PRV-010).
    /// Only compiled when the `tor` feature flag is enabled.
    #[cfg(feature = "tor")]
    pub tor: Option<TorConfig>,

    /// ERLAY set-reconciliation parameters (SPEC §8.3 / ERL-008).
    /// Only compiled when the `erlay` feature flag is enabled.
    #[cfg(feature = "erlay")]
    pub erlay: Option<ErlayConfig>,

    /// Adaptive backpressure thresholds for the priority outbound queue (PRI-005..PRI-008).
    /// `None` means backpressure is disabled and all messages are treated equally.
    pub backpressure: Option<BackpressureConfig>,

    /// CON-004: seconds between keepalive probes. `None` falls back to
    /// [`PING_INTERVAL_SECS`](crate::constants::PING_INTERVAL_SECS) (30 s).
    /// Integration tests typically set this to 1-2 s for fast timeout coverage.
    pub keepalive_ping_interval_secs: Option<u64>,

    /// CON-004: maximum seconds since last successful probe before disconnecting the peer.
    /// `None` falls back to [`PEER_TIMEOUT_SECS`](crate::constants::PEER_TIMEOUT_SECS) (90 s).
    pub keepalive_peer_timeout_secs: Option<u64>,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_P2P_PORT)),
            peer_id: PeerId::default(),
            network_id: Bytes32::default(),
            network: Network::default_mainnet(),
            dns_seed_timeout: Duration::from_secs(DEFAULT_DNS_SEED_TIMEOUT_SECS),
            dns_seed_batch_size: DEFAULT_DNS_SEED_BATCH_SIZE,
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
            keepalive_ping_interval_secs: None,
            keepalive_peer_timeout_secs: None,
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
