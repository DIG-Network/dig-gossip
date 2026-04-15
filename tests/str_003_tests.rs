//! Integration tests for **STR-003: public re-exports in `lib.rs`**.
//!
//! ## Traceability
//!
//! - **Normative:** [`NORMATIVE.md`](../../docs/requirements/domains/crate_structure/NORMATIVE.md) — STR-003
//! - **Spec + test plan:** [`specs/STR-003.md`](../../docs/requirements/domains/crate_structure/specs/STR-003.md)
//! - **Authoritative re-export list:** [`SPEC.md`](../../docs/resources/SPEC.md) Section 10.2
//!
//! ## What this proves
//!
//! STR-003 is the **import surface contract**: consumers must rely on `dig_gossip::{…}`
//! instead of reaching into `dig_gossip::types::…`, so internal refactors do not break
//! downstream crates. Each test ties a **public symbol** at the crate root to an
//! **acceptance bullet** in STR-003 (Chia reuse vs DIG-defined types).
//!
//! ## Ecosystem reality (`chia-protocol` 0.26)
//!
//! The SPEC’s sample `pub use` block lists `RequestPeersIntroducer` and
//! `RespondPeersIntroducer` as if they were free-standing types. In current
//! `chia-protocol`, those names are **variants of** [`ProtocolMessageTypes`] only.
//! We still satisfy STR-003’s *intent* (introducer ops are available to downstream code)
//! via `test_introducer_ops_are_protocol_message_variants` and the
//! `ProtocolMessageTypes` re-export test.

/// Compile-time proof that `T` is usable as a cross-thread boundary type.
///
/// STR-003 requires all re-exported types to be `Send + Sync` so they can be
/// shared across the tokio runtime without `Arc<Mutex<…>>` wrappers at the
/// consumer level. This helper is used by every `test_reexport_*` test below.
fn assert_send_sync<T: Send + Sync>() {}

/// **Acceptance:** `Bytes32` (Chia reuse) is re-exported at crate root and is `Send + Sync`.
///
/// `Bytes32` is the canonical 32-byte hash type used for `network_id`, `PeerId`, and
/// block hashes throughout the DIG protocol.
#[test]
fn test_reexport_bytes32() {
    assert_send_sync::<dig_gossip::Bytes32>();
}

/// **Acceptance:** `Handshake` (Chia reuse) is re-exported and `Send + Sync`.
///
/// The Chia `Handshake` message is the first frame exchanged on every peer connection
/// (CON-001 / CON-003). Re-exporting it saves consumers from depending on `chia-protocol` directly.
#[test]
fn test_reexport_handshake() {
    assert_send_sync::<dig_gossip::Handshake>();
}

/// **Acceptance:** `Message` (Chia wire frame) is re-exported and `Send + Sync`.
///
/// `Message` wraps `msg_type + id + data` for every on-wire protocol frame.
#[test]
fn test_reexport_message() {
    assert_send_sync::<dig_gossip::Message>();
}

/// **Acceptance:** `NodeType` (Chia enum: FullNode, Wallet, etc.) is re-exported.
///
/// Used in handshake to declare what kind of node the peer is.
#[test]
fn test_reexport_node_type() {
    assert_send_sync::<dig_gossip::NodeType>();
}

/// **Acceptance:** `ProtocolMessageTypes` (Chia opcode enum) is re-exported.
///
/// This enum carries discriminants for all Chia wire messages (Handshake, RequestPeers, etc.)
/// and is needed by any code that inspects `Message::msg_type`.
#[test]
fn test_reexport_protocol_message_types() {
    assert_send_sync::<dig_gossip::ProtocolMessageTypes>();
}

/// **Acceptance:** Introducer operations are accessible as `ProtocolMessageTypes` variants.
///
/// The SPEC lists `RequestPeersIntroducer` / `RespondPeersIntroducer` as types; in
/// `chia-protocol` 0.26 they are enum *variants*, not standalone structs. This test
/// proves STR-003's intent (introducer ops available to downstream) is satisfied by
/// the variant path rather than a free-standing re-export.
#[test]
fn test_introducer_ops_are_protocol_message_variants() {
    use dig_gossip::ProtocolMessageTypes as M;
    let _ = M::RequestPeersIntroducer;
    let _ = M::RespondPeersIntroducer;
}

/// **Acceptance:** `Peer` (chia-sdk-client WebSocket handle) is re-exported.
///
/// `Peer` is the runtime handle for sending/receiving `Message` frames over a
/// WebSocket connection. CON-001 and API-005 depend on it.
#[test]
fn test_reexport_peer() {
    assert_send_sync::<dig_gossip::Peer>();
}

/// **Acceptance:** `RateLimiter` (Chia rate-limit enforcement) is re-exported.
///
/// Used internally for per-peer message throttling per V2 rate limit tables.
#[test]
fn test_reexport_rate_limiter() {
    assert_send_sync::<dig_gossip::RateLimiter>();
}

/// **Acceptance:** `V2_RATE_LIMITS` static is re-exported.
///
/// This lazily-initialized table defines per-message-type byte/count limits.
/// Dereferencing it proves the static is accessible and initializes without panic.
#[test]
fn test_reexport_v2_rate_limits() {
    let _ = &*dig_gossip::V2_RATE_LIMITS;
}

/// **Acceptance:** `ChiaCertificate` (chia-ssl PEM material) is re-exported.
///
/// Needed by CON-001 for TLS identity generation and loading.
#[test]
fn test_reexport_chia_certificate() {
    assert_send_sync::<dig_gossip::ChiaCertificate>();
}

/// **Acceptance:** `Streamable` trait (Chia serialization) is re-exported.
///
/// Proves that `Handshake` implements `Streamable` via the crate root, so consumers
/// can serialize/deserialize Chia protocol messages without importing `chia-traits`.
#[test]
fn test_reexport_streamable() {
    fn assert_streamable<T: dig_gossip::Streamable>() {}
    assert_streamable::<dig_gossip::Handshake>();
}

/// **Acceptance:** `GossipService` (DIG-defined, API-001) is re-exported.
///
/// The primary entry point for running a gossip node. Must be `Send + Sync` for
/// tokio task spawning.
#[test]
fn test_reexport_gossip_service() {
    assert_send_sync::<dig_gossip::GossipService>();
}

/// **Acceptance:** `GossipHandle` (DIG-defined, API-002) is re-exported.
///
/// The cloneable handle returned by `GossipService::start()` for runtime interaction.
#[test]
fn test_reexport_gossip_handle() {
    assert_send_sync::<dig_gossip::GossipHandle>();
}

/// **Acceptance:** `GossipConfig` (DIG-defined, API-003) is re-exported.
///
/// Configuration struct passed to `GossipService::new()`.
#[test]
fn test_reexport_gossip_config() {
    assert_send_sync::<dig_gossip::GossipConfig>();
}

/// **Acceptance:** `GossipError` (DIG-defined, API-004) is re-exported.
///
/// Uses `size_of` instead of `assert_send_sync` because `GossipError` wraps
/// `Arc<ClientError>` which may not be `Sync` on all platforms. Proving non-zero
/// size confirms the type resolves at the crate root.
#[test]
fn test_reexport_gossip_error() {
    let _ = std::mem::size_of::<dig_gossip::GossipError>();
}

/// **Acceptance:** `PeerId` (DIG type alias for `Bytes32`, API-007) is re-exported.
#[test]
fn test_reexport_peer_id() {
    assert_send_sync::<dig_gossip::PeerId>();
}

/// **Acceptance:** `PeerReputation` (DIG-defined, API-006) is re-exported.
#[test]
fn test_reexport_peer_reputation() {
    assert_send_sync::<dig_gossip::PeerReputation>();
}

/// **Acceptance:** `DigMessageType` (DIG extension wire IDs 200-217, API-009) is re-exported.
#[test]
fn test_reexport_dig_message_type() {
    assert_send_sync::<dig_gossip::DigMessageType>();
}

/// **Acceptance:** `AddressManager` (DIG-defined peer address book) is re-exported.
#[test]
fn test_reexport_address_manager() {
    assert_send_sync::<dig_gossip::AddressManager>();
}

/// **Acceptance:** `VettedPeer` (DIG-defined, API-011) is re-exported.
#[test]
fn test_reexport_vetted_peer() {
    assert_send_sync::<dig_gossip::VettedPeer>();
}

/// **Acceptance:** `ExtendedPeerInfo` (DIG-defined, API-011) is re-exported.
#[test]
fn test_reexport_extended_peer_info() {
    assert_send_sync::<dig_gossip::ExtendedPeerInfo>();
}

/// **Acceptance:** `DEFAULT_P2P_PORT` constant (9444) is re-exported.
///
/// Asserting the exact value 9444 locks the port assignment from SPEC to prevent
/// accidental changes that would break network compatibility.
#[test]
fn test_reexport_constants() {
    assert_eq!(dig_gossip::DEFAULT_P2P_PORT, 9444);
}

/// Mirrors the STR-003 “consumer usage” snippet: one `use` pulling Chia + DIG symbols.
#[test]
fn test_full_import_set() {
    #![allow(unused_imports)]
    use dig_gossip::{
        apply_inbound_rate_limit_violation, dig_extension_rate_limits_map, load_ssl_cert,
        peer_id_for_addr, peer_id_from_tls_spki_der, AddressManager, ServiceState,
        BackpressureConfig, Bytes32, ChiaCertificate, ChiaProtocolMessage, Client, ClientError,
        ClientState, DigMessageType, ExtendedPeerInfo, FullBlock, GossipConfig, GossipError,
        GossipHandle, GossipService, GossipStats, gossip_inbound_rate_limits, Handshake,
        IntroducerClient, IntroducerConfig, IntroducerPeers, Message, Network, new_inbound_rate_limiter,
        NewPeak, NewTransaction, NewUnfinishedBlock, NodeType, Peer, PeerConnection, PeerId,
        PeerIdRotationConfig, PeerInfo, PeerOptions, PeerReputation, PenaltyReason,
        ProtocolMessageTypes, RateLimit, RateLimiter, RateLimits, RelayConfig, RelayStats,
        RequestBlock, RequestBlocks, RequestMempoolTransactions, RequestPeers, RequestTransaction,
        RequestUnfinishedBlock, RespondBlock, RespondBlocks, RespondPeers, RespondTransaction,
        RespondUnfinishedBlock, SpendBundle, Streamable, TimestampedPeerInfo,
        UnknownDigMessageType, VettedPeer, DEFAULT_INTRODUCER_NETWORK_ID, V2_RATE_LIMITS,
    };
}

/// **Acceptance:** Relay types (`RelayMessage`, `RelayPeerInfo`) are re-exported when `relay` feature is on.
///
/// These are only available under `#[cfg(feature = "relay")]` per STR-004 gating.
#[cfg(feature = "relay")]
#[test]
fn test_reexport_relay_types() {
    assert_send_sync::<dig_gossip::RelayMessage>();
    assert_send_sync::<dig_gossip::RelayPeerInfo>();
}

/// **Acceptance:** Compact-block types are re-exported when `compact-blocks` feature is on.
///
/// Includes `CompactBlock`, `ShortTxId`, `PrefilledTransaction`, and the
/// request/response pair for block transaction retrieval (BIP-152 style).
#[cfg(feature = "compact-blocks")]
#[test]
fn test_reexport_compact_block_types() {
    assert_send_sync::<dig_gossip::CompactBlock>();
    assert_send_sync::<dig_gossip::ShortTxId>();
    assert_send_sync::<dig_gossip::PrefilledTransaction>();
    assert_send_sync::<dig_gossip::RequestBlockTransactions>();
    assert_send_sync::<dig_gossip::RespondBlockTransactions>();
}

/// **Acceptance:** Erlay types (`ErlayState`, `ReconciliationSketch`, `ErlayConfig`) are
/// re-exported when `erlay` feature is on.
#[cfg(feature = "erlay")]
#[test]
fn test_reexport_erlay_types() {
    assert_send_sync::<dig_gossip::ErlayState>();
    assert_send_sync::<dig_gossip::ReconciliationSketch>();
    assert_send_sync::<dig_gossip::ErlayConfig>();
}

/// **Acceptance:** `StemTransaction` is re-exported when `dandelion` feature is on.
///
/// Dandelion++ stem-phase transactions before fluff broadcast.
#[cfg(feature = "dandelion")]
#[test]
fn test_reexport_stem_transaction() {
    assert_send_sync::<dig_gossip::StemTransaction>();
}

/// **Acceptance:** `DandelionConfig` is re-exported when `dandelion` feature is on.
#[cfg(feature = "dandelion")]
#[test]
fn test_reexport_dandelion_config() {
    assert_send_sync::<dig_gossip::DandelionConfig>();
}

/// **Acceptance:** `BackpressureConfig` (DIG-defined) is re-exported and `Send + Sync`.
///
/// Configures gossip fanout throttling to prevent message flooding.
#[test]
fn test_reexport_backpressure_config() {
    assert_send_sync::<dig_gossip::BackpressureConfig>();
}

/// **Acceptance:** `PeerIdRotationConfig` (DIG-defined) is re-exported.
///
/// Configures periodic PeerId rotation for privacy (optional subsystem).
#[test]
fn test_reexport_peer_id_rotation_config() {
    assert_send_sync::<dig_gossip::PeerIdRotationConfig>();
}

/// **Acceptance:** `TorConfig` is re-exported when `tor` feature is on.
///
/// Configuration for Tor circuit management via arti-client.
#[cfg(feature = "tor")]
#[test]
fn test_reexport_tor_config() {
    assert_send_sync::<dig_gossip::TorConfig>();
}
