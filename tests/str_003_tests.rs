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
fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn test_reexport_bytes32() {
    assert_send_sync::<dig_gossip::Bytes32>();
}

#[test]
fn test_reexport_handshake() {
    assert_send_sync::<dig_gossip::Handshake>();
}

#[test]
fn test_reexport_message() {
    assert_send_sync::<dig_gossip::Message>();
}

#[test]
fn test_reexport_node_type() {
    assert_send_sync::<dig_gossip::NodeType>();
}

#[test]
fn test_reexport_protocol_message_types() {
    assert_send_sync::<dig_gossip::ProtocolMessageTypes>();
}

#[test]
fn test_introducer_ops_are_protocol_message_variants() {
    use dig_gossip::ProtocolMessageTypes as M;
    let _ = M::RequestPeersIntroducer;
    let _ = M::RespondPeersIntroducer;
}

#[test]
fn test_reexport_peer() {
    assert_send_sync::<dig_gossip::Peer>();
}

#[test]
fn test_reexport_rate_limiter() {
    assert_send_sync::<dig_gossip::RateLimiter>();
}

#[test]
fn test_reexport_v2_rate_limits() {
    let _ = &*dig_gossip::V2_RATE_LIMITS;
}

#[test]
fn test_reexport_chia_certificate() {
    assert_send_sync::<dig_gossip::ChiaCertificate>();
}

#[test]
fn test_reexport_streamable() {
    fn assert_streamable<T: dig_gossip::Streamable>() {}
    assert_streamable::<dig_gossip::Handshake>();
}

#[test]
fn test_reexport_gossip_service() {
    assert_send_sync::<dig_gossip::GossipService>();
}

#[test]
fn test_reexport_gossip_handle() {
    assert_send_sync::<dig_gossip::GossipHandle>();
}

#[test]
fn test_reexport_gossip_config() {
    assert_send_sync::<dig_gossip::GossipConfig>();
}

#[test]
fn test_reexport_gossip_error() {
    let _ = std::mem::size_of::<dig_gossip::GossipError>();
}

#[test]
fn test_reexport_peer_id() {
    assert_send_sync::<dig_gossip::PeerId>();
}

#[test]
fn test_reexport_peer_reputation() {
    assert_send_sync::<dig_gossip::PeerReputation>();
}

#[test]
fn test_reexport_dig_message_type() {
    assert_send_sync::<dig_gossip::DigMessageType>();
}

#[test]
fn test_reexport_address_manager() {
    assert_send_sync::<dig_gossip::AddressManager>();
}

#[test]
fn test_reexport_vetted_peer() {
    assert_send_sync::<dig_gossip::VettedPeer>();
}

#[test]
fn test_reexport_constants() {
    assert_eq!(dig_gossip::DEFAULT_P2P_PORT, 9444);
}

/// Mirrors the STR-003 “consumer usage” snippet: one `use` pulling Chia + DIG symbols.
#[test]
fn test_full_import_set() {
    #![allow(unused_imports)]
    use dig_gossip::{
        load_ssl_cert, AddressManager, BackpressureConfig, Bytes32, ChiaCertificate,
        ChiaProtocolMessage, Client, ClientError, ClientState, DigMessageType, FullBlock,
        GossipConfig, GossipError, GossipHandle, GossipService, GossipStats, Handshake,
        IntroducerClient, IntroducerConfig, IntroducerPeers, Message, Network, NewPeak,
        NewTransaction, NewUnfinishedBlock, NodeType, Peer, PeerConnection, PeerId,
        PeerIdRotationConfig, PeerInfo, PeerOptions, PeerReputation, PenaltyReason,
        ProtocolMessageTypes, RateLimit, RateLimiter, RateLimits, RelayConfig, RelayStats,
        RequestBlock, RequestBlocks, RequestMempoolTransactions, RequestPeers, RequestTransaction,
        RequestUnfinishedBlock, RespondBlock, RespondBlocks, RespondPeers, RespondTransaction,
        RespondUnfinishedBlock, SpendBundle, Streamable, TimestampedPeerInfo, VettedPeer,
        V2_RATE_LIMITS,
    };
}

#[cfg(feature = "relay")]
#[test]
fn test_reexport_relay_types() {
    assert_send_sync::<dig_gossip::RelayMessage>();
    assert_send_sync::<dig_gossip::RelayPeerInfo>();
}

#[cfg(feature = "compact-blocks")]
#[test]
fn test_reexport_compact_block_types() {
    assert_send_sync::<dig_gossip::CompactBlock>();
    assert_send_sync::<dig_gossip::ShortTxId>();
    assert_send_sync::<dig_gossip::PrefilledTransaction>();
    assert_send_sync::<dig_gossip::RequestBlockTransactions>();
    assert_send_sync::<dig_gossip::RespondBlockTransactions>();
}

#[cfg(feature = "erlay")]
#[test]
fn test_reexport_erlay_types() {
    assert_send_sync::<dig_gossip::ErlayState>();
    assert_send_sync::<dig_gossip::ReconciliationSketch>();
    assert_send_sync::<dig_gossip::ErlayConfig>();
}

#[cfg(feature = "dandelion")]
#[test]
fn test_reexport_stem_transaction() {
    assert_send_sync::<dig_gossip::StemTransaction>();
}

#[cfg(feature = "dandelion")]
#[test]
fn test_reexport_dandelion_config() {
    assert_send_sync::<dig_gossip::DandelionConfig>();
}

#[test]
fn test_reexport_backpressure_config() {
    assert_send_sync::<dig_gossip::BackpressureConfig>();
}

#[test]
fn test_reexport_peer_id_rotation_config() {
    assert_send_sync::<dig_gossip::PeerIdRotationConfig>();
}

#[cfg(feature = "tor")]
#[test]
fn test_reexport_tor_config() {
    assert_send_sync::<dig_gossip::TorConfig>();
}
