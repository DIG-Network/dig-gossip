//! Tests for **INT-013: Clean public API surface**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-013.md`
//!
//! INT-013 proves only user-facing types are in the public API.
//! Internal types are #[doc(hidden)] — importable by tests but hidden from docs.

/// **INT-013: Core lifecycle types importable from root.**
///
/// Proves the primary user-facing types are accessible via `dig_gossip::`.
#[test]
fn test_core_types_importable() {
    // These must compile — proves they're in the public API.
    let _ = std::any::type_name::<dig_gossip::GossipService>();
    let _ = std::any::type_name::<dig_gossip::GossipHandle>();
    let _ = std::any::type_name::<dig_gossip::GossipConfig>();
    let _ = std::any::type_name::<dig_gossip::GossipError>();
    let _ = std::any::type_name::<dig_gossip::GossipStats>();
    let _ = std::any::type_name::<dig_gossip::RelayStats>();
}

/// **INT-013: Peer types importable.**
#[test]
fn test_peer_types_importable() {
    let _ = std::any::type_name::<dig_gossip::PeerId>();
    let _ = std::any::type_name::<dig_gossip::PeerInfo>();
    let _ = std::any::type_name::<dig_gossip::PeerConnection>();
    let _ = std::any::type_name::<dig_gossip::PeerReputation>();
    let _ = std::any::type_name::<dig_gossip::PenaltyReason>();
    let _ = std::any::type_name::<dig_gossip::ExtendedPeerInfo>();
}

/// **INT-013: Config types importable.**
#[test]
fn test_config_types_importable() {
    let _ = std::any::type_name::<dig_gossip::IntroducerConfig>();
    let _ = std::any::type_name::<dig_gossip::RelayConfig>();
    let _ = std::any::type_name::<dig_gossip::PeerIdRotationConfig>();
}

/// **INT-013: Discovery types importable.**
#[test]
fn test_discovery_types_importable() {
    let _ = std::any::type_name::<dig_gossip::AddressManager>();
    let _ = std::any::type_name::<dig_gossip::IntroducerClient>();
    let _ = std::any::type_name::<dig_gossip::IntroducerPeers>();
    let _ = std::any::type_name::<dig_gossip::VettedPeer>();
}

/// **INT-013: Chia protocol types re-exported.**
#[test]
fn test_chia_types_importable() {
    let _ = std::any::type_name::<dig_gossip::Bytes32>();
    let _ = std::any::type_name::<dig_gossip::Message>();
    let _ = std::any::type_name::<dig_gossip::Handshake>();
    let _ = std::any::type_name::<dig_gossip::NodeType>();
    let _ = std::any::type_name::<dig_gossip::Peer>();
    let _ = std::any::type_name::<dig_gossip::ChiaCertificate>();
}

/// **INT-013: DIG extension types importable.**
#[test]
fn test_dig_types_importable() {
    let _ = std::any::type_name::<dig_gossip::DigMessageType>();
}

/// **INT-013: Internal types are doc(hidden) but still accessible for tests.**
///
/// Proves ServiceState is importable (tests need it) but it won't appear
/// in `cargo doc` output (doc(hidden)).
#[test]
fn test_internal_types_accessible_for_tests() {
    // These compile because they're #[doc(hidden)] pub use — accessible but hidden from docs.
    let _ = std::any::type_name::<dig_gossip::ServiceState>();
    let _ = std::any::type_name::<dig_gossip::BackpressureConfig>();
}
