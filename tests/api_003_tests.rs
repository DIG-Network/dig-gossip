//! Integration tests for **API-003: `GossipConfig` struct field set and defaults**.
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`API-003.md`](../docs/requirements/domains/crate_api/specs/API-003.md)
//!   (tables “Default Values”, “Verification / Test Plan”)
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/crate_api/NORMATIVE.md)
//! - **Master SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §2.10
//!
//! ## Proof strategy
//!
//! API-003 is a **shape + defaults contract**: every field named in the spec must exist, use the
//! declared Rust types (Chia types where specified), and `Default` must match SPEC constants.
//! Optional subsystem fields are **Cargo feature–gated** to match STR-004 / API-003 (e.g. `dandelion`,
//! `erlay`, `tor`); tests that exercise those fields use `#[cfg(feature = "...")]` so
//! `cargo test --no-default-features` builds still succeed.

mod common;

use std::net::SocketAddr;

#[cfg(feature = "dandelion")]
use dig_gossip::DandelionConfig;
#[cfg(feature = "erlay")]
use dig_gossip::ErlayConfig;
#[cfg(feature = "tor")]
use dig_gossip::TorConfig;
use dig_gossip::{
    BackpressureConfig, Bytes32, GossipConfig, IntroducerConfig, Network, PeerId,
    PeerIdRotationConfig, PeerOptions, RelayConfig, DEFAULT_MAX_SEEN_MESSAGES, DEFAULT_P2P_PORT,
    DEFAULT_TARGET_OUTBOUND_COUNT,
};

// ----------------------------------------------------------------------------- test plan: all fields

/// **Row:** `test_config_all_fields_exist` — construct with every field set (including `Some` for
/// nested option types where applicable).
///
/// **Why it proves API-003:** acceptance criterion “Construct GossipConfig with all fields populated;
/// compiles and all fields accessible”. Reading each field back ties the struct literal to the
/// public API surface documented in API-003 / SPEC §2.10.
#[test]
fn test_config_all_fields_exist() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let bootstrap: SocketAddr = "192.0.2.50:9444".parse().expect("parse bootstrap");

    let cfg = GossipConfig {
        listen_addr: "192.0.2.1:9000".parse().expect("parse listen"),
        peer_id: PeerId::from([9u8; 32]),
        network_id: common::test_network_id(),
        network: common::test_network(),
        target_outbound_count: 3,
        max_connections: 40,
        bootstrap_peers: vec![bootstrap],
        introducer: Some(IntroducerConfig::default()),
        relay: Some(RelayConfig::default()),
        cert_path: dir.path().join("full.crt").to_string_lossy().into_owned(),
        key_path: dir.path().join("full.key").to_string_lossy().into_owned(),
        peer_connect_interval: 5,
        gossip_fanout: 4,
        max_seen_messages: 99,
        peers_file_path: dir.path().join("addrman.dat"),
        peer_options: PeerOptions::default(),
        #[cfg(feature = "dandelion")]
        dandelion: Some(DandelionConfig::default()),
        peer_id_rotation: Some(PeerIdRotationConfig::default()),
        #[cfg(feature = "tor")]
        tor: Some(TorConfig::default()),
        #[cfg(feature = "erlay")]
        erlay: Some(ErlayConfig::default()),
        backpressure: Some(BackpressureConfig::default()),
        keepalive_ping_interval_secs: Some(7),
        keepalive_peer_timeout_secs: Some(42),
    };

    assert_eq!(cfg.listen_addr, "192.0.2.1:9000".parse().unwrap());
    assert_eq!(cfg.peer_id, PeerId::from([9u8; 32]));
    assert_eq!(cfg.network_id, common::test_network_id());
    assert_eq!(cfg.target_outbound_count, 3);
    assert_eq!(cfg.max_connections, 40);
    assert_eq!(cfg.bootstrap_peers, vec![bootstrap]);
    assert!(cfg.introducer.is_some());
    assert!(cfg.relay.is_some());
    assert!(cfg.cert_path.ends_with("full.crt"));
    assert_eq!(cfg.peer_connect_interval, 5);
    assert_eq!(cfg.gossip_fanout, 4);
    assert_eq!(cfg.max_seen_messages, 99);
    assert_eq!(cfg.peers_file_path, dir.path().join("addrman.dat"));

    #[cfg(feature = "dandelion")]
    assert!(cfg.dandelion.is_some());
    assert!(cfg.peer_id_rotation.is_some());
    #[cfg(feature = "tor")]
    assert!(cfg.tor.is_some());
    #[cfg(feature = "erlay")]
    assert!(cfg.erlay.is_some());
    assert!(cfg.backpressure.is_some());
    assert_eq!(cfg.keepalive_ping_interval_secs, Some(7));
    assert_eq!(cfg.keepalive_peer_timeout_secs, Some(42));
}

// --------------------------------------------------------------------------- test plan: default rows

/// **Row:** `test_config_default_listen_addr` — `Default::default().listen_addr == 0.0.0.0:9444`.
#[test]
fn test_config_default_listen_addr() {
    let c = GossipConfig::default();
    assert_eq!(
        c.listen_addr,
        SocketAddr::from(([0, 0, 0, 0], DEFAULT_P2P_PORT)),
        "must match SPEC DEFAULT_P2P_PORT ({DEFAULT_P2P_PORT}) on all interfaces"
    );
}

/// **Row:** `test_config_default_target_outbound` — default target outbound count is 8.
#[test]
fn test_config_default_target_outbound() {
    assert_eq!(
        GossipConfig::default().target_outbound_count,
        DEFAULT_TARGET_OUTBOUND_COUNT
    );
}

/// **Row:** `test_config_default_max_connections` — default cap is 50 (SPEC §2.10 / API-003 table).
#[test]
fn test_config_default_max_connections() {
    assert_eq!(GossipConfig::default().max_connections, 50);
}

/// **Row:** `test_config_default_peer_connect_interval` — default 10 seconds.
#[test]
fn test_config_default_peer_connect_interval() {
    assert_eq!(GossipConfig::default().peer_connect_interval, 10);
}

/// **Row:** `test_config_default_gossip_fanout` — default fanout 8.
#[test]
fn test_config_default_gossip_fanout() {
    assert_eq!(GossipConfig::default().gossip_fanout, 8);
}

/// **Row:** `test_config_default_max_seen_messages` — default 100_000 (`DEFAULT_MAX_SEEN_MESSAGES`).
#[test]
fn test_config_default_max_seen_messages() {
    assert_eq!(
        GossipConfig::default().max_seen_messages,
        DEFAULT_MAX_SEEN_MESSAGES
    );
}

/// **Row:** `test_config_optional_introducer` — `None` is valid.
#[test]
fn test_config_optional_introducer() {
    let c = GossipConfig::default();
    assert!(c.introducer.is_none());
}

/// **Row:** `test_config_optional_relay`.
#[test]
fn test_config_optional_relay() {
    let c = GossipConfig::default();
    assert!(c.relay.is_none());
}

/// **`Default` for feature-gated optional blocks:** when a feature is enabled, defaults stay `None`
/// so identity/network paths remain explicit (API-003 implementation notes).
#[test]
fn test_config_default_optional_subsystems_none() {
    let c = GossipConfig::default();
    #[cfg(feature = "dandelion")]
    assert!(c.dandelion.is_none());
    assert!(c.peer_id_rotation.is_none());
    #[cfg(feature = "tor")]
    assert!(c.tor.is_none());
    #[cfg(feature = "erlay")]
    assert!(c.erlay.is_none());
    assert!(c.backpressure.is_none());
    assert!(c.keepalive_ping_interval_secs.is_none());
    assert!(c.keepalive_peer_timeout_secs.is_none());
}

/// **Row:** `test_config_peer_options_type` — field is `chia_sdk_client::PeerOptions`.
///
/// Assignment to a locally typed binding is a compile-time + link-time proof on stable Rust (no
/// `TypeId::of_val`, which is not available on MSRV here).
#[test]
fn test_config_peer_options_type() {
    let c = GossipConfig::default();
    let _: PeerOptions = c.peer_options;
}

/// **Row:** `test_config_network_id_type` — `network_id` is `chia_protocol::Bytes32`.
#[test]
fn test_config_network_id_type() {
    let c = GossipConfig::default();
    let _: Bytes32 = c.network_id;
}

/// **`network` field** uses upstream [`Network`] (DNS / introducer policy); default picks mainnet
/// baseline per [`GossipConfig`] `Default` impl — we only assert type + accessibility here.
#[test]
fn test_config_network_field_is_network_type() {
    let c = GossipConfig::default();
    let _: Network = c.network;
}

/// When `tor` is enabled, `GossipConfig` must carry `tor: Option<TorConfig>` (API-003 sketch).
#[cfg(feature = "tor")]
#[test]
fn test_config_tor_slot_compiles_with_tor_feature() {
    let dir = common::test_temp_dir();
    let mut c = common::test_gossip_config(dir.path());
    c.tor = Some(TorConfig::default());
    assert!(c.tor.is_some());
}
