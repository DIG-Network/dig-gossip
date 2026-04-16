//! **PRV-006 — PeerIdRotationConfig defaults**
//!
//! Normative: [`docs/requirements/domains/privacy/specs/PRV-006.md`](../docs/requirements/domains/privacy/specs/PRV-006.md)
//! Master SPEC: [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 1.9.2 (Ephemeral PeerId)
//!
//! ## What this file proves
//!
//! The `PeerIdRotationConfig` struct has SPEC-mandated defaults:
//! `enabled = true`, `rotation_interval_secs = 86400` (24 hours),
//! `reconnect_on_rotation = true`. This config type is always compiled
//! (no feature gate) so all nodes can opt in/out of identity rotation.

use dig_gossip::PeerIdRotationConfig;

/// SPEC §1.9.2 default: `enabled = true`.
///
/// PeerId rotation is on by default so transaction origin privacy through
/// identity unlinkability is active without explicit opt-in.
#[test]
fn test_peer_id_rotation_config_enabled_default() {
    let cfg = PeerIdRotationConfig::default();
    assert!(
        cfg.enabled,
        "PeerIdRotationConfig default must be enabled=true"
    );
}

/// SPEC §1.9.2 default: `rotation_interval_secs = 86400` (24 hours).
///
/// One rotation per day balances fingerprinting resistance against the
/// operational cost of re-establishing connections.
#[test]
fn test_peer_id_rotation_config_interval_default() {
    let cfg = PeerIdRotationConfig::default();
    assert_eq!(
        cfg.rotation_interval_secs, 86400,
        "rotation_interval_secs default must be 86400 (24h)"
    );
}

/// SPEC §1.9.2 default: `reconnect_on_rotation = true`.
///
/// After generating a new TLS certificate, all peer connections are torn
/// down and re-established so every peer sees the new identity immediately.
#[test]
fn test_peer_id_rotation_config_reconnect_default() {
    let cfg = PeerIdRotationConfig::default();
    assert!(
        cfg.reconnect_on_rotation,
        "reconnect_on_rotation default must be true"
    );
}

/// All three defaults in a single assertion for regression coverage.
#[test]
fn test_peer_id_rotation_config_all_defaults() {
    let cfg = PeerIdRotationConfig::default();
    assert!(cfg.enabled);
    assert_eq!(cfg.rotation_interval_secs, 86400);
    assert!(cfg.reconnect_on_rotation);
}

/// PeerIdRotationConfig can be constructed with custom values.
#[test]
fn test_peer_id_rotation_config_custom_values() {
    let cfg = PeerIdRotationConfig {
        enabled: false,
        rotation_interval_secs: 3600,
        reconnect_on_rotation: false,
    };
    assert!(!cfg.enabled);
    assert_eq!(cfg.rotation_interval_secs, 3600);
    assert!(!cfg.reconnect_on_rotation);
}

/// PeerIdRotationConfig implements Clone and the clone is equal to the original.
#[test]
fn test_peer_id_rotation_config_clone_eq() {
    let cfg = PeerIdRotationConfig::default();
    let cloned = cfg.clone();
    assert_eq!(cfg, cloned);
}

/// PeerIdRotationConfig with reconnect_on_rotation=false still has other defaults.
#[test]
fn test_peer_id_rotation_config_reconnect_disabled() {
    let cfg = PeerIdRotationConfig {
        reconnect_on_rotation: false,
        ..PeerIdRotationConfig::default()
    };
    assert!(cfg.enabled, "enabled must remain true");
    assert_eq!(cfg.rotation_interval_secs, 86400);
    assert!(!cfg.reconnect_on_rotation);
}
