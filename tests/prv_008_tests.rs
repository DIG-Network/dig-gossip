//! **PRV-008 — Rotation opt-out**
//!
//! Normative: [`docs/requirements/domains/privacy/specs/PRV-008.md`](../docs/requirements/domains/privacy/specs/PRV-008.md)
//! Master SPEC: [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 1.9.2 (Ephemeral PeerId)
//!
//! ## What this file proves
//!
//! `PeerIdRotationConfig::is_rotation_disabled()` correctly identifies when
//! rotation is effectively disabled:
//! - `rotation_interval_secs = 0` disables rotation regardless of `enabled`.
//! - `enabled = false` disables rotation regardless of interval.
//! - Both conditions active also disables rotation.
//! - Default config (enabled + 86400 interval) does NOT disable rotation.

use dig_gossip::PeerIdRotationConfig;

/// `rotation_interval_secs = 0` disables rotation even when `enabled = true`.
///
/// SPEC §1.9.2: zero interval is nonsensical and MUST be treated as "rotation
/// disabled". This is the primary opt-out mechanism for bootstrap and seed nodes.
#[test]
fn test_interval_zero_disables_rotation() {
    let cfg = PeerIdRotationConfig {
        enabled: true,
        rotation_interval_secs: 0,
        reconnect_on_rotation: true,
    };
    assert!(
        cfg.is_rotation_disabled(),
        "rotation_interval_secs=0 must disable rotation"
    );
}

/// `enabled = false` disables rotation even with a valid interval.
///
/// The `enabled` flag is the explicit administrative switch to turn off rotation.
#[test]
fn test_enabled_false_disables_rotation() {
    let cfg = PeerIdRotationConfig {
        enabled: false,
        rotation_interval_secs: 86400,
        reconnect_on_rotation: true,
    };
    assert!(
        cfg.is_rotation_disabled(),
        "enabled=false must disable rotation"
    );
}

/// Both `enabled = false` and `rotation_interval_secs = 0` — doubly disabled.
#[test]
fn test_both_disabled_conditions() {
    let cfg = PeerIdRotationConfig {
        enabled: false,
        rotation_interval_secs: 0,
        reconnect_on_rotation: true,
    };
    assert!(
        cfg.is_rotation_disabled(),
        "both conditions false must disable rotation"
    );
}

/// The default config (enabled + 86400) is NOT disabled.
///
/// Proves that `is_rotation_disabled()` returns `false` for the standard
/// production configuration — rotation is active by default.
#[test]
fn test_default_config_rotation_enabled() {
    let cfg = PeerIdRotationConfig::default();
    assert!(
        !cfg.is_rotation_disabled(),
        "default PeerIdRotationConfig must NOT be disabled"
    );
}

/// A custom interval (non-zero) with `enabled = true` is NOT disabled.
#[test]
fn test_custom_interval_not_disabled() {
    let cfg = PeerIdRotationConfig {
        enabled: true,
        rotation_interval_secs: 3600,
        reconnect_on_rotation: false,
    };
    assert!(
        !cfg.is_rotation_disabled(),
        "enabled=true with non-zero interval must NOT be disabled"
    );
}

/// Very small interval (1 second) is valid and NOT disabled.
///
/// PRV-006 spec: "Very small rotation_interval_secs values (e.g., 1 second)
/// are technically valid but impractical; no minimum enforcement is required
/// at the config level."
#[test]
fn test_small_interval_not_disabled() {
    let cfg = PeerIdRotationConfig {
        enabled: true,
        rotation_interval_secs: 1,
        reconnect_on_rotation: true,
    };
    assert!(
        !cfg.is_rotation_disabled(),
        "interval=1 with enabled=true must NOT be disabled"
    );
}

/// `reconnect_on_rotation` does not affect disabled status.
///
/// The reconnect flag is orthogonal to whether rotation happens at all;
/// it only controls behavior during a rotation event.
#[test]
fn test_reconnect_flag_does_not_affect_disabled() {
    let cfg_a = PeerIdRotationConfig {
        enabled: true,
        rotation_interval_secs: 86400,
        reconnect_on_rotation: false,
    };
    let cfg_b = PeerIdRotationConfig {
        enabled: true,
        rotation_interval_secs: 86400,
        reconnect_on_rotation: true,
    };
    assert_eq!(
        cfg_a.is_rotation_disabled(),
        cfg_b.is_rotation_disabled(),
        "reconnect_on_rotation must not affect is_rotation_disabled()"
    );
    assert!(
        !cfg_a.is_rotation_disabled(),
        "both configs must have rotation enabled"
    );
}
