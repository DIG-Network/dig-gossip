//! Tests for **API-010: [`IntroducerConfig`] and [`RelayConfig`]**.
//!
//! ## Traceability
//!
//! - **Spec + test plan:** [`API-010.md`](../docs/requirements/domains/crate_api/specs/API-010.md)
//! - **SPEC:** [`SPEC.md`](../docs/resources/SPEC.md) §2.11–2.12
//!
//! ## Proof strategy
//!
//! Each test maps to a row in API-010’s verification table. We assert **field presence**, **`Default`**
//! values from SPEC, **`Debug`/`Clone`**, and **serde round-trips** (JSON + bincode) so configs can
//! persist to disk or remote settings without drift.

use dig_gossip::{
    IntroducerConfig, RelayConfig, DEFAULT_INTRODUCER_NETWORK_ID, PING_INTERVAL_SECS,
};

/// **Row:** `test_introducer_config_fields` — public API surface matches API-010.
#[test]
fn test_introducer_config_fields() {
    let c = IntroducerConfig {
        endpoint: "ws://introducer.test:9448".into(),
        connection_timeout_secs: 42,
        request_timeout_secs: 43,
        network_id: "DIG_TESTNET".into(),
    };
    assert_eq!(c.endpoint, "ws://introducer.test:9448");
    assert_eq!(c.connection_timeout_secs, 42);
    assert_eq!(c.request_timeout_secs, 43);
    assert_eq!(c.network_id, "DIG_TESTNET");
}

/// **Row:** `test_introducer_config_default_timeout`
#[test]
fn test_introducer_config_default_timeout() {
    let c = IntroducerConfig::default();
    assert_eq!(c.connection_timeout_secs, 10);
}

/// **Row:** `test_introducer_config_default_request_timeout`
#[test]
fn test_introducer_config_default_request_timeout() {
    let c = IntroducerConfig::default();
    assert_eq!(c.request_timeout_secs, 10);
}

/// **Row:** `test_introducer_config_default_network_id`
#[test]
fn test_introducer_config_default_network_id() {
    let c = IntroducerConfig::default();
    assert_eq!(c.network_id, DEFAULT_INTRODUCER_NETWORK_ID);
    assert_eq!(c.network_id, "DIG_MAINNET");
}

/// **Row:** `test_introducer_config_json_roundtrip`
#[test]
fn test_introducer_config_json_roundtrip() {
    let c = IntroducerConfig {
        endpoint: "ws://a:1".into(),
        ..Default::default()
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: IntroducerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

/// **Row:** `test_introducer_config_debug`
#[test]
fn test_introducer_config_debug() {
    let c = IntroducerConfig::default();
    let s = format!("{c:?}");
    assert!(s.contains("IntroducerConfig"), "{s}");
}

/// **Row:** `test_introducer_config_clone`
#[test]
fn test_introducer_config_clone() {
    let c = IntroducerConfig {
        endpoint: "ws://x".into(),
        ..Default::default()
    };
    assert_eq!(c.clone(), c);
}

/// **Acceptance:** JSON with only `endpoint` fills SPEC defaults via `#[serde(default)]`.
#[test]
fn test_introducer_config_json_partial_defaults() {
    let json = r#"{"endpoint":"ws://only"}"#;
    let c: IntroducerConfig = serde_json::from_str(json).unwrap();
    assert_eq!(c.endpoint, "ws://only");
    assert_eq!(c.connection_timeout_secs, 10);
    assert_eq!(c.request_timeout_secs, 10);
    assert_eq!(c.network_id, "DIG_MAINNET");
}

/// **Acceptance:** bincode round-trip (API-010).
#[test]
fn test_introducer_config_bincode_roundtrip() {
    let c = IntroducerConfig {
        endpoint: "ws://bin".into(),
        ..Default::default()
    };
    let bytes = bincode::serialize(&c).unwrap();
    let back: IntroducerConfig = bincode::deserialize(&bytes).unwrap();
    assert_eq!(back, c);
}

/// **Row:** `test_relay_config_fields`
#[test]
fn test_relay_config_fields() {
    let r = RelayConfig {
        endpoint: "wss://relay.test:9450".into(),
        enabled: false,
        connection_timeout_secs: 9,
        reconnect_delay_secs: 3,
        max_reconnect_attempts: 7,
        ping_interval_secs: 15,
        prefer_relay: true,
    };
    assert_eq!(r.endpoint, "wss://relay.test:9450");
    assert!(!r.enabled);
    assert_eq!(r.connection_timeout_secs, 9);
    assert_eq!(r.reconnect_delay_secs, 3);
    assert_eq!(r.max_reconnect_attempts, 7);
    assert_eq!(r.ping_interval_secs, 15);
    assert!(r.prefer_relay);
}

/// **Row:** `test_relay_config_default_enabled`
#[test]
fn test_relay_config_default_enabled() {
    assert!(RelayConfig::default().enabled);
}

/// **Row:** `test_relay_config_default_timeout`
#[test]
fn test_relay_config_default_timeout() {
    assert_eq!(RelayConfig::default().connection_timeout_secs, 10);
}

/// **Row:** `test_relay_config_default_reconnect_delay`
#[test]
fn test_relay_config_default_reconnect_delay() {
    assert_eq!(RelayConfig::default().reconnect_delay_secs, 5);
}

/// **Row:** `test_relay_config_default_max_reconnect`
#[test]
fn test_relay_config_default_max_reconnect() {
    assert_eq!(RelayConfig::default().max_reconnect_attempts, 10);
}

/// **Row:** `test_relay_config_default_ping_interval`
#[test]
fn test_relay_config_default_ping_interval() {
    assert_eq!(
        RelayConfig::default().ping_interval_secs,
        PING_INTERVAL_SECS
    );
    assert_eq!(RelayConfig::default().ping_interval_secs, 30);
}

/// **Row:** `test_relay_config_default_prefer_relay`
#[test]
fn test_relay_config_default_prefer_relay() {
    assert!(!RelayConfig::default().prefer_relay);
}

/// **Row:** `test_relay_config_json_roundtrip`
#[test]
fn test_relay_config_json_roundtrip() {
    let r = RelayConfig {
        endpoint: "wss://r:2".into(),
        prefer_relay: true,
        ..Default::default()
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: RelayConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

/// **Row:** `test_relay_config_debug`
#[test]
fn test_relay_config_debug() {
    let r = RelayConfig::default();
    let s = format!("{r:?}");
    assert!(s.contains("RelayConfig"), "{s}");
}

/// **Row:** `test_relay_config_clone`
#[test]
fn test_relay_config_clone() {
    let r = RelayConfig {
        endpoint: "wss://y".into(),
        ..Default::default()
    };
    assert_eq!(r.clone(), r);
}

/// **Acceptance:** bincode round-trip for relay config.
#[test]
fn test_relay_config_bincode_roundtrip() {
    let r = RelayConfig {
        endpoint: "wss://rb".into(),
        enabled: false,
        ..Default::default()
    };
    let bytes = bincode::serialize(&r).unwrap();
    let back: RelayConfig = bincode::deserialize(&bytes).unwrap();
    assert_eq!(back, r);
}
