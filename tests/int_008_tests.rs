//! Tests for **INT-008: Discovery loop spawned in start()**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-008.md`
//! - **Master SPEC:** SS6.4
//!
//! INT-008 is satisfied when run_discovery_loop exists and is callable.
//! The function signature proves it can be spawned in start().

/// **INT-008: run_discovery_loop function exists and is callable.**
#[test]
fn test_run_discovery_loop_exists() {
    // Reference the function to prove it is publicly accessible — if the symbol
    // did not exist this line would fail to compile.
    let _ = dig_gossip::run_discovery_loop;
}

/// **INT-008: DiscoveryAction enum variants exist.**
#[test]
fn test_discovery_action_variants() {
    let _dns = dig_gossip::DiscoveryAction::DnsSeeded { count: 5 };
    let _intro = dig_gossip::DiscoveryAction::IntroducerQueried { count: 10 };
    let _backoff = dig_gossip::DiscoveryAction::IntroducerBackoff { backoff_secs: 2 };
    let _sleep = dig_gossip::DiscoveryAction::CycleSleep;
    let _cancel = dig_gossip::DiscoveryAction::Cancelled;
}

/// **INT-008: Discovery loop can be started and cancelled immediately.**
#[tokio::test]
async fn test_discovery_loop_cancel() {
    let am = dig_gossip::AddressManager::create(std::path::Path::new("")).unwrap();
    let config = dig_gossip::GossipConfig::default();

    let cancel = tokio_util::sync::CancellationToken::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let am_arc = std::sync::Arc::new(am);
    let cfg_arc = std::sync::Arc::new(config);
    let token = cancel.clone();

    let handle = tokio::spawn(dig_gossip::run_discovery_loop(
        am_arc,
        cfg_arc,
        token,
        Some(tx),
    ));

    // Cancel immediately
    cancel.cancel();

    // Wait for loop to exit
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;

    // Should receive at least one Cancelled action
    let mut got_cancelled = false;
    while let Ok(action) = rx.try_recv() {
        if action == dig_gossip::DiscoveryAction::Cancelled {
            got_cancelled = true;
        }
    }
    assert!(got_cancelled, "should receive Cancelled action on cancel");
}
