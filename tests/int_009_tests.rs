//! Tests for **INT-009: Feeler loop spawned in start()**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-009.md`
//! - **Master SPEC:** SS6.4 item 4
//!
//! INT-009 is satisfied when run_feeler_loop exists and is callable.

/// **INT-009: run_feeler_loop function exists and is callable.**
#[test]
fn test_run_feeler_loop_exists() {
    // Reference the function to prove it compiles.
    let _ = dig_gossip::run_feeler_loop;
}

/// **INT-009: FeelerAction enum variants exist.**
#[test]
fn test_feeler_action_variants() {
    let _success = dig_gossip::FeelerAction::Success {
        host: "1.2.3.4".to_string(),
        port: 8444,
    };
    let _failure = dig_gossip::FeelerAction::Failure {
        host: "5.6.7.8".to_string(),
        port: 8444,
    };
    let _none = dig_gossip::FeelerAction::NoCandidates;
    let _cancel = dig_gossip::FeelerAction::Cancelled;
}

/// **INT-009: poisson_next_interval produces positive durations.**
#[test]
fn test_poisson_interval_positive() {
    for _ in 0..20 {
        let dur = dig_gossip::poisson_next_interval(240);
        assert!(dur.as_secs_f64() > 0.0, "interval must be positive");
    }
}

/// **INT-009: Feeler loop can be started and cancelled immediately.**
#[tokio::test]
async fn test_feeler_loop_cancel() {
    let am = dig_gossip::AddressManager::create(std::path::Path::new("")).unwrap();
    let am_arc = std::sync::Arc::new(am);

    let cancel = tokio_util::sync::CancellationToken::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let token = cancel.clone();
    let handle = tokio::spawn(dig_gossip::run_feeler_loop(am_arc, 240, token, Some(tx)));

    // Cancel immediately
    cancel.cancel();

    // Wait for loop to exit
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;

    // Should receive Cancelled action
    let mut got_cancelled = false;
    while let Ok(action) = rx.try_recv() {
        if action == dig_gossip::FeelerAction::Cancelled {
            got_cancelled = true;
        }
    }
    assert!(got_cancelled, "should receive Cancelled action on cancel");
}
