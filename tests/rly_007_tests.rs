//! Tests for **RLY-007: NAT Traversal Hole Punching**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/relay/specs/RLY-007.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS7.1

#[cfg(feature = "relay")]
mod tests {
    use dig_gossip::relay::relay_service::{HolePunchState, HOLE_PUNCH_RETRY_SECS};

    /// **RLY-007: hole punch state machine transitions.**
    ///
    /// Proves SPEC SS7.1: Idle -> WaitingForCoordination -> Connecting -> Succeeded/Failed.
    #[test]
    fn test_hole_punch_success_path() {
        let mut state = HolePunchState::Idle;
        assert!(!state.is_active());

        state.request_sent();
        assert_eq!(state, HolePunchState::WaitingForCoordination);
        assert!(state.is_active());

        state.coordination_received();
        assert_eq!(state, HolePunchState::Connecting);
        assert!(state.is_active());

        state.connect_succeeded();
        assert_eq!(state, HolePunchState::Succeeded);
        assert!(!state.is_active());
    }

    /// **RLY-007: hole punch failure sets retry delay.**
    ///
    /// Proves SPEC SS7.1: "failure retry after 300s."
    #[test]
    fn test_hole_punch_failure() {
        let mut state = HolePunchState::Idle;
        state.request_sent();
        state.coordination_received();
        state.connect_failed();

        assert_eq!(
            state,
            HolePunchState::Failed {
                retry_after_secs: HOLE_PUNCH_RETRY_SECS
            }
        );
        assert_eq!(HOLE_PUNCH_RETRY_SECS, 300);
        assert!(!state.is_active());
    }
}
