//! Tests for **ERL-006: Flood Set Rotation**.
//!
//! ## Requirement traceability
//!
//! - **Spec:** `docs/requirements/domains/erlay/specs/ERL-006.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` SS8.3

#[cfg(feature = "erlay")]
mod tests {
    use dig_gossip::gossip::erlay::ErlayState;

    /// **ERL-006: needs_rotation after interval.**
    #[test]
    fn test_needs_rotation_initial() {
        let state = ErlayState::new();
        // last_rotation = 0, current time > 60s -> needs rotation
        assert!(state.needs_rotation());
    }
}
