//! Tests for **CNC-001: GossipService and GossipHandle Send + Sync + Clone**.
//!
//! - **Spec:** `docs/requirements/domains/concurrency/specs/CNC-001.md`
//! - **Master SPEC:** §9.1

/// **CNC-001: GossipHandle is Send + Sync + Clone.**
///
/// Compile-time assertion — if this compiles, the trait bounds are satisfied.
#[test]
fn test_gossip_handle_send_sync_clone() {
    fn assert_send_sync_clone<T: Send + Sync + Clone>() {}
    assert_send_sync_clone::<dig_gossip::GossipHandle>();
}

/// **CNC-001: GossipService is Send + Sync.**
#[test]
fn test_gossip_service_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<dig_gossip::GossipService>();
}
