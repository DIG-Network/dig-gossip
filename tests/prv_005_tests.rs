//! **PRV-005 — Epoch rotation (`StemRelayManager`)**
//!
//! Normative: [`docs/requirements/domains/privacy/specs/PRV-005.md`](../docs/requirements/domains/privacy/specs/PRV-005.md)
//! Master SPEC: [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 1.9.1 (Dandelion++)
//!
//! ## What this file proves
//!
//! `StemRelayManager` tracks the current epoch's stem relay peer and handles:
//! - Initial state: `needs_rotation()` returns `true` (no relay selected yet).
//! - After `rotate()`: a relay is selected from the provided outbound peers.
//! - `on_relay_disconnected()`: selects a new relay from remaining peers.
//!
//! SPEC §1.9.1: "Each node maintains a single stem_relay peer, re-randomized every
//! DANDELION_EPOCH_SECS."

#[cfg(feature = "dandelion")]
mod tests {
    use dig_gossip::privacy::dandelion::StemRelayManager;
    use dig_gossip::{Bytes32, PeerId};

    /// Helper: create distinct PeerIds for testing.
    fn test_peers(count: usize) -> Vec<PeerId> {
        (0..count)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i as u8;
                bytes[31] = (i + 100) as u8;
                Bytes32::from(bytes)
            })
            .collect()
    }

    /// A freshly constructed `StemRelayManager` needs rotation because no relay
    /// has been selected yet.
    ///
    /// Proves the initial state triggers relay selection on the first stem
    /// transaction rather than silently dropping it.
    #[test]
    fn test_needs_rotation_initially_true() {
        let mgr = StemRelayManager::new(600);
        assert!(
            mgr.needs_rotation(),
            "a new StemRelayManager must need rotation (no relay selected)"
        );
    }

    /// A freshly constructed manager has no current relay.
    #[test]
    fn test_relay_none_initially() {
        let mgr = StemRelayManager::new(600);
        assert!(
            mgr.relay().is_none(),
            "a new StemRelayManager must have no relay"
        );
    }

    /// After `rotate()` with available peers, a relay is selected.
    ///
    /// Proves the rotation mechanism assigns a peer from the outbound set.
    #[test]
    fn test_rotate_selects_relay() {
        let mut mgr = StemRelayManager::new(600);
        let peers = test_peers(5);
        mgr.rotate(&peers);
        let relay = mgr.relay().expect("relay must be Some after rotate()");
        assert!(
            peers.contains(relay),
            "selected relay must be one of the provided peers"
        );
    }

    /// After `rotate()`, `needs_rotation()` returns `false` (within the epoch).
    ///
    /// With a 600-second epoch, a just-rotated manager should not need rotation
    /// again immediately.
    #[test]
    fn test_rotate_clears_needs_rotation() {
        let mut mgr = StemRelayManager::new(600);
        let peers = test_peers(3);
        mgr.rotate(&peers);
        assert!(
            !mgr.needs_rotation(),
            "needs_rotation() must be false immediately after rotate()"
        );
    }

    /// `rotate()` with an empty peer list sets relay to None.
    ///
    /// When there are no outbound peers, the manager cannot select a relay.
    /// This edge case means stem transactions must be force-fluffed.
    #[test]
    fn test_rotate_empty_peers() {
        let mut mgr = StemRelayManager::new(600);
        mgr.rotate(&[]);
        assert!(
            mgr.relay().is_none(),
            "rotate() with empty peers must set relay to None"
        );
    }

    /// `on_relay_disconnected()` selects a new relay from remaining peers.
    ///
    /// Mid-epoch relay disconnect requires immediate re-selection to avoid
    /// dropping stem transactions.
    #[test]
    fn test_on_relay_disconnected_selects_new_relay() {
        let mut mgr = StemRelayManager::new(600);
        let peers = test_peers(5);
        mgr.rotate(&peers);
        let original_relay = *mgr.relay().expect("relay after rotate");

        // Simulate disconnect: remaining peers exclude the original relay.
        let remaining: Vec<PeerId> = peers
            .iter()
            .copied()
            .filter(|p| *p != original_relay)
            .collect();
        mgr.on_relay_disconnected(&remaining);

        let new_relay = mgr.relay().expect("relay after on_relay_disconnected");
        assert!(
            remaining.contains(new_relay),
            "new relay must be from the remaining peers"
        );
    }

    /// `on_relay_disconnected()` with empty peers sets relay to None.
    ///
    /// If all outbound peers have disconnected, there is no viable relay.
    #[test]
    fn test_on_relay_disconnected_empty_peers() {
        let mut mgr = StemRelayManager::new(600);
        let peers = test_peers(3);
        mgr.rotate(&peers);
        mgr.on_relay_disconnected(&[]);
        assert!(
            mgr.relay().is_none(),
            "on_relay_disconnected with empty peers must set relay to None"
        );
    }

    /// With a single outbound peer, `rotate()` always selects that peer.
    #[test]
    fn test_rotate_single_peer() {
        let mut mgr = StemRelayManager::new(600);
        let peers = test_peers(1);
        mgr.rotate(&peers);
        assert_eq!(
            mgr.relay(),
            Some(&peers[0]),
            "rotate() with a single peer must select that peer"
        );
    }

    /// Epoch start is updated on rotate, proving the epoch timer resets.
    #[test]
    fn test_rotate_updates_epoch_start() {
        let mut mgr = StemRelayManager::new(600);
        assert_eq!(mgr.epoch_start, 0, "epoch_start must start at 0");
        let peers = test_peers(2);
        mgr.rotate(&peers);
        assert!(
            mgr.epoch_start > 0,
            "epoch_start must be updated to current time after rotate()"
        );
    }
}
