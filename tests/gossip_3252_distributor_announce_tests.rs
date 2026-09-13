//! External-crate-boundary smoke test for the opcode-226 `distributor-announce` public API
//! (dig_ecosystem#3252).
//!
//! ## Why this file exists
//!
//! Every item below is imported through `dig_gossip::` — the same boundary an external
//! consumer (e.g. `dig-node`) crosses — never `dig_gossip::service::...` and never `super::`.
//! Unit 1 of #3252 was blocked at the merge gate because a constant lived in a private module
//! and was unreachable from outside the crate, while its in-module tests still passed under the
//! defect by importing it via `super::`. This file exists so that class of regression fails to
//! **compile** here, rather than merely failing a runtime assertion somewhere else.
//!
//! This is a re-export/API-surface smoke test, not a protocol test — the wire-layout KAT and the
//! union/eviction behavioral tests already live in `src/service/distributor_announce.rs`'s own
//! `#[cfg(test)]` module and are not duplicated here.

use dig_gossip::{
    distributor_announce_payload, frame_distributor_announce, is_distributor_announce,
    DistributorAnnounce, DistributorAnnounceError, DistributorHintCache, DISTRIBUTOR_ANNOUNCE,
    MAX_DISTRIBUTOR_ANNOUNCE_BODY_BYTES, MAX_LAUNCHER_IDS_PER_ANNOUNCE,
    MAX_RETAINED_HINTS_PER_PEER,
};

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn opcode_and_predicate_are_reachable_through_the_crate_root() {
    assert_eq!(DISTRIBUTOR_ANNOUNCE, 226);
    assert!(is_distributor_announce(DISTRIBUTOR_ANNOUNCE));
    assert!(!is_distributor_announce(225));
}

#[test]
fn size_constants_are_reachable_and_agree_through_the_crate_root() {
    assert_eq!(
        MAX_DISTRIBUTOR_ANNOUNCE_BODY_BYTES,
        32 + 2 + MAX_LAUNCHER_IDS_PER_ANNOUNCE * 32
    );
    assert_eq!(MAX_LAUNCHER_IDS_PER_ANNOUNCE, 32);
    assert_eq!(MAX_RETAINED_HINTS_PER_PEER, 64);
}

#[test]
fn announce_build_frame_and_lift_round_trip_through_the_crate_root() {
    let announce = DistributorAnnounce::new(id(0x01), vec![id(0x02), id(0x03)])
        .expect("within MAX_LAUNCHER_IDS_PER_ANNOUNCE");
    let msg = frame_distributor_announce(&announce);
    assert_eq!(msg.msg_type, DISTRIBUTOR_ANNOUNCE);
    let lifted =
        distributor_announce_payload(&msg).expect("a frame_distributor_announce output decodes");
    assert_eq!(lifted, announce);
}

#[test]
fn over_cap_construction_is_rejected_through_the_crate_root() {
    let over_cap: Vec<[u8; 32]> = (0..=MAX_LAUNCHER_IDS_PER_ANNOUNCE as u16)
        .map(|i| id(i as u8))
        .collect();
    assert_eq!(
        DistributorAnnounce::new(id(0x99), over_cap),
        Err(DistributorAnnounceError::TooManyLauncherIds {
            count: MAX_LAUNCHER_IDS_PER_ANNOUNCE + 1
        })
    );
}

#[test]
fn hint_cache_unions_and_is_reachable_through_the_crate_root() {
    let store = id(0xAA);
    let mut cache = DistributorHintCache::new();
    cache.union(&DistributorAnnounce::new(store, vec![id(0x01)]).unwrap());
    cache.union(&DistributorAnnounce::new(store, vec![id(0x02)]).unwrap());

    let mut retained = cache.hints_for_store(&store);
    retained.sort();
    assert_eq!(retained, vec![id(0x01), id(0x02)]);
    assert_eq!(cache.len(), 2);
    assert!(!cache.is_empty());
}
