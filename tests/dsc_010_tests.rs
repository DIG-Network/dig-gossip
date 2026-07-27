//! Tests for **DSC-010: AS-level diversity classification**.
//!
//! ## Requirement traceability
//!
//! - **Normative:** `docs/requirements/domains/discovery/NORMATIVE.md` (DSC-010)
//! - **Spec:** `docs/requirements/domains/discovery/specs/DSC-010.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` §6.4 item 3, §1.8#7, §5.2.3
//!
//! ## What this file proves
//!
//! Since #1703, AS-level outbound diversity is enforced in `connect_to` by deriving occupancy from the
//! live peer map (the single source of truth) — classifying each existing OUTBOUND slot's IP with the
//! immutable [`AsLookupTable`] and comparing to the candidate — NOT a parallel mutable filter set that
//! could drift out of agreement with the connections and under-count. The end-to-end "one outbound per
//! AS, a net-new outbound sharing an occupied AS is refused" enforcement is exercised against the real
//! peer map in `con_1703_outbound_reconnect_tests`. This file proves the classification table it builds
//! on: longest-prefix-match, unknown fail-open, and that same-AS IPs classify equal (so the map-derived
//! check counts them as one occupancy) while different-AS IPs classify distinct.

use std::net::IpAddr;

use dig_gossip::util::as_lookup::{AsLookupTable, AsNumber};

/// Helper: create a test BGP table with a few prefixes.
fn test_table() -> AsLookupTable {
    // AS 13335 = Cloudflare (1.1.1.0/24)
    // AS 15169 = Google (8.8.8.0/24)
    // AS 16509 = Amazon (3.0.0.0/8)
    // AS 64500 = test (10.0.0.0/8) — private range for testing
    let entries: Vec<(IpAddr, u8, AsNumber)> = vec![
        ("1.1.1.0".parse().unwrap(), 24, 13335),
        ("8.8.8.0".parse().unwrap(), 24, 15169),
        ("3.0.0.0".parse().unwrap(), 8, 16509),
        ("10.0.0.0".parse().unwrap(), 8, 64500),
        // More specific prefix within AS 64500
        ("10.1.0.0".parse().unwrap(), 16, 64501), // different AS for /16
    ];
    AsLookupTable::from_entries(entries)
}

/// **DSC-010: basic lookup resolves IPs to their AS numbers.**
#[test]
fn test_lookup_basic() {
    let table = test_table();
    assert_eq!(table.lookup(&"1.1.1.1".parse().unwrap()), Some(13335));
    assert_eq!(table.lookup(&"8.8.8.8".parse().unwrap()), Some(15169));
    assert_eq!(table.lookup(&"3.5.0.1".parse().unwrap()), Some(16509));
}

/// **DSC-010: longest-prefix-match wins (10.1.0.1 → /16 AS 64501, not /8 AS 64500).**
///
/// SPEC §1.8#7: "longest-prefix-match for accurate AS assignment."
#[test]
fn test_longest_prefix_match() {
    let table = test_table();
    assert_eq!(table.lookup(&"10.1.0.1".parse().unwrap()), Some(64501));
    assert_eq!(table.lookup(&"10.2.0.1".parse().unwrap()), Some(64500));
}

/// **DSC-010: unknown IP returns None (fail-open — "allow if AS unknown").**
#[test]
fn test_lookup_unknown_ip() {
    let table = test_table();
    assert_eq!(table.lookup(&"192.168.1.1".parse().unwrap()), None);
}

/// **DSC-010: empty table returns None for all (no BGP data → /16 is the sole guard).**
#[test]
fn test_empty_table_lookup() {
    let table = AsLookupTable::empty();
    assert!(table.is_empty());
    assert_eq!(table.lookup(&"1.1.1.1".parse().unwrap()), None);
}

/// **DSC-010: two IPs in the same AS classify EQUAL — the map-derived INT-007 counts them as one
/// outbound occupancy, so a second outbound sharing that AS is refused.**
#[test]
fn test_same_as_classifies_equal() {
    let table = test_table();
    let ip1: IpAddr = "1.1.1.1".parse().unwrap();
    let ip2: IpAddr = "1.1.1.2".parse().unwrap(); // same /24, same AS
    assert_eq!(table.lookup(&ip1), Some(13335));
    assert_eq!(
        table.lookup(&ip1),
        table.lookup(&ip2),
        "same-AS IPs must classify equal so the map-derived check treats them as one occupancy"
    );
}

/// **DSC-010: IPs in different ASes classify DISTINCT — a second outbound is allowed.**
#[test]
fn test_different_as_classifies_distinct() {
    let table = test_table();
    let cloudflare: IpAddr = "1.1.1.1".parse().unwrap();
    let google: IpAddr = "8.8.8.8".parse().unwrap();
    assert_ne!(table.lookup(&cloudflare), table.lookup(&google));
}
