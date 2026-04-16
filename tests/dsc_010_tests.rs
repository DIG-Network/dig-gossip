//! Tests for **DSC-010: AS-level diversity**.
//!
//! ## Requirement traceability
//!
//! - **Normative:** `docs/requirements/domains/discovery/NORMATIVE.md` (DSC-010)
//! - **Spec:** `docs/requirements/domains/discovery/specs/DSC-010.md`
//! - **Master SPEC:** `docs/resources/SPEC.md` §6.4 item 3, §1.8#7
//!
//! ## What this file proves
//!
//! DSC-010 is satisfied when:
//! 1. AsLookupTable performs longest-prefix-match correctly
//! 2. AsDiversityFilter blocks second outbound to same AS
//! 3. Unknown IPs (not in BGP table) fail open (allowed)
//! 4. add_outbound/remove_outbound track AS set correctly
//! 5. Empty BGP table allows all connections (/16 sole guard)

use std::net::IpAddr;

use dig_gossip::util::as_lookup::{AsDiversityFilter, AsLookupTable, AsNumber};

/// Helper: create test BGP table with a few prefixes.
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

/// **DSC-010: basic lookup matches prefix.**
///
/// Proves AS lookup resolves IPs to correct AS numbers.
#[test]
fn test_lookup_basic() {
    let table = test_table();

    assert_eq!(table.lookup(&"1.1.1.1".parse().unwrap()), Some(13335));
    assert_eq!(table.lookup(&"8.8.8.8".parse().unwrap()), Some(15169));
    assert_eq!(table.lookup(&"3.5.0.1".parse().unwrap()), Some(16509));
}

/// **DSC-010: longest-prefix-match wins.**
///
/// Proves 10.1.0.1 matches /16 (AS 64501) not /8 (AS 64500).
/// SPEC §1.8#7: "longest-prefix-match for accurate AS assignment."
#[test]
fn test_longest_prefix_match() {
    let table = test_table();

    // 10.1.0.1 matches both 10.0.0.0/8 (AS 64500) and 10.1.0.0/16 (AS 64501)
    // Longest prefix (/16) should win.
    assert_eq!(table.lookup(&"10.1.0.1".parse().unwrap()), Some(64501));

    // 10.2.0.1 only matches 10.0.0.0/8
    assert_eq!(table.lookup(&"10.2.0.1".parse().unwrap()), Some(64500));
}

/// **DSC-010: unknown IP returns None.**
///
/// Proves fail-open behavior: "allow if AS unknown" (DSC-010 spec).
#[test]
fn test_lookup_unknown_ip() {
    let table = test_table();

    // 192.168.1.1 not in any prefix
    assert_eq!(table.lookup(&"192.168.1.1".parse().unwrap()), None);
}

/// **DSC-010: empty table returns None for all.**
#[test]
fn test_empty_table_lookup() {
    let table = AsLookupTable::empty();

    assert!(table.is_empty());
    assert_eq!(table.lookup(&"1.1.1.1".parse().unwrap()), None);
}

/// **DSC-010: filter blocks second outbound to same AS.**
///
/// Proves SPEC §6.4: "at most one outbound per AS number."
#[test]
fn test_filter_blocks_same_as() {
    let table = test_table();
    let mut filter = AsDiversityFilter::new(table);

    let ip1: IpAddr = "1.1.1.1".parse().unwrap();
    let ip2: IpAddr = "1.1.1.2".parse().unwrap(); // same /24, same AS

    // First connection allowed
    assert!(filter.is_allowed(&ip1));
    filter.add_outbound(&ip1);

    // Second connection to same AS blocked
    assert!(
        !filter.is_allowed(&ip2),
        "second outbound to same AS must be blocked"
    );
}

/// **DSC-010: filter allows different AS.**
#[test]
fn test_filter_allows_different_as() {
    let table = test_table();
    let mut filter = AsDiversityFilter::new(table);

    let cloudflare: IpAddr = "1.1.1.1".parse().unwrap();
    let google: IpAddr = "8.8.8.8".parse().unwrap();

    filter.add_outbound(&cloudflare);

    // Different AS should be allowed
    assert!(filter.is_allowed(&google), "different AS must be allowed");
}

/// **DSC-010: unknown IP fails open.**
///
/// Proves DSC-010: "Unknown AS fails open (connection allowed)."
#[test]
fn test_filter_unknown_ip_allowed() {
    let table = test_table();
    let mut filter = AsDiversityFilter::new(table);

    let unknown: IpAddr = "192.168.1.1".parse().unwrap();

    assert!(
        filter.is_allowed(&unknown),
        "unknown AS must fail open (allowed)"
    );
}

/// **DSC-010: remove_outbound re-allows AS.**
#[test]
fn test_filter_remove_outbound() {
    let table = test_table();
    let mut filter = AsDiversityFilter::new(table);

    let ip: IpAddr = "1.1.1.1".parse().unwrap();

    filter.add_outbound(&ip);
    assert!(!filter.is_allowed(&"1.1.1.2".parse().unwrap()));

    filter.remove_outbound(&ip);
    assert!(
        filter.is_allowed(&"1.1.1.2".parse().unwrap()),
        "after remove, AS should be allowed again"
    );
}

/// **DSC-010: no BGP data allows all (fallback to /16).**
///
/// Proves DSC-010: "if no BGP table loaded, /16 filter is sole guard."
#[test]
fn test_no_bgp_data_allows_all() {
    let filter = AsDiversityFilter::no_bgp_data();

    assert!(!filter.has_bgp_data());
    assert!(filter.is_allowed(&"1.1.1.1".parse().unwrap()));
    assert!(filter.is_allowed(&"8.8.8.8".parse().unwrap()));
}

/// **DSC-010: outbound_as_count tracks correctly.**
#[test]
fn test_outbound_count() {
    let table = test_table();
    let mut filter = AsDiversityFilter::new(table);

    assert_eq!(filter.outbound_as_count(), 0);

    filter.add_outbound(&"1.1.1.1".parse().unwrap()); // AS 13335
    assert_eq!(filter.outbound_as_count(), 1);

    filter.add_outbound(&"8.8.8.8".parse().unwrap()); // AS 15169
    assert_eq!(filter.outbound_as_count(), 2);

    // Adding same AS again doesn't increase count (HashSet)
    filter.add_outbound(&"1.1.1.2".parse().unwrap()); // AS 13335 again
    assert_eq!(filter.outbound_as_count(), 2);
}
