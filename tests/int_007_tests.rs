//! Tests for **INT-007: AS-level outbound diversity classification**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-007.md`
//! - **Master SPEC:** §6.4 item 3, §5.2.3
//!
//! Since #1703, outbound AS diversity is NOT tracked in a parallel mutable filter set (which could
//! drift out of agreement with the actual connections and under-count). Occupancy is derived from the
//! live peer map — the single source of truth — inside `connect_to`, using the immutable
//! [`AsLookupTable`] purely to CLASSIFY each peer's IP to an AS number. The end-to-end enforcement
//! ("a net-new outbound sharing an occupied AS/group is refused") is exercised against the real peer
//! map in `con_1703_outbound_reconnect_tests`; this file proves the classification table INT-007
//! builds on: longest-prefix match, and same-AS / different-AS / unknown-fail-open resolution.

use dig_gossip::util::as_lookup::AsLookupTable;
use std::net::IpAddr;

/// **INT-007: an empty table (no BGP data) classifies every IP as unknown → AS check fails open.**
#[test]
fn test_no_bgp_data_classifies_all_as_unknown() {
    let table = AsLookupTable::empty();
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    assert!(table.is_empty());
    assert_eq!(
        table.lookup(&ip),
        None,
        "no BGP data → unknown AS → INT-007 fails open (/16 is the sole guard)"
    );
}

/// **INT-007: two IPs in the same AS resolve to the SAME AS number (map-derived INT-007 blocks the
/// second outbound because their classifications collide).**
#[test]
fn test_same_as_resolves_equal() {
    let entries = vec![
        ("10.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 100u32),
        ("20.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 200u32),
    ];
    let table = AsLookupTable::from_entries(entries);

    let ip1: IpAddr = "10.1.1.1".parse().unwrap();
    let ip2: IpAddr = "10.2.2.2".parse().unwrap();
    assert_eq!(table.lookup(&ip1), Some(100));
    assert_eq!(
        table.lookup(&ip1),
        table.lookup(&ip2),
        "same-AS IPs must classify equal so INT-007 counts them as one occupancy"
    );
}

/// **INT-007: IPs in different ASes resolve to different AS numbers (second outbound allowed).**
#[test]
fn test_different_as_resolves_distinct() {
    let entries = vec![
        ("10.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 100u32),
        ("20.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 200u32),
    ];
    let table = AsLookupTable::from_entries(entries);

    let ip1: IpAddr = "10.1.1.1".parse().unwrap();
    let ip2: IpAddr = "20.1.1.1".parse().unwrap();
    assert_ne!(table.lookup(&ip1), table.lookup(&ip2));
}

/// **INT-007: an IP outside every prefix classifies as unknown (fails open).**
#[test]
fn test_unknown_ip_classifies_none() {
    let entries = vec![("10.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 100u32)];
    let table = AsLookupTable::from_entries(entries);

    let unknown_ip: IpAddr = "192.168.1.1".parse().unwrap();
    assert_eq!(table.lookup(&unknown_ip), None, "unknown IP fails open");
}

/// **INT-007: AsLookupTable resolves via longest-prefix-match.**
#[test]
fn test_as_lookup_table_longest_prefix() {
    let entries = vec![
        ("10.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 100u32),
        ("10.1.0.0".parse::<IpAddr>().unwrap(), 16u8, 200u32),
    ];
    let table = AsLookupTable::from_entries(entries);

    // 10.1.x.x matches the more-specific /16 (AS 200), not the /8 (AS 100).
    assert_eq!(
        table.lookup(&"10.1.1.1".parse::<IpAddr>().unwrap()),
        Some(200)
    );
    // 10.2.x.x falls back to the /8 (AS 100).
    assert_eq!(
        table.lookup(&"10.2.1.1".parse::<IpAddr>().unwrap()),
        Some(100)
    );
}
