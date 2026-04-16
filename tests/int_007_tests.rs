//! Tests for **INT-007: AsDiversityFilter on connect_to()**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-007.md`
//! - **Master SPEC:** SS6.4 item 3
//!
//! INT-007 is satisfied when AsDiversityFilter is wired into ServiceState and
//! checked during connect_to().

use dig_gossip::util::as_lookup::{AsDiversityFilter, AsLookupTable};
use std::net::IpAddr;

/// **INT-007: AsDiversityFilter with no BGP data allows all.**
#[test]
fn test_as_filter_no_bgp_data_allows_all() {
    let f = AsDiversityFilter::no_bgp_data();
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    assert!(f.is_allowed(&ip), "no BGP data should fail open");
    assert!(!f.has_bgp_data());
}

/// **INT-007: AsDiversityFilter blocks same AS.**
#[test]
fn test_as_filter_blocks_same_as() {
    // Create table: 10.0.0.0/8 -> AS100, 20.0.0.0/8 -> AS200
    let entries = vec![
        ("10.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 100u32),
        ("20.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 200u32),
    ];
    let table = AsLookupTable::from_entries(entries);
    let mut f = AsDiversityFilter::new(table);

    assert!(f.has_bgp_data());

    let ip1: IpAddr = "10.1.1.1".parse().unwrap();
    let ip2: IpAddr = "10.2.2.2".parse().unwrap(); // same AS (100)

    assert!(f.is_allowed(&ip1));
    f.add_outbound(&ip1);
    assert!(!f.is_allowed(&ip2), "same AS should be blocked");
}

/// **INT-007: AsDiversityFilter allows different AS.**
#[test]
fn test_as_filter_allows_different_as() {
    let entries = vec![
        ("10.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 100u32),
        ("20.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 200u32),
    ];
    let table = AsLookupTable::from_entries(entries);
    let mut f = AsDiversityFilter::new(table);

    let ip1: IpAddr = "10.1.1.1".parse().unwrap(); // AS 100
    let ip2: IpAddr = "20.1.1.1".parse().unwrap(); // AS 200

    f.add_outbound(&ip1);
    assert!(f.is_allowed(&ip2), "different AS should be allowed");
}

/// **INT-007: AsDiversityFilter remove_outbound re-allows the AS.**
#[test]
fn test_as_filter_remove_outbound() {
    let entries = vec![("10.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 100u32)];
    let table = AsLookupTable::from_entries(entries);
    let mut f = AsDiversityFilter::new(table);

    let ip: IpAddr = "10.1.1.1".parse().unwrap();
    f.add_outbound(&ip);
    assert!(!f.is_allowed(&ip));

    f.remove_outbound(&ip);
    assert!(f.is_allowed(&ip), "after remove, AS should be allowed");
}

/// **INT-007: Unknown IPs fail open (allowed).**
#[test]
fn test_as_filter_unknown_ip_fails_open() {
    let entries = vec![("10.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 100u32)];
    let table = AsLookupTable::from_entries(entries);
    let f = AsDiversityFilter::new(table);

    let unknown_ip: IpAddr = "192.168.1.1".parse().unwrap(); // not in table
    assert!(f.is_allowed(&unknown_ip), "unknown IP should fail open");
}

/// **INT-007: AsLookupTable longest-prefix-match.**
#[test]
fn test_as_lookup_table_longest_prefix() {
    let entries = vec![
        ("10.0.0.0".parse::<IpAddr>().unwrap(), 8u8, 100u32),
        ("10.1.0.0".parse::<IpAddr>().unwrap(), 16u8, 200u32),
    ];
    let table = AsLookupTable::from_entries(entries);

    // 10.1.x.x should match /16 (AS 200), not /8 (AS 100)
    let ip: IpAddr = "10.1.1.1".parse().unwrap();
    assert_eq!(table.lookup(&ip), Some(200));

    // 10.2.x.x should match /8 (AS 100)
    let ip2: IpAddr = "10.2.1.1".parse().unwrap();
    assert_eq!(table.lookup(&ip2), Some(100));
}

/// **INT-007: ServiceState has as_filter field.**
#[test]
fn test_service_state_has_as_filter() {
    fn _check_field(state: &dig_gossip::ServiceState) {
        let _af = state.as_filter.lock().unwrap();
    }
}
