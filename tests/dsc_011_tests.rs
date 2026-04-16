//! Tests for **DSC-011: /16 group filter for outbound connections**.
//!
//! ## Requirement traceability
//!
//! - **Normative:** `docs/requirements/domains/discovery/NORMATIVE.md` (DSC-011)
//! - **Spec:** `docs/requirements/domains/discovery/specs/DSC-011.md`
//! - **Master SPEC:** §6.4 item 3, §1.6#5
//! - **Chia:** `node_discovery.py:296-306` — one outbound per /16 group
//!
//! ## What this file proves
//!
//! DSC-011 is satisfied when:
//! 1. subnet_group() returns correct /16 for IPv4 (first 2 octets)
//! 2. SubnetGroupFilter blocks second outbound in same /16
//! 3. Different /16 groups allowed simultaneously
//! 4. remove_outbound re-allows group
//! 5. IPv6 grouping uses first 4 bytes

use std::net::IpAddr;

use dig_gossip::util::ip_address::{subnet_group, SubnetGroupFilter};

/// **DSC-011: IPv4 /16 group = first 2 octets.**
#[test]
fn test_subnet_group_ipv4() {
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    let group = subnet_group(&ip);
    // 192 << 8 | 168 = 49320
    assert_eq!(group, (192 << 8) | 168);
}

/// **DSC-011: same /16 → same group.**
#[test]
fn test_same_subnet_same_group() {
    let a: IpAddr = "10.5.0.1".parse().unwrap();
    let b: IpAddr = "10.5.255.254".parse().unwrap();
    assert_eq!(subnet_group(&a), subnet_group(&b));
}

/// **DSC-011: different /16 → different group.**
#[test]
fn test_different_subnet_different_group() {
    let a: IpAddr = "10.5.0.1".parse().unwrap();
    let b: IpAddr = "10.6.0.1".parse().unwrap();
    assert_ne!(subnet_group(&a), subnet_group(&b));
}

/// **DSC-011: IPv6 group = first 4 bytes.**
#[test]
fn test_subnet_group_ipv6() {
    let ip: IpAddr = "2001:db8::1".parse().unwrap();
    let group = subnet_group(&ip);
    // 0x2001 << 16 | 0x0db8 = 0x20010db8
    assert_eq!(group, 0x2001_0db8);
}

/// **DSC-011: filter blocks same /16.**
///
/// Proves SPEC §1.6#5: "one outbound per /16 group."
#[test]
fn test_filter_blocks_same_subnet() {
    let mut filter = SubnetGroupFilter::new();
    let a: IpAddr = "10.5.0.1".parse().unwrap();
    let b: IpAddr = "10.5.0.2".parse().unwrap();

    assert!(filter.is_allowed(&a));
    filter.add_outbound(&a);
    assert!(!filter.is_allowed(&b), "same /16 must be blocked");
}

/// **DSC-011: filter allows different /16.**
#[test]
fn test_filter_allows_different_subnet() {
    let mut filter = SubnetGroupFilter::new();
    let a: IpAddr = "10.5.0.1".parse().unwrap();
    let b: IpAddr = "10.6.0.1".parse().unwrap();

    filter.add_outbound(&a);
    assert!(filter.is_allowed(&b), "different /16 must be allowed");
}

/// **DSC-011: remove re-allows group.**
#[test]
fn test_filter_remove_re_allows() {
    let mut filter = SubnetGroupFilter::new();
    let ip: IpAddr = "10.5.0.1".parse().unwrap();

    filter.add_outbound(&ip);
    assert!(!filter.is_allowed(&"10.5.0.2".parse().unwrap()));

    filter.remove_outbound(&ip);
    assert!(filter.is_allowed(&"10.5.0.2".parse().unwrap()));
}

/// **DSC-011: group count tracks correctly.**
#[test]
fn test_filter_count() {
    let mut filter = SubnetGroupFilter::new();
    assert_eq!(filter.outbound_group_count(), 0);

    filter.add_outbound(&"10.5.0.1".parse().unwrap());
    assert_eq!(filter.outbound_group_count(), 1);

    filter.add_outbound(&"10.6.0.1".parse().unwrap());
    assert_eq!(filter.outbound_group_count(), 2);

    // Same /16 doesn't increase (HashSet)
    filter.add_outbound(&"10.5.0.2".parse().unwrap());
    assert_eq!(filter.outbound_group_count(), 2);
}

/// **DSC-011: empty filter allows everything.**
#[test]
fn test_empty_filter_allows_all() {
    let filter = SubnetGroupFilter::new();
    assert!(filter.is_allowed(&"1.1.1.1".parse().unwrap()));
    assert!(filter.is_allowed(&"8.8.8.8".parse().unwrap()));
}
