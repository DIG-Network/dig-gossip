//! Tests for **INT-006: /16 SubnetGroupFilter on connect_to()**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-006.md`
//! - **Master SPEC:** SS6.4 item 3
//!
//! INT-006 is satisfied when SubnetGroupFilter is wired into ServiceState and
//! checked during connect_to().

use dig_gossip::util::ip_address::{subnet_group, SubnetGroupFilter};
use std::net::IpAddr;

/// **INT-006: SubnetGroupFilter can be created empty.**
#[test]
fn test_subnet_filter_new() {
    let f = SubnetGroupFilter::new();
    assert_eq!(f.outbound_group_count(), 0);
}

/// **INT-006: SubnetGroupFilter allows first connection from a /16.**
#[test]
fn test_subnet_filter_allows_first() {
    let f = SubnetGroupFilter::new();
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    assert!(f.is_allowed(&ip));
}

/// **INT-006: SubnetGroupFilter blocks second connection from same /16.**
#[test]
fn test_subnet_filter_blocks_same_group() {
    let mut f = SubnetGroupFilter::new();
    let ip1: IpAddr = "10.1.100.1".parse().unwrap();
    let ip2: IpAddr = "10.1.200.2".parse().unwrap(); // same /16 (10.1.x.x)

    f.add_outbound(&ip1);
    assert!(!f.is_allowed(&ip2), "same /16 should be blocked");
}

/// **INT-006: SubnetGroupFilter allows connections from different /16s.**
#[test]
fn test_subnet_filter_allows_different_groups() {
    let mut f = SubnetGroupFilter::new();
    let ip1: IpAddr = "10.1.0.1".parse().unwrap();
    let ip2: IpAddr = "10.2.0.1".parse().unwrap(); // different /16

    f.add_outbound(&ip1);
    assert!(f.is_allowed(&ip2), "different /16 should be allowed");
}

/// **INT-006: SubnetGroupFilter remove_outbound re-allows the group.**
#[test]
fn test_subnet_filter_remove_outbound() {
    let mut f = SubnetGroupFilter::new();
    let ip: IpAddr = "172.16.5.1".parse().unwrap();

    f.add_outbound(&ip);
    assert!(!f.is_allowed(&ip));

    f.remove_outbound(&ip);
    assert!(
        f.is_allowed(&ip),
        "after remove, group should be allowed again"
    );
}

/// **INT-006: subnet_group computation for IPv4.**
#[test]
fn test_subnet_group_ipv4() {
    let ip1: IpAddr = "192.168.1.1".parse().unwrap();
    let ip2: IpAddr = "192.168.255.255".parse().unwrap();
    assert_eq!(subnet_group(&ip1), subnet_group(&ip2), "same /16");

    let ip3: IpAddr = "192.169.1.1".parse().unwrap();
    assert_ne!(subnet_group(&ip1), subnet_group(&ip3), "different /16");
}

/// **INT-006: subnet_group computation for IPv6.**
#[test]
fn test_subnet_group_ipv6() {
    let ip1: IpAddr = "2001:0db8::1".parse().unwrap();
    let ip2: IpAddr = "2001:0db8::ffff".parse().unwrap();
    // Same first 4 bytes
    assert_eq!(subnet_group(&ip1), subnet_group(&ip2));
}

/// **INT-006: ServiceState has subnet_filter field.**
#[test]
fn test_service_state_has_subnet_filter() {
    fn _check_field(state: &dig_gossip::ServiceState) {
        let _sf = state.subnet_filter.lock().unwrap();
    }
}
