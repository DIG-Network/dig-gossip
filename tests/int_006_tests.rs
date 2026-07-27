//! Tests for **INT-006: /16 outbound diversity grouping**.
//!
//! - **Spec:** `docs/requirements/domains/integration/specs/INT-006.md`
//! - **Master SPEC:** §6.4 item 3
//!
//! Since #1703, INT-006 outbound occupancy is derived from the live peer map (the single source of
//! truth) inside `connect_to`, NOT a parallel mutable side-set — so a refcount-free set can no longer
//! under-count and re-admit a second outbound into an occupied `/16`. This file proves the pure `/16`
//! grouping KEY that the enforcement is built on ([`subnet_group`]); the end-to-end "one outbound per
//! /16" ENFORCEMENT against the real peer map is exercised in `con_1703_outbound_reconnect_tests`.

use dig_gossip::util::ip_address::subnet_group;
use std::net::IpAddr;

/// **INT-006: subnet_group computation for IPv4 — same /16 → equal key, different /16 → distinct.**
#[test]
fn test_subnet_group_ipv4() {
    let ip1: IpAddr = "192.168.1.1".parse().unwrap();
    let ip2: IpAddr = "192.168.255.255".parse().unwrap();
    assert_eq!(subnet_group(&ip1), subnet_group(&ip2), "same /16");

    let ip3: IpAddr = "192.169.1.1".parse().unwrap();
    assert_ne!(subnet_group(&ip1), subnet_group(&ip3), "different /16");
}

/// **INT-006: subnet_group computation for IPv6 — first 4 bytes group.**
#[test]
fn test_subnet_group_ipv6() {
    let ip1: IpAddr = "2001:0db8::1".parse().unwrap();
    let ip2: IpAddr = "2001:0db8::ffff".parse().unwrap();
    // Same first 4 bytes
    assert_eq!(subnet_group(&ip1), subnet_group(&ip2));
}
