//! Tests for **DSC-011: /16 group classification for outbound diversity**.
//!
//! ## Requirement traceability
//!
//! - **Normative:** `docs/requirements/domains/discovery/NORMATIVE.md` (DSC-011)
//! - **Spec:** `docs/requirements/domains/discovery/specs/DSC-011.md`
//! - **Master SPEC:** §6.4 item 3, §1.6#5, §5.2.3
//! - **Chia:** `node_discovery.py:296-306` — one outbound per /16 group
//!
//! ## What this file proves
//!
//! DSC-011 is the /16 grouping that INT-006 outbound diversity is built on. Since #1703, outbound
//! occupancy is derived from the live peer map (the single source of truth), NOT a parallel mutable
//! side-set — so the classifier under test here is the pure [`subnet_group`] key, and the "one
//! outbound per /16" ENFORCEMENT is exercised end-to-end against the real peer map in
//! `con_1703_outbound_reconnect_tests`. This file proves the grouping key itself: IPv4 /16 = first 2
//! octets; same /16 → equal key (blocks a second outbound); different /16 → distinct key (a second
//! outbound allowed); IPv6 grouping = first 4 bytes.

use std::net::IpAddr;

use dig_gossip::util::ip_address::subnet_group;

/// **DSC-011: IPv4 /16 group = first 2 octets.**
#[test]
fn test_subnet_group_ipv4() {
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    // 192 << 8 | 168 = 49320
    assert_eq!(subnet_group(&ip), (192 << 8) | 168);
}

/// **DSC-011: same /16 → same group (a second outbound here is the one INT-006 blocks).**
#[test]
fn test_same_subnet_same_group() {
    let a: IpAddr = "10.5.0.1".parse().unwrap();
    let b: IpAddr = "10.5.255.254".parse().unwrap();
    assert_eq!(
        subnet_group(&a),
        subnet_group(&b),
        "same /16 must share a group key so INT-006 counts them as one occupancy"
    );
}

/// **DSC-011: different /16 → different group (a second outbound here is allowed).**
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
    // 0x2001 << 16 | 0x0db8 = 0x20010db8
    assert_eq!(subnet_group(&ip), 0x2001_0db8);
}
