//! /16 subnet grouping and outbound diversity filter (**DSC-011**).
//!
//! # Requirements
//!
//! - **DSC-011** — [`docs/requirements/domains/discovery/specs/DSC-011.md`]:
//!   At most one outbound per IPv4 /16 subnet. Fast first-pass before AS check.
//!   Chia `node_discovery.py:296-306` — "Only connect out to one peer per network group."
//! - **Master SPEC:** §6.4 item 3, §1.6#5.
//!
//! # Design
//!
//! - **`subnet_group()`** — returns a u32 group key from an IP.
//!   IPv4: first 2 octets (0-65535). IPv6: first 4 bytes.
//!   Matches `PeerInfo::get_group()` in `types/peer.rs` but returns u32 for HashSet.
//! - **`SubnetGroupFilter`** — HashSet<u32> of outbound /16 groups.
//!   Fast O(1) check per candidate. Applied before AS filter (DSC-010).

use std::collections::HashSet;
use std::net::IpAddr;

/// Compute /16 group key for IP. IPv4: first 2 octets. IPv6: first 4 bytes.
///
/// SPEC §1.6#5: "One outbound per /16 group."
/// Chia `node_discovery.py:296-306`, `peer_info.py:51-56`.
pub fn subnet_group(ip: &IpAddr) -> u32 {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            ((o[0] as u32) << 8) | (o[1] as u32)
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
        }
    }
}

/// Outbound /16 subnet diversity filter (**DSC-011**).
///
/// Fast first-pass before AS diversity (DSC-010). Blocks candidates whose
/// /16 group already has an outbound connection.
///
/// SPEC §6.4 item 3: "/16 group filter — one outbound per IPv4 /16 subnet."
/// Chia `node_discovery.py:296-306`.
#[derive(Debug, Clone, Default)]
pub struct SubnetGroupFilter {
    /// /16 groups currently represented in outbound connections.
    outbound_groups: HashSet<u32>,
}

impl SubnetGroupFilter {
    /// New empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if candidate IP allowed (group not already in outbound set).
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        let group = subnet_group(ip);
        !self.outbound_groups.contains(&group)
    }

    /// Record new outbound connection's /16 group.
    pub fn add_outbound(&mut self, ip: &IpAddr) {
        self.outbound_groups.insert(subnet_group(ip));
    }

    /// Remove outbound connection's /16 group (on disconnect).
    pub fn remove_outbound(&mut self, ip: &IpAddr) {
        self.outbound_groups.remove(&subnet_group(ip));
    }

    /// Current outbound group count.
    pub fn outbound_group_count(&self) -> usize {
        self.outbound_groups.len()
    }
}
