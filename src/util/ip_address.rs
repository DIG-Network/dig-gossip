//! /16 subnet grouping, outbound diversity filter (**DSC-011**), and IPv6-first candidate
//! ordering (ecosystem-wide IPv6-first / IPv4-fallback peer-communication rule).
//!
//! # Requirements
//!
//! - **DSC-011** — [`docs/requirements/domains/discovery/specs/DSC-011.md`]:
//!   At most one outbound per IPv4 /16 subnet. Fast first-pass before AS check.
//!   Chia `node_discovery.py:296-306` — "Only connect out to one peer per network group."
//! - **Master SPEC:** §6.4 item 3, §1.6#5, §1.10 (IPv6-first peer communication).
//!
//! # Design
//!
//! - **`subnet_group()`** — returns a u32 group key from an IP.
//!   IPv4: first 2 octets (0-65535). IPv6: first 4 bytes.
//!   Matches `PeerInfo::get_group()` in `types/peer.rs` but returns u32 for HashSet.
//! - **`SubnetGroupFilter`** — HashSet<u32> of outbound /16 groups.
//!   Fast O(1) check per candidate. Applied before AS filter (DSC-010).
//! - **`order_ipv6_first()`** — stable-sorts a candidate address list so every IPv6 address
//!   precedes every IPv4 address, without disturbing relative order within each family. Shared
//!   by every peer-selection / outbound-dial call site that assembles a candidate list, per the
//!   ecosystem-wide "IPv6-first, IPv4-fallback for peer communication" rule.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

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

/// Reorder `candidates` so every IPv6 address sorts before every IPv4 address, preserving
/// relative order within each family (a stable partition, not a full sort).
///
/// # Why this exists
///
/// Ecosystem-wide hard rule (dig_ecosystem `CLAUDE.md` §"IPv6-first, IPv4-fallback for peer
/// communication" / this crate's [`SPEC.md`](../../docs/resources/SPEC.md) §1.10): peer/address
/// **selection** must prefer IPv6 and use IPv4 only as a fallback. `dig-gossip`'s address-book
/// grouping (`PeerInfo::get_group`, `subnet_group` above) was already family-aware, but the
/// candidate-list assembly that feeds outbound dialing
/// ([`GossipHandle::gather_pool_candidates`](crate::service::gossip_handle::GossipHandle)) was
/// family-BLIND — it never considered address family when ordering candidates, so an IPv4
/// candidate could be dialed ahead of an available IPv6 one purely by the luck of the weighted
/// random draw. This helper is the single place that ordering is corrected; callers assemble
/// their candidate list per their own preference logic (tried-vs-new bias, most-diverse-first,
/// etc.) and pass it through here as a final pass.
///
/// # Family detection
///
/// Uses [`SocketAddr::is_ipv6`] on the already-parsed address — **not** a `contains(':')` string
/// check, which would misclassify a bracketed IPv6 host string (`"[::1]:9444"`) or trip over an
/// embedded IPv4-mapped textual form.
///
/// # Stability
///
/// [`slice::sort_by_key`] is a stable sort, so within the IPv6 group and within the IPv4 group
/// candidates keep their original relative order. IPv4 addresses are not dropped — IPv4 remains
/// the fallback, never removed.
pub fn order_ipv6_first(mut candidates: Vec<SocketAddr>) -> Vec<SocketAddr> {
    // `false` (IPv6, `is_ipv4() == false`) sorts before `true` (IPv4), giving IPv6-first order.
    candidates.sort_by_key(|addr| addr.is_ipv4());
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> SocketAddr {
        s.parse().expect("valid IPv4 SocketAddr")
    }

    fn v6(s: &str) -> SocketAddr {
        s.parse().expect("valid IPv6 SocketAddr")
    }

    #[test]
    fn order_ipv6_first_promotes_ipv6_over_ipv4() {
        let candidates = vec![v4("203.0.113.1:9444"), v6("[2001:db8::1]:9444")];
        let ordered = order_ipv6_first(candidates);
        assert!(ordered[0].is_ipv6());
        assert!(ordered[1].is_ipv4());
    }

    #[test]
    fn order_ipv6_first_is_a_stable_partition() {
        let a = v6("[2001:db8::a]:9444");
        let b = v6("[2001:db8::b]:9444");
        let c = v4("203.0.113.1:9444");
        let d = v4("203.0.113.2:9444");
        let ordered = order_ipv6_first(vec![c, a, d, b]);
        assert_eq!(ordered, vec![a, b, c, d]);
    }

    #[test]
    fn order_ipv6_first_handles_empty_and_single_family_lists() {
        assert!(order_ipv6_first(Vec::new()).is_empty());
        let only_v4 = vec![v4("203.0.113.1:9444"), v4("198.51.100.1:9444")];
        assert_eq!(order_ipv6_first(only_v4.clone()), only_v4);
        let only_v6 = vec![v6("[::1]:9444"), v6("[2001:db8::1]:9444")];
        assert_eq!(order_ipv6_first(only_v6.clone()), only_v6);
    }
}
