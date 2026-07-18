//! /16 subnet grouping, outbound diversity filter (**DSC-011**), and the local∩peer
//! family-INTERSECTION candidate ordering (ecosystem-wide IPv6-first / IPv4-fallback rule).
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
//! - **`order_by_local_stack()`** — orders a candidate address list IPv6-first and DROPS any
//!   candidate whose family the LOCAL host cannot originate on, using the canonical
//!   [`dig_ip`] crate as the single family authority ([`dig_ip::Family`] for the IPv6-first key,
//!   [`dig_ip::LocalStack`] for the local-capability intersection). This is the ecosystem's one
//!   implementation of the "IPv6-first, IPv4-fallback" rule (CLAUDE.md §5.2); no crate hand-rolls a
//!   family sort or a local-capability check any more.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use dig_ip::{Family, LocalStack};

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

/// Order `candidates` IPv6-first over the LOCAL host's reachable families, dropping any candidate of
/// a family this host cannot originate on.
///
/// # Why this exists
///
/// Ecosystem-wide hard rule (dig_ecosystem `CLAUDE.md` §5.2 "IPv6-first, IPv4-fallback for peer
/// communication" / this crate's [`SPEC.md`](../../docs/resources/SPEC.md) §1.10), whose single
/// canonical implementation is the [`dig_ip`] crate. `dig-gossip`'s candidate-list assembly that
/// feeds outbound dialing
/// ([`GossipHandle::gather_pool_candidates`](crate::service::gossip_handle::GossipHandle)) draws
/// family-BLIND weighted-random addresses from the address book; this helper corrects that draw in
/// one place. It does two things, both delegated to `dig-ip` as the family authority:
///
/// - **IPv6-first** — for each family the local host has, in [`dig_ip::Family`] preference order
///   (IPv6 then IPv4), the candidates of that family are emitted in their original (draw) order, so
///   every IPv6 candidate precedes every IPv4 candidate while unrelated preference signals
///   (`select_peer`'s tried-vs-new bias) survive within each family.
/// - **Local∩candidate intersection (the new correctness)** — a candidate of a family the local
///   host cannot reach ([`dig_ip::LocalStack::has`] is false) is DROPPED, so an IPv4-only host never
///   emits an IPv6 SYN and an IPv6-only host never emits an IPv4 SYN. Mirrors [`dig_ip::dial_order`]
///   (whose per-peer variant returns [`dig_ip::NoCommonFamily`] when disjoint); at the multi-peer
///   pool layer an empty result is the natural "nothing dialable this pass" outcome.
///
/// # Family authority
///
/// Family classification is [`dig_ip::Family::of`] — never a `contains(':')` string check (which
/// misclassifies a bracketed IPv6 host string) nor an `is_ipv4()` sort key. An IPv4-mapped IPv6
/// address is correctly treated as IPv4 reachability by `dig_ip`.
pub fn order_by_local_stack(local: &LocalStack, candidates: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut ordered = Vec::with_capacity(candidates.len());
    for family in local.families() {
        ordered.extend(
            candidates
                .iter()
                .copied()
                .filter(|addr| Family::of(addr) == family),
        );
    }
    ordered
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

    const DUAL: LocalStack = LocalStack::from_flags(true, true);
    const V4_ONLY: LocalStack = LocalStack::from_flags(false, true);
    const V6_ONLY: LocalStack = LocalStack::from_flags(true, false);

    #[test]
    fn dual_stack_promotes_ipv6_over_ipv4() {
        let candidates = vec![v4("203.0.113.1:9444"), v6("[2001:db8::1]:9444")];
        let ordered = order_by_local_stack(&DUAL, &candidates);
        assert!(ordered[0].is_ipv6());
        assert!(ordered[1].is_ipv4());
    }

    #[test]
    fn dual_stack_is_a_stable_partition() {
        let a = v6("[2001:db8::a]:9444");
        let b = v6("[2001:db8::b]:9444");
        let c = v4("203.0.113.1:9444");
        let d = v4("203.0.113.2:9444");
        let ordered = order_by_local_stack(&DUAL, &[c, a, d, b]);
        assert_eq!(ordered, vec![a, b, c, d]);
    }

    #[test]
    fn dual_stack_handles_empty_and_single_family_lists() {
        assert!(order_by_local_stack(&DUAL, &[]).is_empty());
        let only_v4 = vec![v4("203.0.113.1:9444"), v4("198.51.100.1:9444")];
        assert_eq!(order_by_local_stack(&DUAL, &only_v4), only_v4);
        let only_v6 = vec![v6("[::1]:9444"), v6("[2001:db8::1]:9444")];
        assert_eq!(order_by_local_stack(&DUAL, &only_v6), only_v6);
    }

    // G1 — never emit a family the LOCAL host lacks: a v4-only host drops every IPv6 candidate.
    #[test]
    fn v4_only_local_drops_ipv6_candidates() {
        let candidates = vec![v6("[2001:db8::1]:9444"), v4("203.0.113.1:9444")];
        let ordered = order_by_local_stack(&V4_ONLY, &candidates);
        assert_eq!(ordered, vec![v4("203.0.113.1:9444")]);
        assert!(ordered.iter().all(|a| a.is_ipv4()));
    }

    // G1 mirror — a v6-only host drops every IPv4 candidate (IPv4 is the fallback, not always kept).
    #[test]
    fn v6_only_local_drops_ipv4_candidates() {
        let candidates = vec![v6("[2001:db8::1]:9444"), v4("203.0.113.1:9444")];
        let ordered = order_by_local_stack(&V6_ONLY, &candidates);
        assert_eq!(ordered, vec![v6("[2001:db8::1]:9444")]);
        assert!(ordered.iter().all(|a| a.is_ipv6()));
    }

    // Disjoint families → empty (the multi-peer analog of dig_ip's NoCommonFamily): a v4-only host
    // with only IPv6 candidates has nothing dialable — a clean empty, never a doomed IPv6 attempt.
    #[test]
    fn disjoint_families_yield_no_candidates() {
        let candidates = vec![v6("[2001:db8::1]:9444"), v6("[2001:db8::2]:9444")];
        assert!(order_by_local_stack(&V4_ONLY, &candidates).is_empty());
    }
}
