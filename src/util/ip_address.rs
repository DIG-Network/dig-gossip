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
//!   Matches `PeerInfo::get_group()` in `types/peer.rs`. Outbound /16 diversity (INT-006) is enforced
//!   in `connect_to` by comparing this key across the live peer map (#1703) — the single source of
//!   truth — not a parallel occupancy set that could drift.
//! - **`order_by_local_stack()`** — orders a candidate address list IPv6-first and DROPS any
//!   candidate whose family the LOCAL host cannot originate on, using the canonical
//!   [`dig_ip`] crate as the single family authority ([`dig_ip::Family`] for the IPv6-first key,
//!   [`dig_ip::LocalStack`] for the local-capability intersection). This is the ecosystem's one
//!   implementation of the "IPv6-first, IPv4-fallback" rule (CLAUDE.md §5.2); no crate hand-rolls a
//!   family sort or a local-capability check any more.

use std::net::{IpAddr, SocketAddr};

use dig_ip::{Family, LocalStack};

/// Canonicalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4 form.
///
/// A genuine IPv6 address is returned unchanged (so it still groups by its own /32, per §5.2). This
/// is the one seam where a mapped-v6 candidate would otherwise be keyed differently than its plain-v4
/// twin: without canonicalization `subnet_group` collapses `::ffff:a.b.c.d` to group `0` (its first
/// four bytes are zero) instead of the mapped `a.b` /16, and the AS classifier ([`super::as_lookup`])
/// fails to match it against v4 BGP prefixes — either seam lets the SAME routable network dodge the
/// one-outbound-per-/16 (INT-006) or per-AS (INT-007) eclipse cap by presenting itself as mapped-v6.
/// `Ipv6Addr::to_ipv4_mapped` is the canonical test — deliberately NOT `to_ipv4`, which would also
/// fold the deprecated v4-*compatible* `::a.b.c.d` form.
pub(crate) fn canonical_ip(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => *ip,
        },
        IpAddr::V4(_) => *ip,
    }
}

/// Compute /16 group key for IP. IPv4: first 2 octets. IPv6: first 4 bytes.
///
/// An IPv4-mapped IPv6 address is canonicalized to IPv4 first ([`canonical_ip`]), so it shares the
/// /16 group of its plain-v4 twin and cannot dodge the /16 eclipse cap (INT-006, #1709).
///
/// SPEC §1.6#5: "One outbound per /16 group."
/// Chia `node_discovery.py:296-306`, `peer_info.py:51-56`.
pub fn subnet_group(ip: &IpAddr) -> u32 {
    match canonical_ip(ip) {
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

/// The SOURCE group of an INBOUND peer: an IPv4 `/16`, or an IPv6 `/48` (**dig_ecosystem#3124**).
///
/// # Why this is not [`subnet_group`]
///
/// The two functions answer opposite questions and a coarse group is conservative for exactly one of
/// them. [`subnet_group`] bounds this node's OWN dialing (INT-006): a coarse group can only make the
/// dial set more diverse, so erring wide errs safe. This one REFUSES a peer, and in that direction a
/// group wider than the unit an attacker actually controls is a denial primitive — it lets whoever
/// holds `max_direct_inbound_per_group` addresses inside the group lock out every other host in it.
///
/// [`subnet_group`]'s IPv6 branch keys on the first four bytes, a `/32`. **An IPv6 `/32` is an RIR
/// allocation to a hosting provider, not a site** — DigitalOcean is `2604:a880::/32`, Linode
/// `2600:3c00::/32`, Vultr `2001:19f0::/32`, Hetzner `2a01:4f8::/32`. Reused as an inbound refusal
/// key it caps a default node at two accepted direct peers from an ENTIRE PROVIDER worldwide, and two
/// cheap rented hosts at that provider deny direct-inbound registration to every DIG node there.
/// CLAUDE.md §5.2 makes IPv6 the preferred family for peer communication, so that is the common case
/// on this path rather than an edge of it.
///
/// # Why `/48`
///
/// A `/48` is the end-SITE unit of IPv6 allocation (RFC 6177 / RIPE-690): it is what a provider hands
/// to one customer, so it is the smallest prefix an attacker can be assumed to control in full and the
/// largest one an honest operator's whole site fits inside. It is thus the closest IPv6 analogue of
/// the IPv4 `/16` this bound already uses — wide enough that a genuine multi-homed site groups
/// together, narrow enough that "same provider" buys an attacker nothing. Customers given a `/56`
/// group under their own `/48` and are unaffected.
///
/// IPv4 keeps its `/16`: the v4 analogue of the provider problem does not arise, an attacker must sit
/// inside the victim's own `/16`, and the outbound cap has used this width since INT-006.
///
/// An IPv4-mapped IPv6 address is canonicalized first ([`canonical_ip`]) for the same reason it is
/// there — otherwise the same routable network dodges its group by presenting itself as mapped-v6.
///
/// The two families are returned as DISTINCT variants rather than as one integer, so a v4 `/16` key
/// can never collide with the low bits of a v6 `/48` key and silently pool two unrelated sources into
/// one group.
pub fn inbound_source_group(ip: &IpAddr) -> InboundSourceGroup {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            InboundSourceGroup::V4Slash16(((o[0] as u32) << 8) | (o[1] as u32))
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let mut key: u64 = 0;
            for byte in &o[..6] {
                key = (key << 8) | (*byte as u64);
            }
            InboundSourceGroup::V6Slash48(key)
        }
    }
}

/// The group key [`inbound_source_group`] produces, one variant per address family.
///
/// Separate variants rather than a single integer so the two families' key spaces cannot overlap:
/// pooling an IPv4 `/16` with an IPv6 `/48` that happened to share low bits would refuse peers that
/// share no network at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InboundSourceGroup {
    /// The first two octets of an IPv4 address — a `/16`.
    V4Slash16(u32),
    /// The first six octets of an IPv6 address — a `/48`, the end-site allocation unit.
    V6Slash48(u64),
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

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid IpAddr")
    }

    // #1709 regression — an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) MUST group by the mapped /16
    // exactly like its plain-v4 twin, or the same network dodges the /16 eclipse cap (INT-006) by
    // presenting itself as mapped-v6 (collapsing to group 0) vs plain-v4.
    #[test]
    fn v4_mapped_v6_groups_with_plain_v4_same_16() {
        let mapped = subnet_group(&ip("::ffff:203.0.113.7"));
        let plain = subnet_group(&ip("203.0.113.9"));
        assert_eq!(
            mapped, plain,
            "mapped-v6 must share the /16 group of its plain-v4 twin"
        );
        // And it is the actual 203.0 /16 key, not the collapsed IPv6 group 0.
        assert_eq!(mapped, 203u32 << 8);
    }

    // Genuine IPv6 (not v4-mapped) still groups by its first 4 bytes (/32) — §5.2 IPv6-first unchanged.
    #[test]
    fn genuine_ipv6_still_groups_by_slash_32() {
        let g = subnet_group(&ip("2001:db8::1"));
        assert_eq!(
            g,
            (0x20u32 << 24) | (0x01u32 << 16) | (0x0du32 << 8) | 0xb8u32
        );
    }
}
