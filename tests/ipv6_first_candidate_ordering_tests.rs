//! IPv6-first candidate ordering + local∩candidate family INTERSECTION — the ecosystem-wide
//! "IPv6-first, IPv4-fallback for peer communication" hard rule (dig_ecosystem `CLAUDE.md` §5.2 /
//! this repo's `SPEC.md` §1.10), whose single canonical implementation is the [`dig_ip`] crate.
//!
//! Peer/address SELECTION in `dig-gossip` (the [`AddressManager`](dig_gossip::discovery::address_manager::AddressManager)'s
//! `select_peer` weighted-random draw, and [`GossipHandle::gather_pool_candidates`]'s pool of
//! outbound dial candidates built from those draws) is family-blind. This suite proves the ordering
//! helper ([`dig_gossip::util::ip_address::order_by_local_stack`]) that the pool call site now uses,
//! delegating family classification to [`dig_ip::Family`] and the local-capability check to
//! [`dig_ip::LocalStack`]:
//!
//! - **IPv6-first** — given a mixed candidate set, IPv6 addresses sort before IPv4 addresses, with
//!   relative order preserved within each family (a stable partition) so unrelated preference
//!   signals (`select_peer`'s tried-vs-new bias) are not disturbed beyond the family split.
//! - **Local∩candidate intersection (the new correctness of #1030 / epic #1020)** — a candidate of
//!   a family the LOCAL host cannot originate on is DROPPED, so an IPv4-only host never emits an IPv6
//!   SYN and an IPv6-only host never emits an IPv4 SYN. A disjoint local/candidate pair yields no
//!   candidates (a clean empty — the multi-peer analog of `dig_ip::dial_order`'s `NoCommonFamily`),
//!   never a doomed attempt that hangs.
//!
//! ## Regression: IPv6 candidates were silently dropped before ordering could even matter
//!
//! While wiring the IPv6-first fix into `gather_pool_candidates`, testing surfaced a SEPARATE,
//! pre-existing bug: the function built each candidate's `SocketAddr` via
//! `format!("{host}:{port}").parse::<SocketAddr>()`. An **unbracketed** IPv6 literal formatted this
//! way (e.g. `"2001:db8::1:9444"` for host `"2001:db8::1"` + port `9444`) is not a valid
//! `SocketAddr` string, so the parse failed and the candidate was silently `continue`d past — every
//! IPv6 entry in the address book was dropped before it ever reached the ordering step. Fixed by
//! parsing the host as an [`std::net::IpAddr`] first and combining it with the port via
//! [`std::net::SocketAddr::new`]. [`gathered_pool_candidates_are_ipv6_first`] is the regression test
//! for both the parsing drop and the ordering gap; [`ipv6_hosts_survive_pool_candidate_gathering`]
//! isolates just the parsing regression with a single-family (all-IPv6) address book.

use std::net::SocketAddr;

use dig_gossip::util::ip_address::order_by_local_stack;
use dig_ip::LocalStack;

/// A dual-stack host reachable on both families — the ordering-property fixture (no family dropped).
const DUAL: LocalStack = LocalStack::from_flags(true, true);

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("valid test SocketAddr")
}

/// A mixed IPv4/IPv6 candidate list is reordered so every IPv6 candidate precedes every IPv4
/// candidate, regardless of input order (on a dual-stack host, so nothing is filtered).
#[test]
fn ipv6_candidates_sort_before_ipv4_candidates() {
    let candidates = vec![
        addr("203.0.113.1:9444"),
        addr("[2001:db8::1]:9444"),
        addr("198.51.100.7:9444"),
        addr("[2001:db8::2]:9444"),
    ];

    let ordered = order_by_local_stack(&DUAL, &candidates);

    assert!(
        ordered[0].is_ipv6() && ordered[1].is_ipv6(),
        "both IPv6 candidates must sort first, got {ordered:?}"
    );
    assert!(
        ordered[2].is_ipv4() && ordered[3].is_ipv4(),
        "both IPv4 candidates must sort last, got {ordered:?}"
    );
}

/// Relative order within each address family is preserved (stable partition) -- the IPv6-first rule
/// only splits families, it does not otherwise re-rank a caller's existing preference order
/// (e.g. `select_peer`'s tried-vs-new bias, or discovery's most-preferred-first ordering).
#[test]
fn relative_order_within_each_family_is_preserved() {
    let v6_a = addr("[2001:db8::a]:9444");
    let v6_b = addr("[2001:db8::b]:9444");
    let v4_a = addr("203.0.113.10:9444");
    let v4_b = addr("203.0.113.20:9444");

    let candidates = vec![v4_a, v6_a, v4_b, v6_b];
    let ordered = order_by_local_stack(&DUAL, &candidates);

    assert_eq!(ordered, vec![v6_a, v6_b, v4_a, v4_b]);
}

/// An all-IPv6 list on a dual-stack host is left in its original order (no IPv4 to demote).
#[test]
fn all_ipv6_list_is_unchanged() {
    let candidates = vec![addr("[::1]:9444"), addr("[2001:db8::1]:9444")];
    let ordered = order_by_local_stack(&DUAL, &candidates);
    assert_eq!(ordered, candidates);
}

/// An all-IPv4 list on a dual-stack host is left in its original order (no IPv6 to promote) -- IPv4
/// peers still work as before (IPv4 remains the fallback, not removed).
#[test]
fn all_ipv4_list_is_unchanged() {
    let candidates = vec![addr("203.0.113.1:9444"), addr("198.51.100.7:9444")];
    let ordered = order_by_local_stack(&DUAL, &candidates);
    assert_eq!(ordered, candidates);
}

/// An empty candidate list stays empty (no panic on the boundary case).
#[test]
fn empty_list_stays_empty() {
    let ordered = order_by_local_stack(&DUAL, &[]);
    assert!(ordered.is_empty());
}

/// G1 — an IPv4-only host drops every IPv6 candidate (never emits an IPv6 SYN it cannot route).
#[test]
fn ipv4_only_host_drops_ipv6_candidates() {
    let candidates = vec![addr("[2001:db8::1]:9444"), addr("203.0.113.1:9444")];
    let ordered = order_by_local_stack(&LocalStack::from_flags(false, true), &candidates);
    assert_eq!(ordered, vec![addr("203.0.113.1:9444")]);
    assert!(ordered.iter().all(|a| a.is_ipv4()));
}

/// G1 mirror — an IPv6-only host drops every IPv4 candidate.
#[test]
fn ipv6_only_host_drops_ipv4_candidates() {
    let candidates = vec![addr("[2001:db8::1]:9444"), addr("203.0.113.1:9444")];
    let ordered = order_by_local_stack(&LocalStack::from_flags(true, false), &candidates);
    assert_eq!(ordered, vec![addr("[2001:db8::1]:9444")]);
    assert!(ordered.iter().all(|a| a.is_ipv6()));
}

/// Disjoint local/candidate families → no candidates (multi-peer analog of `NoCommonFamily`): an
/// IPv4-only host with only IPv6 candidates has nothing dialable, a clean empty and no hang.
#[test]
fn disjoint_families_yield_no_candidates() {
    let candidates = vec![addr("[2001:db8::1]:9444"), addr("[2001:db8::2]:9444")];
    let ordered = order_by_local_stack(&LocalStack::from_flags(false, true), &candidates);
    assert!(ordered.is_empty());
}

// -------------------------------------------------------------------------------------------------
// End-to-end: `GossipHandle`'s pool-candidate gathering applies the IPv6-first ordering + intersection.
// -------------------------------------------------------------------------------------------------
//
// The unit tests above prove `order_by_local_stack` itself; these prove the REAL call site
// (`GossipHandle::gather_pool_candidates`) routes its address-manager draw through it. Seeds a mixed
// IPv4/IPv6 address book via the `__seed_address_book_for_tests` hook and reads the gathered order
// back via `__pool_gathered_candidates_with_stack_for_tests` -- a `#[doc(hidden)]` test-only hook
// that injects an EXPLICIT `dig_ip::LocalStack`, so the result is deterministic regardless of the CI
// runner's real IPv6/IPv4 capability (the production `gather_pool_candidates` uses the live stack).

mod common;

/// A mixed address book on a dual-stack host yields IPv6-first, IPv4-fallback pool candidates: every
/// gathered IPv6 candidate precedes every gathered IPv4 candidate, and repeated draws eventually
/// surface every seeded address (nothing dropped -- IPv4 remains the fallback).
///
/// `gather_pool_candidates` draws from `AddressManager::select_peer`, a WEIGHTED-RANDOM single-address
/// draw -- a single small draw is not guaranteed to surface every address, so the test draws
/// repeatedly to prove the ORDERING property holds on every mixed draw and that no family is starved.
#[tokio::test]
async fn gathered_pool_candidates_are_ipv6_first() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = dig_gossip::GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");

    // Seed a deliberately IPv4-heavy-first address book so a family-blind draw would very likely
    // surface IPv4 candidates before IPv6 ones absent the fix.
    let seeded = [
        ("203.0.113.1".to_string(), 9444),
        ("198.51.100.7".to_string(), 9444),
        ("203.0.113.2".to_string(), 9444),
        ("2001:db8::1".to_string(), 9444),
        ("2001:db8::2".to_string(), 9444),
        ("203.0.113.3".to_string(), 9444),
    ];
    handle.__seed_address_book_for_tests(&seeded);
    assert_eq!(
        handle.stats().await.known_addresses,
        seeded.len(),
        "every seeded address must land in the address book"
    );

    let mut seen: std::collections::HashSet<SocketAddr> = std::collections::HashSet::new();
    let mut saw_ipv6 = false;
    let mut saw_ipv4 = false;
    for _ in 0..200 {
        // Dual-stack injected stack: both families are kept, so ordering is what is under test.
        let candidates =
            handle.__pool_gathered_candidates_with_stack_for_tests(seeded.len(), true, true);
        let addrs: Vec<SocketAddr> = candidates.iter().filter_map(|c| c.addr).collect();

        // The ordering property must hold on EVERY draw that contains both families.
        let first_ipv4_pos = addrs.iter().position(|a| a.is_ipv4());
        let last_ipv6_pos = addrs.iter().rposition(|a| a.is_ipv6());
        if let (Some(first_v4), Some(last_v6)) = (first_ipv4_pos, last_ipv6_pos) {
            assert!(
                last_v6 < first_v4,
                "every IPv6 candidate must precede every IPv4 candidate, got {addrs:?}"
            );
        }

        saw_ipv6 |= addrs.iter().any(|a| a.is_ipv6());
        saw_ipv4 |= addrs.iter().any(|a| a.is_ipv4());
        seen.extend(addrs);

        if seen.len() == seeded.len() {
            break;
        }
    }

    assert_eq!(
        seen.len(),
        seeded.len(),
        "every seeded address should surface across repeated draws (none silently dropped): {seen:?}"
    );
    assert!(
        saw_ipv6,
        "expected at least one draw to include an IPv6 candidate"
    );
    assert!(
        saw_ipv4,
        "expected at least one draw to include an IPv4 candidate (fallback retained)"
    );

    let _ = svc.stop().await;
}

/// G1 end-to-end: on an IPv4-only host, a mixed address book yields ONLY IPv4 pool candidates -- the
/// local∩candidate intersection drops every IPv6 address before it can be dialed.
#[tokio::test]
async fn gathered_pool_candidates_respect_local_stack_intersection() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = dig_gossip::GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");

    let seeded = [
        ("203.0.113.1".to_string(), 9444),
        ("2001:db8::1".to_string(), 9444),
        ("203.0.113.2".to_string(), 9444),
        ("2001:db8::2".to_string(), 9444),
    ];
    handle.__seed_address_book_for_tests(&seeded);
    assert_eq!(handle.stats().await.known_addresses, seeded.len());

    for _ in 0..200 {
        // IPv4-only injected stack: every gathered candidate MUST be IPv4 (G1 — never a family the
        // host lacks), no matter which address the weighted-random draw picked.
        let candidates =
            handle.__pool_gathered_candidates_with_stack_for_tests(seeded.len(), false, true);
        for c in candidates.iter().filter_map(|c| c.addr) {
            assert!(
                c.is_ipv4(),
                "an IPv4-only host must never gather an IPv6 candidate, got {c:?}"
            );
        }
    }

    let _ = svc.stop().await;
}

/// Regression: an all-IPv6 address book on a dual-stack host must still yield gathered pool
/// candidates (isolates the `format!("{host}:{port}").parse::<SocketAddr>()` drop bug).
#[tokio::test]
async fn ipv6_hosts_survive_pool_candidate_gathering() {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = dig_gossip::GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");

    let seeded = [
        ("2001:db8::1".to_string(), 9444),
        ("2001:db8::2".to_string(), 9444),
        ("2001:db8::3".to_string(), 9444),
    ];
    handle.__seed_address_book_for_tests(&seeded);
    assert_eq!(handle.stats().await.known_addresses, seeded.len());

    let mut seen: std::collections::HashSet<SocketAddr> = std::collections::HashSet::new();
    for _ in 0..200 {
        // Dual-stack so the IPv6 candidates are not filtered by the intersection.
        let candidates =
            handle.__pool_gathered_candidates_with_stack_for_tests(seeded.len(), true, true);
        seen.extend(candidates.iter().filter_map(|c| c.addr));
        if seen.len() == seeded.len() {
            break;
        }
    }

    assert_eq!(
        seen.len(),
        seeded.len(),
        "every IPv6-only seeded address should be gathered as a dialable candidate: {seen:?}"
    );
    assert!(seen.iter().all(|a| a.is_ipv6()));

    let _ = svc.stop().await;
}
