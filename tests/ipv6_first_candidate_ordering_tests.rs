//! IPv6-first candidate ordering — ecosystem-wide "IPv6-first, IPv4-fallback for peer
//! communication" hard rule (see the dig_ecosystem `CLAUDE.md` and this repo's `SPEC.md`).
//!
//! Peer/address SELECTION in `dig-gossip` (the [`AddressManager`](dig_gossip::discovery::address_manager::AddressManager)'s
//! `select_peer` weighted-random draw, and [`GossipHandle::gather_pool_candidates`]'s pool of
//! outbound dial candidates built from those draws) was family-blind: it never considered whether
//! a candidate address was IPv4 or IPv6 when deciding dial order. This suite proves the ordering
//! helper ([`dig_gossip::util::ip_address::order_ipv6_first`]) that both call sites now use:
//! given a mixed set of candidate addresses, IPv6 addresses sort before IPv4 addresses, with
//! relative order preserved within each family (a stable sort) so unrelated preference signals
//! (e.g. `select_peer`'s tried-vs-new bias) are not disturbed beyond the family split.
//!
//! **Family detection:** via `std::net::IpAddr::is_ipv6()` on a parsed address -- NOT a
//! `contains(':')` string check (a string check would misclassify a bracketed IPv6 host string
//! `"[::1]"` or trip over embedded IPv4-mapped textual forms).
//!
//! ## Regression: IPv6 candidates were silently dropped before ordering could even matter
//!
//! While wiring the IPv6-first fix into `gather_pool_candidates`, testing surfaced a SEPARATE,
//! pre-existing bug that made the family-blind ordering moot for IPv6 in practice: the function
//! built each candidate's `SocketAddr` via `format!("{host}:{port}").parse::<SocketAddr>()`. An
//! **unbracketed** IPv6 literal formatted this way (e.g. `"2001:db8::1:9444"` for host
//! `"2001:db8::1"` + port `9444`) is not a valid `SocketAddr` string -- `SocketAddr`'s `FromStr`
//! requires IPv6 hosts to be bracketed (`"[2001:db8::1]:9444"`) so the port separator is
//! unambiguous. The parse failed and the candidate was silently `continue`d past, so **every**
//! IPv6 entry in the address book was dropped before it ever reached the ordering step -- an
//! IPv6-only network would have had ZERO dialable candidates. Fixed by parsing the host as an
//! [`std::net::IpAddr`] first and combining it with the port via [`std::net::SocketAddr::new`]
//! (see `gather_pool_candidates` in `src/service/gossip_handle.rs`), which handles both families
//! without ever constructing an ambiguous address string.
//! [`gathered_pool_candidates_are_ipv6_first`] below is the regression test for both the parsing
//! drop and the ordering gap; [`ipv6_hosts_survive_pool_candidate_gathering`] isolates just the
//! parsing regression with a single-family (all-IPv6) address book.

use std::net::SocketAddr;

use dig_gossip::util::ip_address::order_ipv6_first;

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("valid test SocketAddr")
}

/// A mixed IPv4/IPv6 candidate list is reordered so every IPv6 candidate precedes every IPv4
/// candidate, regardless of input order.
#[test]
fn ipv6_candidates_sort_before_ipv4_candidates() {
    let candidates = vec![
        addr("203.0.113.1:9444"),
        addr("[2001:db8::1]:9444"),
        addr("198.51.100.7:9444"),
        addr("[2001:db8::2]:9444"),
    ];

    let ordered = order_ipv6_first(candidates);

    assert!(
        ordered[0].is_ipv6() && ordered[1].is_ipv6(),
        "both IPv6 candidates must sort first, got {ordered:?}"
    );
    assert!(
        ordered[2].is_ipv4() && ordered[3].is_ipv4(),
        "both IPv4 candidates must sort last, got {ordered:?}"
    );
}

/// Relative order within each address family is preserved (stable sort) -- the IPv6-first rule
/// only splits families, it does not otherwise re-rank a caller's existing preference order
/// (e.g. `select_peer`'s tried-vs-new bias, or discovery's most-preferred-first ordering).
#[test]
fn relative_order_within_each_family_is_preserved() {
    let v6_a = addr("[2001:db8::a]:9444");
    let v6_b = addr("[2001:db8::b]:9444");
    let v4_a = addr("203.0.113.10:9444");
    let v4_b = addr("203.0.113.20:9444");

    let candidates = vec![v4_a, v6_a, v4_b, v6_b];
    let ordered = order_ipv6_first(candidates);

    assert_eq!(ordered, vec![v6_a, v6_b, v4_a, v4_b]);
}

/// An all-IPv6 list is left in its original order (no IPv4 to demote).
#[test]
fn all_ipv6_list_is_unchanged() {
    let candidates = vec![addr("[::1]:9444"), addr("[2001:db8::1]:9444")];
    let ordered = order_ipv6_first(candidates.clone());
    assert_eq!(ordered, candidates);
}

/// An all-IPv4 list is left in its original order (no IPv6 to promote) -- IPv4-only peers /
/// networks still work exactly as before (IPv4 remains the fallback, not removed).
#[test]
fn all_ipv4_list_is_unchanged() {
    let candidates = vec![addr("203.0.113.1:9444"), addr("198.51.100.7:9444")];
    let ordered = order_ipv6_first(candidates.clone());
    assert_eq!(ordered, candidates);
}

/// An empty candidate list stays empty (no panic on the boundary case).
#[test]
fn empty_list_stays_empty() {
    let ordered = order_ipv6_first(Vec::<SocketAddr>::new());
    assert!(ordered.is_empty());
}

// -------------------------------------------------------------------------------------------------
// End-to-end: `GossipHandle`'s pool-candidate gathering applies the IPv6-first ordering.
// -------------------------------------------------------------------------------------------------
//
// The unit tests above prove `order_ipv6_first` itself; this proves the REAL call site
// (`GossipHandle::gather_pool_candidates`, the outbound-dial candidate source `run_pool_maintenance_once`
// feeds to the planner) actually routes its address-manager draw through it. Seeds a mixed IPv4/IPv6
// address book via the `__seed_address_book_for_tests` hook (bypasses the `connect_to` + `RequestPeers`
// round trip) and reads the gathered order back via `__pool_gathered_candidates_for_tests` -- both
// `#[doc(hidden)]` test-only hooks on `GossipHandle`, following this crate's existing `__..._for_tests`
// convention (see e.g. `__con001_last_address_batch_for_tests`).

mod common;

/// A mixed address book yields IPv6-first, IPv4-fallback pool candidates: every gathered IPv6
/// candidate precedes every gathered IPv4 candidate, and repeated draws eventually surface every
/// seeded address (nothing is dropped -- IPv4 remains the fallback, not removed).
///
/// `gather_pool_candidates` draws from `AddressManager::select_peer`, a Bitcoin/Chia-style
/// WEIGHTED-RANDOM single-address draw (see `address_manager.rs::select_peer_`) -- a single small
/// draw is not guaranteed to surface every address in one call. The test therefore draws
/// repeatedly (each call re-samples independently) both to prove the ORDERING property holds on
/// every draw that contains a mix, and to confirm across draws that no address family is starved
/// out entirely by the fix.
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
    // Enough independent draws that, with 6 addresses roughly evenly weighted, every address is
    // seen with overwhelming probability -- flakiness budget, not a magic number tied to the fix.
    for _ in 0..200 {
        let candidates = handle.__pool_gathered_candidates_for_tests(seeded.len());
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

/// Regression: an all-IPv6 address book must still yield gathered pool candidates.
///
/// Isolates the `format!("{host}:{port}").parse::<SocketAddr>()` bug documented at the top of
/// this file: with only IPv6 entries in the address book, the unbracketed-string parse failure
/// meant EVERY draw silently produced zero candidates. This would have made an IPv6-only network
/// (or an IPv6-only bootstrap set) completely undialable regardless of the IPv6-first ordering.
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
        let candidates = handle.__pool_gathered_candidates_for_tests(seeded.len());
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
