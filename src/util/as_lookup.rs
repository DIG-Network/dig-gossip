//! Cached BGP-derived AS lookups for outbound diversity caps (**DSC-010**).
//!
//! # Requirements
//!
//! - **DSC-010** — [`docs/requirements/domains/discovery/specs/DSC-010.md`]:
//!   At most one outbound per AS number. AS resolved via cached BGP prefix table.
//!   Stronger than Chia's /16 grouping (SPEC §6.4 item 3, §1.8#7).
//! - **Master SPEC:** [`SPEC.md`] §1.8#7 — AS-level diversity improvement.
//!
//! # Design
//!
//! - **`AsLookupTable`** — in-memory sorted vec of (network, prefix_len, ASN) entries.
//!   Longest-prefix-match via reverse-sorted binary search.
//! - **`AsDiversityFilter`** — tracks outbound AS numbers in a `HashSet<AsNumber>`.
//!   `is_allowed()` returns false if ASN already in outbound set.
//!   Unknown IPs (not in BGP table) fail open — allowed through.
//! - **Fallback** — if no BGP table loaded, /16 filter (DSC-011) is sole guard.
//!
//! # Chia comparison
//!
//! Chia only does /16 grouping (`node_discovery.py:296-306`). An attacker controlling
//! many /16 blocks in one AS can bypass that. AS-level grouping catches this.

use std::collections::HashSet;
use std::net::IpAddr;

/// Autonomous System number (32-bit, per RFC 6793).
pub type AsNumber = u32;

/// In-memory BGP prefix table for IP → AS resolution.
///
/// Entries sorted by (prefix_len DESC, network) for longest-prefix-match.
/// SPEC §1.8#7 — "AS numbers resolved via cached BGP prefix table."
///
/// # Loading
///
/// `AsLookupTable::from_entries()` accepts pre-parsed entries.
/// A future `load_from_file()` will parse routeviews/RIPE dumps.
/// For now, tests and config can populate directly.
#[derive(Debug, Clone)]
pub struct AsLookupTable {
    /// (network_ip, prefix_len, as_number) sorted for longest-prefix-match.
    /// Sorted by prefix_len DESC so we find longest match first in linear scan.
    /// For production BGP tables (~900K entries), a prefix trie would be faster —
    /// sorted vec + linear scan is sufficient for initial implementation.
    entries: Vec<(IpAddr, u8, AsNumber)>,
}

impl AsLookupTable {
    /// Create empty table (no BGP data — all lookups return None).
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create from pre-parsed entries.
    ///
    /// Entries are sorted internally by prefix_len descending for longest-prefix-match.
    pub fn from_entries(mut entries: Vec<(IpAddr, u8, AsNumber)>) -> Self {
        // Sort by prefix_len descending so longest match comes first in scan.
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        Self { entries }
    }

    /// Number of entries in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty (no BGP data loaded).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up the AS number for an IP using longest-prefix-match.
    ///
    /// Returns `None` if the IP is not covered by any prefix in the table.
    /// Unknown IPs should fail open (DSC-010: "allow if AS unknown").
    ///
    /// SPEC §1.8#7 — "AS numbers resolved via cached BGP prefix table."
    pub fn lookup(&self, ip: &IpAddr) -> Option<AsNumber> {
        // Linear scan over entries sorted by prefix_len DESC.
        // First match = longest prefix match.
        for &(ref network, prefix_len, asn) in &self.entries {
            if ip_in_prefix(ip, network, prefix_len) {
                return Some(asn);
            }
        }
        None
    }
}

/// Check if `ip` falls within the prefix defined by `network/prefix_len`.
fn ip_in_prefix(ip: &IpAddr, network: &IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix_len);
            (u32::from(*ip4) & mask) == (u32::from(*net4) & mask)
        }
        (IpAddr::V6(ip6), IpAddr::V6(net6)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let ip_bits = u128::from(*ip6);
            let net_bits = u128::from(*net6);
            let mask = u128::MAX << (128 - prefix_len);
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false, // v4 vs v6 mismatch
    }
}

/// Outbound AS diversity filter (**DSC-010**).
///
/// Tracks AS numbers of current outbound connections. Rejects candidates
/// whose AS is already represented in outbound set.
///
/// SPEC §6.4 item 3: "AS-level diversity — one outbound per AS."
/// SPEC §1.8#7: "AS-level grouping provides stronger eclipse resistance."
#[derive(Debug, Clone)]
pub struct AsDiversityFilter {
    /// BGP prefix table for IP → AS resolution.
    as_table: AsLookupTable,
    /// AS numbers currently represented in outbound connections.
    outbound_as_numbers: HashSet<AsNumber>,
}

impl AsDiversityFilter {
    /// Create filter with given BGP table.
    pub fn new(as_table: AsLookupTable) -> Self {
        Self {
            as_table,
            outbound_as_numbers: HashSet::new(),
        }
    }

    /// Create filter with no BGP data (all candidates allowed — /16 is sole guard).
    pub fn no_bgp_data() -> Self {
        Self::new(AsLookupTable::empty())
    }

    /// Check if candidate IP is allowed (AS not already in outbound set).
    ///
    /// Returns `true` if:
    /// - AS unknown (IP not in BGP table) — fail open per DSC-010 spec
    /// - AS not yet represented in outbound connections
    ///
    /// Returns `false` if AS already has an outbound connection.
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        match self.as_table.lookup(ip) {
            Some(asn) => !self.outbound_as_numbers.contains(&asn),
            None => true, // fail open — unknown AS allowed
        }
    }

    /// Record new outbound connection's AS.
    pub fn add_outbound(&mut self, ip: &IpAddr) {
        if let Some(asn) = self.as_table.lookup(ip) {
            self.outbound_as_numbers.insert(asn);
        }
    }

    /// Remove outbound connection's AS (on disconnect).
    pub fn remove_outbound(&mut self, ip: &IpAddr) {
        if let Some(asn) = self.as_table.lookup(ip) {
            self.outbound_as_numbers.remove(&asn);
        }
    }

    /// Current outbound AS count.
    pub fn outbound_as_count(&self) -> usize {
        self.outbound_as_numbers.len()
    }

    /// Whether BGP data is loaded.
    pub fn has_bgp_data(&self) -> bool {
        !self.as_table.is_empty()
    }
}
