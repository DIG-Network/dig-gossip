//! Discovery bootstrap: DNS seeding and (later) introducer-first loop coordination.
//!
//! # Requirements
//!
//! - **DSC-003** — [`docs/requirements/domains/discovery/specs/DSC-003.md`](../../docs/requirements/domains/discovery/specs/DSC-003.md):
//!   DNS resolution MUST go through [`chia_sdk_client::Network::lookup_all`] (normative
//!   [`NORMATIVE.md`](../../docs/requirements/domains/discovery/NORMATIVE.md) — no custom resolver).
//! - **DSC-006** (future) — full discovery loop will call into this module first; see
//!   [`docs/requirements/domains/discovery/specs/DSC-006.md`](../../docs/requirements/domains/discovery/specs/DSC-006.md).
//! - **Master SPEC:** [`SPEC.md`](../../docs/resources/SPEC.md) §6.2 (DNS seeding).
//!
//! # Design
//!
//! - **Thin `lookup_all` wrapper:** [`dns_lookup_seed_addrs`] exists so there is exactly one
//!   auditable call site proving we do not fork Chia’s DNS batching / timeout behaviour.
//! - **Pure conversion:** [`timestamped_peer_infos_from_dns_addrs`] is synchronous and trivially
//!   unit-testable — it is the bridge to [`crate::discovery::address_manager::AddressManager::add_to_new_table`].
//! - **Orchestration:** [`dns_seed_resolve_and_merge`] is what DSC-006 will schedule on an empty
//!   address manager: resolve, merge into the **new** table, return the raw socket list for metrics.

use std::net::SocketAddr;
use std::time::Duration;

use chia_protocol::TimestampedPeerInfo;
use chia_sdk_client::Network;

use crate::discovery::address_manager::AddressManager;
use crate::types::config::GossipConfig;
use crate::types::peer::{metric_unix_timestamp_secs, PeerInfo};

/// Snapshot the [`Network`] embedded in [`GossipConfig`] for DNS operations.
///
/// DNS introducers, default P2P port, and genesis challenge all live on upstream [`Network`]
/// (API-003). Discovery code should use this helper rather than reassembling a [`Network`] from
/// scratch so configuration stays single-sourced.
pub fn dig_network_from_gossip_config(config: &GossipConfig) -> Network {
    config.network.clone()
}

/// Resolve DNS introducer hostnames to [`SocketAddr`] values using **only**
/// [`Network::lookup_all`](chia_sdk_client::Network::lookup_all).
///
/// # Parameters
///
/// - `timeout` — passed through to upstream (per-host timeout inside each batch).
/// - `batch_size` — forwarded verbatim after clamping to at least **1** (defensive guard).
///
/// # Errors / logging
///
/// Upstream logs failures and timeouts via `tracing::warn!` and returns partial or empty results;
/// this wrapper never panics and does not map DNS errors into [`crate::error::GossipError`]
/// (DSC-003 acceptance: failures are soft; the discovery loop continues).
pub async fn dns_lookup_seed_addrs(
    network: &Network,
    timeout: Duration,
    batch_size: usize,
) -> Vec<SocketAddr> {
    let batch_size = batch_size.max(1);
    network.lookup_all(timeout, batch_size).await
}

/// Convert seed resolver output into [`TimestampedPeerInfo`] rows for the address manager.
///
/// `timestamp_secs` should usually be [`metric_unix_timestamp_secs`] so rows align with
/// Chia-style gossip timestamps used elsewhere in [`crate::discovery::address_manager`].
pub fn timestamped_peer_infos_from_dns_addrs(
    addrs: &[SocketAddr],
    timestamp_secs: u64,
) -> Vec<TimestampedPeerInfo> {
    addrs
        .iter()
        .map(|addr| TimestampedPeerInfo::new(addr.ip().to_string(), addr.port(), timestamp_secs))
        .collect()
}

/// Push DNS results into the address manager **new** table (DSC-003 integration bullet).
///
/// `source` is the Chia-style gossip source [`PeerInfo`] for bucket placement — for DNS bootstrap
/// the caller may use a synthetic localhost row or a future dedicated “DNS” sentinel; tests pin
/// a deterministic `PeerInfo` so bucket keys stay stable.
pub fn merge_dns_seed_addrs_into_address_manager(
    address_manager: &AddressManager,
    addrs: &[SocketAddr],
    source: &PeerInfo,
    timestamp_secs: u64,
) {
    if addrs.is_empty() {
        return;
    }
    let rows = timestamped_peer_infos_from_dns_addrs(addrs, timestamp_secs);
    address_manager.add_to_new_table(&rows, source, 0);
}

/// Run DNS seeding using [`GossipConfig::network`], [`GossipConfig::dns_seed_timeout`], and
/// [`GossipConfig::dns_seed_batch_size`], then merge into `address_manager`.
///
/// Returns the resolved [`SocketAddr`] list (possibly empty) so callers can log counts or feed
/// metrics without re-querying.
pub async fn dns_seed_resolve_and_merge(
    config: &GossipConfig,
    address_manager: &AddressManager,
    source: &PeerInfo,
) -> Vec<SocketAddr> {
    let addrs = dns_lookup_seed_addrs(
        &config.network,
        config.dns_seed_timeout,
        config.dns_seed_batch_size,
    )
    .await;
    let ts = metric_unix_timestamp_secs();
    merge_dns_seed_addrs_into_address_manager(address_manager, &addrs, source, ts);
    addrs
}
