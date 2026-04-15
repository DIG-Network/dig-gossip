//! Discovery bootstrap: DNS seeding, introducer fallback, and the main discovery loop.
//!
//! # Requirements
//!
//! - **DSC-003** — [`docs/requirements/domains/discovery/specs/DSC-003.md`](../../docs/requirements/domains/discovery/specs/DSC-003.md):
//!   DNS resolution MUST go through [`chia_sdk_client::Network::lookup_all`] (normative
//!   [`NORMATIVE.md`](../../docs/requirements/domains/discovery/NORMATIVE.md) — no custom resolver).
//! - **DSC-006** — [`docs/requirements/domains/discovery/specs/DSC-006.md`](../../docs/requirements/domains/discovery/specs/DSC-006.md):
//!   The discovery loop orchestrates DNS-first seeding with introducer exponential backoff.
//!   Ported from Chia `node_discovery.py:256-293` with improvements (SPEC §6.4).
//! - **Master SPEC:** [`SPEC.md`](../../docs/resources/SPEC.md) §6.2 (DNS seeding), §6.4 (discovery loop).
//!
//! # Design
//!
//! - **Thin `lookup_all` wrapper:** [`dns_lookup_seed_addrs`] exists so there is exactly one
//!   auditable call site proving we do not fork Chia’s DNS batching / timeout behaviour.
//! - **Pure conversion:** [`timestamped_peer_infos_from_dns_addrs`] is synchronous and trivially
//!   unit-testable — it is the bridge to [`crate::discovery::address_manager::AddressManager::add_to_new_table`].
//! - **Orchestration:** [`dns_seed_resolve_and_merge`] handles the DNS→AddressManager path.
//! - **Discovery loop:** [`run_discovery_loop`] is the main loop (DSC-006). It runs continuously,
//!   checking the address manager size on each iteration. When empty: DNS first, then introducer
//!   with exponential backoff (1s → 2s → 4s → ... → 300s cap). Backoff resets on success.
//!   5-second sleep between cycles when peers are available.
//!
//! # Chia comparison
//!
//! Chia’s `_connect_to_peers()` (`node_discovery.py:244-349`) combines seeding, peer selection,
//! and connection establishment in one monolithic async loop. DIG splits these concerns:
//! - **DSC-006 (this loop):** seeding only (DNS + introducer)
//! - **DSC-009 (future):** parallel connection establishment
//! - **DSC-008 (future):** feeler connections on Poisson schedule

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

// =========================================================================
// DSC-006 — Discovery loop
// =========================================================================
//
// SPEC §6.4 — Ported from Chia `node_discovery.py:256-293`.
//
// The loop runs continuously, seeding the address manager when empty:
//   1. Try DNS (round-robin across configured DNS introducers) — cheap, fast.
//   2. If DNS returns nothing, try the introducer with exponential backoff.
//   3. When peers are available, sleep 5s before the next cycle.
//
// This loop handles **seeding only**. Peer connection, feelers, and AS diversity
// are handled by DSC-007 through DSC-012 (future phases).

use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Maximum introducer backoff duration (300 seconds / 5 minutes).
/// SPEC §6.4, Chia `node_discovery.py:290-291`.
const MAX_INTRODUCER_BACKOFF_SECS: u64 = 300;

/// Sleep between discovery cycles when the address manager has peers.
/// SPEC §6.4 — "After receiving peers, wait 5 seconds before next cycle."
/// Chia `node_discovery.py:280-283`.
const DISCOVERY_CYCLE_SLEEP_SECS: u64 = 5;

/// Output from a single discovery loop iteration, used for testing and metrics.
/// Not part of the public API — callers interact via [`run_discovery_loop`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryAction {
    /// DNS seeding was attempted. `count` is the number of addresses found.
    DnsSeeded { count: usize },
    /// Introducer was queried. `count` is the number of peers received.
    IntroducerQueried { count: usize },
    /// Introducer query failed, backoff applied. `backoff_secs` is the current backoff.
    IntroducerBackoff { backoff_secs: u64 },
    /// Address manager has peers; sleeping before next cycle.
    CycleSleep,
    /// Loop was cancelled via the cancellation token.
    Cancelled,
}

/// Run the main discovery loop (**DSC-006**).
///
/// This function runs until `cancel` is triggered. On each iteration:
/// 1. If the address manager is empty: DNS seed → if empty → introducer with backoff.
/// 2. If the address manager has peers: sleep 5 seconds.
///
/// # Arguments
///
/// - `address_manager` — shared address manager (DSC-001). The loop adds peers to the "new" table.
/// - `config` — gossip configuration with DNS and introducer settings.
/// - `cancel` — cancellation token. When triggered, the loop exits cleanly.
/// - `action_log` — optional channel to report each action (for testing/metrics). Pass `None` in production.
///
/// # SPEC references
///
/// - SPEC §6.4 — Discovery loop algorithm
/// - SPEC §6.2 — DNS seeding (delegated to [`dns_seed_resolve_and_merge`])
/// - SPEC §6.5 — Introducer client (delegated to [`crate::discovery::introducer_client::IntroducerClient`])
/// - Chia `node_discovery.py:256-293` — DNS-first, introducer exponential backoff
///
/// # Cancellation safety
///
/// The loop checks `cancel.is_cancelled()` before each sleep and after each await.
/// All sleeps use `tokio::select!` with the cancellation token so the loop responds
/// promptly to shutdown signals (CNC-004).
pub async fn run_discovery_loop(
    address_manager: Arc<AddressManager>,
    config: Arc<GossipConfig>,
    cancel: CancellationToken,
    action_log: Option<tokio::sync::mpsc::UnboundedSender<DiscoveryAction>>,
) {
    // Synthetic "self" PeerInfo for address manager source parameter.
    // DNS-seeded entries use localhost as the source (consistent with Chia convention).
    let dns_source = PeerInfo {
        host: "127.0.0.1".to_string(),
        port: config.listen_addr.port(),
    };

    // SPEC §6.4: "Backoff starts at 1 second, doubles on each retry, caps at 300 seconds."
    let mut introducer_backoff_secs: u64 = 1;

    tracing::info!(
        "DSC-006: discovery loop starting (target_outbound={})",
        config.target_outbound_count
    );

    loop {
        // -- Cancellation check (before any work) --
        if cancel.is_cancelled() {
            report(&action_log, DiscoveryAction::Cancelled);
            tracing::info!("DSC-006: discovery loop cancelled");
            break;
        }

        let manager_size = address_manager.size();

        if manager_size == 0 {
            // ====================================================================
            // Phase 1: Address manager is empty — seed from DNS then introducer.
            // SPEC §6.4 step 1: "DNS seeding is attempted first."
            // Chia: node_discovery.py:262-274 — alternate DNS and introducer.
            // ====================================================================

            // -- Step 1a: Try DNS seeding (fast, low-overhead) --
            let dns_addrs =
                dns_seed_resolve_and_merge(&config, &address_manager, &dns_source).await;

            if !dns_addrs.is_empty() {
                // DNS returned peers — reset backoff and continue.
                // SPEC §6.4: "Backoff resets to 1 second when peers are successfully received."
                tracing::info!(
                    "DSC-006: DNS seeded {} addresses, resetting backoff",
                    dns_addrs.len()
                );
                introducer_backoff_secs = 1;
                report(
                    &action_log,
                    DiscoveryAction::DnsSeeded {
                        count: dns_addrs.len(),
                    },
                );
            } else {
                // -- Step 1b: DNS empty — fall back to introducer --
                // SPEC §6.4: "If DNS returns no results, query the introducer."
                // Chia: node_discovery.py:275-292

                let introducer_result = try_introducer_query(&config, &address_manager).await;

                match introducer_result {
                    Ok(count) if count > 0 => {
                        // Introducer returned peers — reset backoff.
                        tracing::info!(
                            "DSC-006: introducer returned {} peers, resetting backoff",
                            count
                        );
                        introducer_backoff_secs = 1;
                        report(&action_log, DiscoveryAction::IntroducerQueried { count });
                    }
                    _ => {
                        // Both DNS and introducer failed — apply exponential backoff.
                        // SPEC §6.4: "Exponential backoff: 1s → 2s → 4s → ... → 300s max."
                        // Chia: node_discovery.py:286-291
                        tracing::warn!(
                            "DSC-006: introducer failed, backing off {}s (max {}s)",
                            introducer_backoff_secs,
                            MAX_INTRODUCER_BACKOFF_SECS
                        );
                        report(
                            &action_log,
                            DiscoveryAction::IntroducerBackoff {
                                backoff_secs: introducer_backoff_secs,
                            },
                        );

                        // Sleep with cancellation awareness.
                        let sleep_dur = Duration::from_secs(introducer_backoff_secs);
                        tokio::select! {
                            _ = tokio::time::sleep(sleep_dur) => {}
                            _ = cancel.cancelled() => {
                                report(&action_log, DiscoveryAction::Cancelled);
                                tracing::info!("DSC-006: cancelled during backoff");
                                break;
                            }
                        }

                        // Double the backoff, cap at MAX_INTRODUCER_BACKOFF_SECS.
                        introducer_backoff_secs = (introducer_backoff_secs.saturating_mul(2))
                            .min(MAX_INTRODUCER_BACKOFF_SECS);

                        // Continue immediately to retry (no 5s cycle sleep on failure).
                        continue;
                    }
                }
            }
        }

        // ====================================================================
        // Phase 2: Address manager has peers — sleep before next cycle.
        // SPEC §6.4: "5-second wait between discovery cycles."
        // Chia: node_discovery.py:280-283 — prevents busy-looping.
        // ====================================================================
        report(&action_log, DiscoveryAction::CycleSleep);

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(DISCOVERY_CYCLE_SLEEP_SECS)) => {}
            _ = cancel.cancelled() => {
                report(&action_log, DiscoveryAction::Cancelled);
                tracing::info!("DSC-006: cancelled during cycle sleep");
                break;
            }
        }
    }

    tracing::info!("DSC-006: discovery loop exited");
}

/// Helper: report a [`DiscoveryAction`] to the optional action log channel.
fn report(
    log: &Option<tokio::sync::mpsc::UnboundedSender<DiscoveryAction>>,
    action: DiscoveryAction,
) {
    if let Some(tx) = log {
        let _ = tx.send(action);
    }
}

/// Attempt to query the introducer for peers and merge them into the address manager.
///
/// Returns `Ok(count)` on success (where `count` may be 0 for an empty response),
/// or an error on failure (timeout, TLS, transport).
///
/// **SPEC §6.5** — delegates to [`IntroducerClient::query_peers`] (DSC-004).
#[cfg(any(feature = "native-tls", feature = "rustls"))]
async fn try_introducer_query(
    config: &GossipConfig,
    address_manager: &AddressManager,
) -> Result<usize, crate::error::GossipError> {
    use crate::discovery::introducer_client::IntroducerClient;

    let intro_config = match &config.introducer {
        Some(c) if !c.endpoint.is_empty() => c,
        _ => {
            tracing::debug!("DSC-006: no introducer configured, skipping");
            return Ok(0);
        }
    };

    let cert = match (&config.cert_path, &config.key_path) {
        (cert_p, key_p) if !cert_p.is_empty() && !key_p.is_empty() => {
            chia_sdk_client::load_ssl_cert(cert_p, key_p)
                .map_err(|e| crate::error::GossipError::IntroducerError(format!("TLS load: {e}")))?
        }
        _ => chia_ssl::ChiaCertificate::generate()
            .map_err(|e| crate::error::GossipError::IntroducerError(format!("TLS gen: {e}")))?,
    };

    let timeout = Duration::from_secs(intro_config.connection_timeout_secs);

    let peers = IntroducerClient::query_peers(
        &intro_config.endpoint,
        &cert,
        config.network_id,
        config.peer_options,
        timeout,
    )
    .await?;

    let count = peers.len();
    if !peers.is_empty() {
        let source = PeerInfo {
            host: "introducer".to_string(),
            port: 0,
        };
        address_manager.add_to_new_table(&peers, &source, 0);
    }

    Ok(count)
}

/// Fallback when no TLS feature is enabled — always returns `Ok(0)`.
#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
async fn try_introducer_query(
    _config: &GossipConfig,
    _address_manager: &AddressManager,
) -> Result<usize, crate::error::GossipError> {
    tracing::debug!("DSC-006: TLS not available, skipping introducer query");
    Ok(0)
}
