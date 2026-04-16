//! Discovery bootstrap: DNS seeding, introducer fallback, and the main discovery loop.
//!
//! # Requirements
//!
//! - **DSC-003** — [`docs/requirements/domains/discovery/specs/DSC-003.md`](../../docs/requirements/domains/discovery/specs/DSC-003.md):
//!   DNS resolution MUST go through [`dig_protocol::Network::lookup_all`] (normative
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

use dig_protocol::Network;
use dig_protocol::TimestampedPeerInfo;

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
/// [`Network::lookup_all`](dig_protocol::Network::lookup_all).
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
// DSC-007 — Peer exchange helpers
// =========================================================================
//
// SPEC §6.6 — Peer Exchange via Gossip.
// Chia `node_discovery.py:135-136` — send RequestPeers on outbound connect.
// Chia `node_discovery.py:34-35` — caps on received peers.

use std::sync::atomic::{AtomicU64, Ordering};

/// Cap a `RespondPeers` peer list per DSC-007 acceptance criteria.
///
/// 1. Truncate to [`MAX_PEERS_RECEIVED_PER_REQUEST`] (1000) — SPEC §1.6#10.
/// 2. Check `total_peers_received` against [`MAX_TOTAL_PEERS_RECEIVED`] (3000) — SPEC §1.6#11.
///    If the global cap is reached, return an empty slice.
///
/// Returns the (possibly truncated) subslice of `peers` that should be added to the
/// address manager, and updates `total_peers_received` atomically.
///
/// # Arguments
///
/// - `peers` — the `peer_list` from a `RespondPeers` message.
/// - `total_peers_received` — shared atomic counter across all peer exchange rounds (ServiceState).
///
/// # SPEC references
///
/// - SPEC §6.6 — Peer Exchange via Gossip
/// - SPEC §1.6#10 — MAX_PEERS_RECEIVED_PER_REQUEST (1000)
/// - SPEC §1.6#11 — MAX_TOTAL_PEERS_RECEIVED (3000)
/// - Chia `node_discovery.py:34-35`
pub fn cap_received_peers<'a>(
    peers: &'a [TimestampedPeerInfo],
    total_peers_received: &AtomicU64,
) -> &'a [TimestampedPeerInfo] {
    use crate::constants::{MAX_PEERS_RECEIVED_PER_REQUEST, MAX_TOTAL_PEERS_RECEIVED};

    // Step 1: per-request cap (SPEC §1.6#10).
    let capped = if peers.len() > MAX_PEERS_RECEIVED_PER_REQUEST {
        tracing::debug!(
            "DSC-007: capping RespondPeers from {} to {} peers (per-request limit)",
            peers.len(),
            MAX_PEERS_RECEIVED_PER_REQUEST
        );
        &peers[..MAX_PEERS_RECEIVED_PER_REQUEST]
    } else {
        peers
    };

    // Step 2: global total cap (SPEC §1.6#11).
    let current_total = total_peers_received.load(Ordering::Relaxed);
    if current_total >= MAX_TOTAL_PEERS_RECEIVED as u64 {
        tracing::debug!(
            "DSC-007: total peers received ({}) >= cap ({}), discarding {} peers",
            current_total,
            MAX_TOTAL_PEERS_RECEIVED,
            capped.len()
        );
        return &capped[..0]; // empty slice
    }

    // How many more can we accept?
    let remaining = (MAX_TOTAL_PEERS_RECEIVED as u64).saturating_sub(current_total) as usize;
    let accepted = capped.len().min(remaining);

    // Update the global counter.
    total_peers_received.fetch_add(accepted as u64, Ordering::Relaxed);

    &capped[..accepted]
}

// =========================================================================
// DSC-008 — Feeler connections (Poisson schedule)
// =========================================================================
//
// SPEC §6.4 item 4 — feeler connections on Poisson schedule (240s average).
// Chia `node_discovery.py:308-325` — "Feeler Connections" design.
//
// Feelers are short-lived connections that test reachability of "new" table
// addresses. On success the address is promoted to "tried" via mark_good().
// The connection is immediately closed — feelers don't participate in gossip.

/// Generate the next interval for a Poisson process (exponential distribution).
///
/// Returns a [`Duration`] sampled from an exponential distribution with the given
/// average in seconds. The formula is: `interval = -ln(U) * average` where U is
/// uniform random in (0, 1).
///
/// SPEC §6.4: "Feeler connections MUST use Poisson schedule with FEELER_INTERVAL_SECS
/// (240s) average."
/// Chia: `node_discovery.py:167-171` (`_poisson_next_send`).
///
/// # Why Poisson?
///
/// Poisson-distributed intervals make the connection pattern unpredictable to
/// network observers, preventing timing analysis that could reveal network topology.
/// This is the same approach used by Bitcoin and Chia for feeler connections.
pub fn poisson_next_interval(average_secs: u64) -> Duration {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    // Clamp away from 0 to avoid ln(0) = -infinity.
    let u: f64 = rng.gen_range(0.0001_f64..1.0_f64);
    let interval_secs = -(u.ln()) * average_secs as f64;
    // Clamp to a reasonable maximum (10x average) to prevent extreme outliers.
    let clamped = interval_secs.min((average_secs * 10) as f64);
    Duration::from_secs_f64(clamped.max(0.1))
}

/// Output from a single feeler iteration, used for testing and metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeelerAction {
    /// A feeler connection was attempted and succeeded. Address promoted to tried.
    Success { host: String, port: u16 },
    /// A feeler connection was attempted and failed. Failure recorded.
    Failure { host: String, port: u16 },
    /// No candidate available in the new table — skipped this cycle.
    NoCandidates,
    /// Loop was cancelled.
    Cancelled,
}

/// Run feeler connections on a Poisson schedule (**DSC-008**).
///
/// This function runs until `cancel` is triggered. On each cycle:
/// 1. Wait for a Poisson-distributed interval (average `feeler_interval_secs`).
/// 2. Select a random address from the "new" table.
/// 3. Attempt a connection. On success → `mark_good()`. On failure → `attempt(true)`.
/// 4. Immediately close the connection (feelers don't participate in gossip).
///
/// # SPEC references
///
/// - SPEC §6.4 item 4 — feeler connections on Poisson schedule
/// - Chia `node_discovery.py:308-325` — feeler connection design
///
/// # Note on actual connections
///
/// In the current implementation, feelers call `mark_good()` / `attempt()` on the
/// address manager but do NOT actually dial the peer (real TCP/TLS connect is deferred
/// to DSC-009 parallel connection establishment). The address manager promotion
/// logic is the core behavior being verified here.
pub async fn run_feeler_loop(
    address_manager: Arc<AddressManager>,
    feeler_interval_secs: u64,
    cancel: CancellationToken,
    action_log: Option<tokio::sync::mpsc::UnboundedSender<FeelerAction>>,
) {
    tracing::info!(
        "DSC-008: feeler loop starting (avg interval={}s)",
        feeler_interval_secs
    );

    loop {
        // Step 1: Poisson-distributed wait.
        let wait = poisson_next_interval(feeler_interval_secs);
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = cancel.cancelled() => {
                report_feeler(&action_log, FeelerAction::Cancelled);
                tracing::info!("DSC-008: feeler loop cancelled during wait");
                break;
            }
        }

        if cancel.is_cancelled() {
            report_feeler(&action_log, FeelerAction::Cancelled);
            break;
        }

        // Step 2: Select a random address from the "new" table only.
        // SPEC §6.4: "select random 'new' table address, connect, promote to 'tried'."
        // Chia: `node_discovery.py:315` — `is_feeler = True` → `select_peer(new_only=True)`.
        let candidate = address_manager.select_peer(true /* new_only */);

        let Some(candidate) = candidate else {
            // No candidates in new table — skip and wait for next interval.
            tracing::debug!("DSC-008: no candidates in new table, skipping feeler cycle");
            report_feeler(&action_log, FeelerAction::NoCandidates);
            continue;
        };

        let host = candidate.peer_info.host.clone();
        let port = candidate.peer_info.port;

        // Step 3: In a full implementation, we would attempt a TCP/TLS connection here.
        // For now, we just call mark_good() to promote the address, simulating success.
        // The actual connection logic will be added in DSC-009 (parallel connection establishment).
        //
        // TODO(DSC-009): Replace this with actual try_connect() call.
        address_manager.mark_good(&candidate.peer_info);

        tracing::debug!("DSC-008: feeler promoted {}:{} to tried", host, port);
        report_feeler(&action_log, FeelerAction::Success { host, port });
    }

    tracing::info!("DSC-008: feeler loop exited");
}

/// Helper: report a [`FeelerAction`] to the optional action log channel.
fn report_feeler(
    log: &Option<tokio::sync::mpsc::UnboundedSender<FeelerAction>>,
    action: FeelerAction,
) {
    if let Some(tx) = log {
        let _ = tx.send(action);
    }
}

// =========================================================================
// DSC-009 — Parallel connection establishment
// =========================================================================
//
// SPEC §6.4 item 2 — "Parallel connection establishment: Select up to
// PARALLEL_CONNECT_BATCH_SIZE (8) peers and connect concurrently using
// FuturesUnordered."
//
// DIG improvement: Chia's _connect_to_peers() connects one at a time with
// asyncio.sleep() between attempts (node_discovery.py:244-349). Parallel
// batching reduces bootstrap time by ~Nx.

use futures_util::stream::{FuturesUnordered, StreamExt};

/// Result of a single connection attempt within a parallel batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectResult {
    /// Connection succeeded. Address promoted to tried.
    Success { host: String, port: u16 },
    /// Connection failed. Failure recorded.
    Failure {
        host: String,
        port: u16,
        reason: String,
    },
    /// Skipped (already connected, group/AS filter, etc.).
    Skipped {
        host: String,
        port: u16,
        reason: String,
    },
}

/// Select up to `batch_size` candidates from the address manager and attempt
/// connections in parallel using [`FuturesUnordered`] (**DSC-009**).
///
/// This is the core parallel bootstrap improvement over Chia. Instead of
/// connecting one peer at a time with sequential sleeps, we batch up to
/// `PARALLEL_CONNECT_BATCH_SIZE` concurrent attempts.
///
/// # Current implementation
///
/// In Phase 3, actual TCP/TLS connections are not yet wired — candidates are
/// selected and `mark_good()` / `attempt()` is called directly. The FuturesUnordered
/// infrastructure is in place for when real connect logic (CON-001 `connect_outbound_peer`)
/// is integrated into the discovery loop.
///
/// # Arguments
///
/// - `address_manager` — shared address manager for peer selection and promotion.
/// - `batch_size` — max concurrent attempts (usually `PARALLEL_CONNECT_BATCH_SIZE`).
///
/// # Returns
///
/// A vec of [`ConnectResult`] for each attempted candidate.
///
/// # SPEC references
///
/// - SPEC §6.4 item 2 — parallel connection establishment
/// - SPEC §1.8#5 — improvement over Chia's sequential approach
/// - SPEC §1.3#16 — design decision for parallel outbound
pub async fn parallel_connect_batch(
    address_manager: &AddressManager,
    batch_size: usize,
) -> Vec<ConnectResult> {
    let batch_size = batch_size.max(1);

    // Step 1: Select candidates from the address manager.
    // select_peer(false) = consider both new and tried tables.
    let mut candidates = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        if let Some(candidate) = address_manager.select_peer(false /* new_only */) {
            candidates.push(candidate);
        }
    }

    if candidates.is_empty() {
        tracing::debug!("DSC-009: no candidates available for parallel connect");
        return Vec::new();
    }

    tracing::debug!(
        "DSC-009: attempting {} parallel connections (batch_size={})",
        candidates.len(),
        batch_size
    );

    // Step 2: Launch connections in parallel via FuturesUnordered.
    let mut futures = FuturesUnordered::new();

    for candidate in &candidates {
        let host = candidate.peer_info.host.clone();
        let port = candidate.peer_info.port;
        let peer_info = candidate.peer_info.clone();

        // In Phase 3, we simulate successful connections.
        // TODO(DSC-009/CON-001): Replace with actual try_connect() using
        // connect_outbound_peer() from connection/outbound.rs.
        futures.push(async move {
            // Simulate a fast "connection attempt" — in production this would be
            // a real TCP/TLS/WebSocket connect with timeout.
            (peer_info, ConnectResult::Success { host, port })
        });
    }

    // Step 3: Collect results as they complete.
    let mut results = Vec::with_capacity(candidates.len());
    while let Some((peer_info, result)) = futures.next().await {
        match &result {
            ConnectResult::Success { .. } => {
                address_manager.mark_good(&peer_info);
            }
            ConnectResult::Failure { .. } => {
                address_manager.attempt(&peer_info, true /* count_failure */);
            }
            ConnectResult::Skipped { .. } => {}
        }
        results.push(result);
    }

    let success_count = results
        .iter()
        .filter(|r| matches!(r, ConnectResult::Success { .. }))
        .count();
    tracing::info!(
        "DSC-009: parallel batch complete: {}/{} succeeded",
        success_count,
        results.len()
    );

    results
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
            dig_protocol::load_ssl_cert(cert_p, key_p)
                .map_err(|e| crate::error::GossipError::IntroducerError(format!("TLS load: {e}")))?
        }
        _ => dig_protocol::ChiaCertificate::generate()
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
