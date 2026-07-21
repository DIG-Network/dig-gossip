//! Unified multi-source peer discovery (L7 peer-network spec §4).
//!
//! A DIG Node fills its address book from TWO complementary sources, so discovery never depends on a
//! single rendezvous:
//!
//! - **§4a — the relay introducer.** [`relay_get_peers`] sends RLY-005 `get_peers` over the relay
//!   WebSocket and decodes the `peers` list of [`RelayPeerInfo`](crate::relay::relay_types::RelayPeerInfo)
//!   into [`PeerRecord`]s. A node registered with the relay is itself returned to others'
//!   `get_peers`, so registration IS the introducer advertisement.
//!
//!   **Superseded as the LIVE discovery path (#870).** The pool no longer calls [`relay_get_peers`] /
//!   [`unified_discover`]: an ephemeral open→register→get_peers→close every maintenance interval kept
//!   two nodes' registration windows from ever overlapping, so neither appeared in the other's
//!   `get_peers` (the proven root cause of `connected_peers` staying `0`). `dig-nat` OWNS the relay
//!   transport now — its ONE long-lived reservation socket also discovers peers, exposed via
//!   [`RelayStatus::known_peers`](dig_nat::relay::RelayStatus::known_peers) — and dig-gossip consumes
//!   that set through [`GossipHandle::fold_relay_known_peers`](crate::service::gossip_handle::GossipHandle::fold_relay_known_peers).
//!   These functions remain only for their pure RLY-005 wire-decode tests; removing them (and the dead
//!   Phase-4 `relay/relay_client.rs` + `relay_service.rs` state machines) is tracked for the
//!   arch-audit lane.
//! - **§4b — node peer-exchange (`dig.getPeers` / `RequestPeers`).** The gossip layer already asks
//!   connected peers for their address lists ([`crate::service::gossip_handle::GossipHandle::connect_to`]
//!   sends `RequestPeers` on connect; [`crate::service::gossip_handle::GossipHandle::discover_from_introducer`]
//!   queries a dedicated introducer). Those return Chia-streamable
//!   [`TimestampedPeerInfo`](dig_peer_protocol::TimestampedPeerInfo) which
//!   [`PeerRecord::from_timestamped_peer_info`] normalizes into the same record type.
//!
//! Both sources reduce to [`PeerRecord`], which [`merge_records_into_address_manager`] folds into the
//! [`AddressManager`] — the unchanged Chia-style
//! address book the gossip discovery/feeler loops already consume. Only records that carry a DIALABLE
//! candidate address are placed by-address; a relay-only record is reached via the relay/hole-punch.
//!
//! Reusing the existing address manager here is deliberate: the discovery ALGORITHM (buckets, feeler
//! schedule, eclipse resistance) is untouched — this module only widens where addresses COME FROM to
//! the unified relay-introducer + `dig.getPeers` sources.

// `Duration` is used only by the relay-introducer discovery path (timeouts on `get_peers`), which is
// entirely `#[cfg(feature = "relay")]`; gate the import so a `--no-default-features` build stays clean.
#[cfg(feature = "relay")]
use std::time::Duration;

#[cfg(feature = "relay")]
use futures_util::{SinkExt, StreamExt};

use crate::discovery::address_manager::AddressManager;
#[cfg(feature = "relay")]
use crate::error::GossipError;
use crate::nat::peer_record::PeerRecord;
#[cfg(feature = "relay")]
use crate::relay::relay_types::RelayMessage;
use crate::types::peer::PeerInfo;

/// Relay protocol version advertised in RLY-001 `register` — matches `dig-nat`'s
/// `RELAY_PROTOCOL_VERSION` and `dig-relay`'s server so all four relay-wire copies agree.
#[cfg(feature = "relay")]
const RELAY_PROTOCOL_VERSION: u32 = 1;

/// **Audit #179 (MEDIUM finding 4) — normative.** Maximum number of non-`Peers`/non-`Error` frames
/// [`relay_get_peers`]'s read loop will `continue` past while waiting for the `peers` response.
/// The relay is explicitly untrusted; without this bound a relay (or an on-path MITM of the relay
/// WebSocket) could stream frames indefinitely, burning CPU/bandwidth for the whole `timeout`
/// window on every discovery pass. Legitimate traffic here is a handful of control frames
/// (`register_ack`, `ping`, stray notifications) — this budget is generous relative to that.
#[cfg(feature = "relay")]
pub const MAX_RELAY_DISCOVERY_FRAMES: usize = 64;

/// Query the relay introducer for known peers via RLY-005 `get_peers` → `peers` (§4a).
///
/// Opens a WebSocket to `endpoint`, registers (RLY-001, so the relay will talk to us), sends
/// `get_peers` scoped to `network_id`, and returns the first `peers` response as [`PeerRecord`]s
/// (each [`Via::Relay`](crate::nat::peer_record::Via::Relay) with no direct address — the relay
/// addresses peers by `peer_id`). Bounded by `timeout`; on expiry / transport error returns
/// [`GossipError::RelayError`].
///
/// This is the discovery counterpart to `dig-nat`'s reservation loop (which only keeps a node
/// reachable) — it actively PULLS the peer list, which the reservation loop does not do.
///
/// **Audit #179 (MEDIUM finding 4):** the relay is untrusted (see module docs). Two independent
/// bounds protect against a hostile/compromised relay: (1) the frame-read loop gives up with
/// [`GossipError::RelayError`] after [`MAX_RELAY_DISCOVERY_FRAMES`] non-terminal frames rather
/// than looping indefinitely on filler; (2) the accepted `peers` list is capped at
/// [`crate::constants::MAX_PEERS_RECEIVED_PER_REQUEST`] — the SAME per-request cap node
/// peer-exchange applies to `RespondPeers` — before being converted to [`PeerRecord`]s.
#[cfg(feature = "relay")]
pub async fn relay_get_peers(
    endpoint: &str,
    peer_id_hex: impl Into<String>,
    network_id: &str,
    timeout: Duration,
) -> Result<Vec<PeerRecord>, GossipError> {
    let peer_id_hex = peer_id_hex.into();
    let network_id = network_id.to_string();
    let work = async move {
        let (ws, _resp) = tokio_tungstenite::connect_async(endpoint)
            .await
            .map_err(|e| GossipError::RelayError(format!("connect: {e}")))?;
        let (mut write, mut read) = ws.split();

        // RLY-001: register so the relay accepts our control messages (it rejects pre-register with
        // NOT_REGISTERED). We do not need the RegisterAck to proceed to get_peers, but we must send
        // register first per the wire contract.
        send_relay(
            &mut write,
            &RelayMessage::Register {
                peer_id: peer_id_hex.clone(),
                network_id: network_id.clone(),
                protocol_version: RELAY_PROTOCOL_VERSION,
                // This is an introducer-query registration (get_peers) only — no gossip listen
                // candidates advertised (#924 B1 candidate advertisement rides dig-nat's reservation).
                listen_addrs: Vec::new(),
            },
        )
        .await?;

        // RLY-005: ask for the peer list scoped to our network.
        send_relay(
            &mut write,
            &RelayMessage::GetPeers {
                network_id: Some(network_id.clone()),
            },
        )
        .await?;

        // Read until we get a `peers` response (ignore register_ack / pings / notifications).
        //
        // Audit #179 (MEDIUM finding 4): the relay is untrusted — bound how many non-terminal
        // frames we will read before giving up, so a hostile/compromised relay cannot force this
        // loop to spin on filler frames for the entire `timeout` window.
        let mut frames_seen = 0usize;
        loop {
            if frames_seen >= MAX_RELAY_DISCOVERY_FRAMES {
                return Err(GossipError::RelayError(format!(
                    "relay sent {frames_seen} frames without a peers/error response (max {MAX_RELAY_DISCOVERY_FRAMES})"
                )));
            }
            let Some(frame) = read.next().await else {
                return Err(GossipError::RelayError(
                    "relay closed before returning peers".into(),
                ));
            };
            frames_seen += 1;
            let frame = frame.map_err(|e| GossipError::RelayError(format!("read: {e}")))?;
            let bytes = match frame {
                tokio_tungstenite::tungstenite::Message::Text(t) => t.into_bytes(),
                tokio_tungstenite::tungstenite::Message::Binary(b) => b,
                tokio_tungstenite::tungstenite::Message::Close(_) => {
                    return Err(GossipError::RelayError(
                        "relay closed before returning peers".into(),
                    ));
                }
                _ => continue,
            };
            let Ok(msg) = serde_json::from_slice::<RelayMessage>(&bytes) else {
                continue; // ignore anything unparsable; the relay is untrusted
            };
            match msg {
                RelayMessage::Peers { peers } => {
                    // Audit #179 (MEDIUM finding 4): cap the accepted peers list at the same
                    // per-request bound node peer-exchange uses (`RespondPeers`), so a single
                    // oversized `Peers` frame from an untrusted relay cannot poison the address
                    // book with an unbounded number of records.
                    let capped_len = peers
                        .len()
                        .min(crate::constants::MAX_PEERS_RECEIVED_PER_REQUEST);
                    return Ok(peers[..capped_len]
                        .iter()
                        .map(PeerRecord::from_relay_peer_info)
                        .collect());
                }
                RelayMessage::Error { code, message } => {
                    return Err(GossipError::RelayError(format!(
                        "relay error {code}: {message}"
                    )));
                }
                _ => continue,
            }
        }
    };

    match tokio::time::timeout(timeout, work).await {
        Ok(inner) => inner,
        Err(_) => Err(GossipError::RelayError("get_peers timed out".into())),
    }
}

/// Serialize + send one [`RelayMessage`] as a WebSocket text frame (JSON-over-WS wire).
#[cfg(feature = "relay")]
async fn send_relay<W>(write: &mut W, msg: &RelayMessage) -> Result<(), GossipError>
where
    W: SinkExt<tokio_tungstenite::tungstenite::Message> + Unpin,
    <W as futures_util::Sink<tokio_tungstenite::tungstenite::Message>>::Error: std::fmt::Display,
{
    let txt =
        serde_json::to_string(msg).map_err(|e| GossipError::RelayError(format!("encode: {e}")))?;
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(txt))
        .await
        .map_err(|e| GossipError::RelayError(format!("send: {e}")))
}

/// Merge discovered [`PeerRecord`]s into the address manager's **new** table, returning how many were
/// placed. `src_host`/`src_port` is the source peer (for Chia source-group bucketing).
///
/// Only records with a dialable candidate address ([`PeerRecord::to_timestamped_peer_info`] is
/// `Some`) are placed by-address; relay-only records are skipped here (they are reached via the relay,
/// not by dialing an IP). This is the single fold that widens the address book to BOTH discovery
/// sources without changing the address manager's own bucketing.
pub fn merge_records_into_address_manager(
    am: &AddressManager,
    records: &[PeerRecord],
    src_host: &str,
    src_port: u16,
) -> usize {
    let dialable: Vec<_> = records
        .iter()
        .filter_map(PeerRecord::to_timestamped_peer_info)
        .collect();
    if dialable.is_empty() {
        return 0;
    }
    let src = PeerInfo {
        host: src_host.to_string(),
        port: src_port,
    };
    let before = am.size();
    am.add_to_new_table(&dialable, &src, 0);
    am.size().saturating_sub(before)
}

/// [`merge_records_into_address_manager`], additionally capping the dialable batch through
/// [`crate::discovery::node_discovery::cap_received_peers`] against a SHARED
/// `total_peers_received` counter (**audit #179 MEDIUM finding 4** — normative, SPEC §7.0.1).
///
/// Use this at the relay-introducer call site (an explicitly untrusted, single,
/// network-configurable source): sharing the SAME atomic counter node peer-exchange
/// (`GossipHandle::connect_to`) and introducer discovery (`run_discovery_loop`) use means no
/// single discovery source — however untrusted — can add more peers, in total, across the
/// process lifetime than the combined per-request (1000) / global (3000) budget allows.
/// [`relay_get_peers`] already caps an individual oversized `Peers` response; this additionally
/// binds the CUMULATIVE contribution across repeated relay-discovery passes (the pool
/// maintenance loop calls this every interval).
pub fn merge_records_into_address_manager_capped(
    am: &AddressManager,
    records: &[PeerRecord],
    src_host: &str,
    src_port: u16,
    total_peers_received: &std::sync::atomic::AtomicU64,
) -> usize {
    let dialable: Vec<_> = records
        .iter()
        .filter_map(PeerRecord::to_timestamped_peer_info)
        .collect();
    if dialable.is_empty() {
        return 0;
    }
    let capped =
        crate::discovery::node_discovery::cap_received_peers(&dialable, total_peers_received);
    if capped.is_empty() {
        return 0;
    }
    let src = PeerInfo {
        host: src_host.to_string(),
        port: src_port,
    };
    let before = am.size();
    am.add_to_new_table(capped, &src, 0);
    am.size().saturating_sub(before)
}

/// Configuration for a [`unified_discover`] pass: which sources to consult + timeouts.
#[cfg(feature = "relay")]
#[derive(Debug, Clone)]
pub struct UnifiedDiscoveryConfig {
    /// The relay endpoint to query for the introducer peer list (§4a). Empty = skip the relay source.
    pub relay_endpoint: String,
    /// This node's `peer_id` hex (sent in the relay `register`).
    pub self_peer_id_hex: String,
    /// The network id to scope discovery to.
    pub network_id: String,
    /// Per-source timeout.
    pub timeout: Duration,
}

/// Run one unified discovery pass against the relay introducer (§4a) and return the merged
/// [`PeerRecord`]s. Node peer-exchange (§4b) is driven by the connection path
/// ([`GossipHandle::connect_to`](crate::service::gossip_handle::GossipHandle::connect_to) /
/// [`discover_from_introducer`](crate::service::gossip_handle::GossipHandle::discover_from_introducer))
/// which already merges `TimestampedPeerInfo`; callers fold both into the address book via
/// [`merge_records_into_address_manager`].
///
/// A relay-source failure is soft (logged, empty result) so discovery never blocks on the relay
/// being down — consistent with the ecosystem's graceful-fallback rule.
#[cfg(feature = "relay")]
pub async fn unified_discover(config: &UnifiedDiscoveryConfig) -> Vec<PeerRecord> {
    if config.relay_endpoint.trim().is_empty() {
        return Vec::new();
    }
    match relay_get_peers(
        &config.relay_endpoint,
        config.self_peer_id_hex.clone(),
        &config.network_id,
        config.timeout,
    )
    .await
    {
        Ok(records) => records,
        Err(e) => {
            tracing::debug!(error = %e, "relay introducer discovery failed — continuing without it");
            Vec::new()
        }
    }
}
