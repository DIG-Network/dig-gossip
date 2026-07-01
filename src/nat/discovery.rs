//! Unified multi-source peer discovery (L7 peer-network spec §4).
//!
//! A DIG Node fills its address book from TWO complementary sources, so discovery never depends on a
//! single rendezvous:
//!
//! - **§4a — the relay introducer.** [`relay_get_peers`] sends RLY-005 `get_peers` over the relay
//!   WebSocket and decodes the `peers` list of [`RelayPeerInfo`](crate::relay::relay_types::RelayPeerInfo)
//!   into [`PeerRecord`]s. A node registered with the relay is itself returned to others'
//!   `get_peers`, so registration IS the introducer advertisement.
//! - **§4b — node peer-exchange (`dig.getPeers` / `RequestPeers`).** The gossip layer already asks
//!   connected peers for their address lists ([`crate::service::gossip_handle::GossipHandle::connect_to`]
//!   sends `RequestPeers` on connect; [`crate::service::gossip_handle::GossipHandle::discover_from_introducer`]
//!   queries a dedicated introducer). Those return Chia-streamable
//!   [`TimestampedPeerInfo`](dig_protocol::TimestampedPeerInfo) which
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
        loop {
            let Some(frame) = read.next().await else {
                return Err(GossipError::RelayError(
                    "relay closed before returning peers".into(),
                ));
            };
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
                    return Ok(peers.iter().map(PeerRecord::from_relay_peer_info).collect());
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
