//! Cheap clone handle for callers to broadcast, query stats, and shut down.
//!
//! **Requirement:** API-002 /
//! [`docs/requirements/domains/crate_api/specs/API-002.md`](../../../docs/requirements/domains/crate_api/specs/API-002.md)
//! and [`SPEC.md`](../../../docs/resources/SPEC.md) §3.3.
//!
//! ## Deviations from the markdown spec (Rust ownership)
//!
//! - **`inbound_receiver`:** SPEC shows `&mpsc::Receiver<_>` while [`GossipHandle`] is [`Clone`].
//!   Cloning a handle cannot share a single-consumer `mpsc` receiver safely. We return a
//!   [`broadcast::Receiver`] subscription (see [`ServiceState::inbound_tx`](super::state::ServiceState::inbound_tx)).
//! - **`connected_peers` / `get_connections`:** Returning real [`crate::types::peer::PeerConnection`]
//!   values requires live [`chia_sdk_client::Peer`] handles (CON-001). These methods return an empty
//!   vector until the connection layer can populate them (TRACKING notes).

use chia_protocol::{
    ChiaProtocolMessage, Message, NodeType, RequestPeers, RespondPeers, TimestampedPeerInfo,
};
use chia_traits::Streamable;
use std::any::TypeId;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::constants::PENALTY_BAN_THRESHOLD;
use crate::error::GossipError;
use crate::types::peer::{PeerConnection, PeerId};
use crate::types::reputation::PenaltyReason;
use crate::types::stats::{GossipStats, RelayStats};

use super::state::{peer_id_for_addr, ServiceState, StubPeer};

/// Cloneable façade over the shared [`ServiceState`] (`Arc`).
#[derive(Debug, Clone)]
pub struct GossipHandle {
    pub(crate) inner: Arc<ServiceState>,
}

impl GossipHandle {
    fn require_running(&self) -> Result<(), GossipError> {
        if self.inner.is_running() {
            Ok(())
        } else {
            Err(GossipError::ServiceNotStarted)
        }
    }

    /// API-001 lifecycle probe — still used by older tests.
    pub async fn health_check(&self) -> Result<(), GossipError> {
        self.require_running()
    }

    /// Subscribe to inbound `(sender_peer_id, wire_message)` pairs.
    ///
    /// **SPEC:** [`SPEC.md`](../../../docs/resources/SPEC.md) §3.3 — see module docs for the
    /// `broadcast` vs `mpsc` deviation.
    pub fn inbound_receiver(&self) -> Result<broadcast::Receiver<(PeerId, Message)>, GossipError> {
        self.require_running()?;
        let g = self
            .inner
            .inbound_tx
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?;
        let tx = g.as_ref().ok_or(GossipError::ServiceNotStarted)?;
        Ok(tx.subscribe())
    }

    /// Broadcast a wire [`Message`] to the stub peer set; returns how many peers would receive it.
    ///
    /// **Stub:** increments [`ServiceState::messages_sent`] by the per-peer delivery count. With zero
    /// peers, returns `Ok(0)` (API-002 implementation notes).
    pub async fn broadcast(
        &self,
        message: Message,
        exclude: Option<PeerId>,
    ) -> Result<usize, GossipError> {
        self.require_running()?;
        let _ = message; // CON-* will forward bytes to `Peer::send_raw`.
        let mut n = self
            .inner
            .peers
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .len();
        if let Some(e) = exclude {
            if self
                .inner
                .peers
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?
                .contains_key(&e)
            {
                n = n.saturating_sub(1);
            }
        }
        self.inner
            .messages_sent
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }

    /// Serialize `body` with [`Streamable`] and delegate to [`Self::broadcast`].
    pub async fn broadcast_typed<T: Streamable + ChiaProtocolMessage + Send>(
        &self,
        body: T,
        exclude: Option<PeerId>,
    ) -> Result<usize, GossipError> {
        let msg = encode_message(&body)?;
        self.broadcast(msg, exclude).await
    }

    /// Send a typed message to one stub peer.
    pub async fn send_to<T: Streamable + ChiaProtocolMessage + Send>(
        &self,
        peer_id: PeerId,
        body: T,
    ) -> Result<(), GossipError> {
        self.require_running()?;
        let _ = encode_message(&body)?;
        if self
            .inner
            .banned
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .contains(&peer_id)
        {
            return Err(GossipError::PeerBanned(peer_id));
        }
        if !self
            .inner
            .peers
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .contains_key(&peer_id)
        {
            return Err(GossipError::PeerNotConnected(peer_id));
        }
        self.inner
            .messages_sent
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Typed request/response — **stub** implements `RequestPeers → RespondPeers` via [`TypeId`];
    /// other pairs time out after [`DEFAULT_GOSSIP_REQUEST_TIMEOUT_SECS`].
    pub async fn request<T, B>(&self, peer_id: PeerId, body: B) -> Result<T, GossipError>
    where
        T: Streamable + ChiaProtocolMessage + Send + 'static,
        B: Streamable + ChiaProtocolMessage + Send + 'static,
    {
        self.require_running()?;
        let _ = encode_message(&body)?;
        if self
            .inner
            .banned
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .contains(&peer_id)
        {
            return Err(GossipError::PeerBanned(peer_id));
        }
        if !self
            .inner
            .peers
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .contains_key(&peer_id)
        {
            return Err(GossipError::PeerNotConnected(peer_id));
        }

        if TypeId::of::<B>() == TypeId::of::<RequestPeers>()
            && TypeId::of::<T>() == TypeId::of::<RespondPeers>()
        {
            let resp = empty_respond_peers()?;
            let bytes = resp
                .to_bytes()
                .map_err(|e| GossipError::from(chia_sdk_client::ClientError::Streamable(e)))?;
            return T::from_bytes(&bytes)
                .map_err(|e| GossipError::from(chia_sdk_client::ClientError::Streamable(e)));
        }

        // Unimplemented request/response pairs: fail fast (CON-001 will add real timeouts via
        // `Peer::request_infallible` and `DEFAULT_GOSSIP_REQUEST_TIMEOUT_SECS` from `constants`).
        Err(GossipError::RequestTimeout)
    }

    /// Always empty until CON-001 builds [`PeerConnection`] from live peers (see module docs).
    pub async fn connected_peers(&self) -> Vec<PeerConnection> {
        let _ = self.require_running();
        Vec::new()
    }

    pub async fn peer_count(&self) -> usize {
        self.inner.peers.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub async fn get_connections(
        &self,
        _node_type: Option<NodeType>,
        _outbound_only: bool,
    ) -> Vec<PeerConnection> {
        let _ = self.require_running();
        Vec::new()
    }

    /// Stub `connect_to`: records a synthetic peer until CON-001 calls `connect_peer`.
    pub async fn connect_to(&self, addr: std::net::SocketAddr) -> Result<PeerId, GossipError> {
        self.connect_stub_inner(addr, NodeType::FullNode, true)
            .await
    }

    async fn connect_stub_inner(
        &self,
        addr: std::net::SocketAddr,
        node_type: NodeType,
        is_outbound: bool,
    ) -> Result<PeerId, GossipError> {
        self.require_running()?;
        if addr == self.inner.config.listen_addr {
            return Err(GossipError::SelfConnection);
        }
        let pid = peer_id_for_addr(addr);
        if self
            .inner
            .banned
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .contains(&pid)
        {
            return Err(GossipError::PeerBanned(pid));
        }
        let mut peers = self
            .inner
            .peers
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?;
        if peers.contains_key(&pid) {
            return Err(GossipError::DuplicateConnection(pid));
        }
        if peers.len() >= self.inner.config.max_connections {
            return Err(GossipError::MaxConnectionsReached(
                self.inner.config.max_connections,
            ));
        }
        peers.insert(
            pid,
            StubPeer {
                remote: addr,
                node_type,
                is_outbound,
            },
        );
        drop(peers);
        self.inner
            .total_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(pid)
    }

    /// Test hook: model an **inbound** stub (different [`NodeType`] / direction) without real TCP.
    #[doc(hidden)]
    pub async fn __connect_stub_peer_with_direction(
        &self,
        addr: std::net::SocketAddr,
        node_type: NodeType,
        is_outbound: bool,
    ) -> Result<PeerId, GossipError> {
        self.connect_stub_inner(addr, node_type, is_outbound).await
    }

    /// How many stub rows match [`Self::get_connections`] filters (until CON-001 returns real [`PeerConnection`]s).
    #[doc(hidden)]
    pub async fn __stub_filter_count_for_tests(
        &self,
        node_type: Option<NodeType>,
        outbound_only: bool,
    ) -> usize {
        let peers = match self.inner.peers.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        peers
            .values()
            .filter(|p| {
                node_type.is_none_or(|nt| nt == p.node_type) && (!outbound_only || p.is_outbound)
            })
            .count()
    }

    pub async fn disconnect(&self, peer_id: &PeerId) -> Result<(), GossipError> {
        self.require_running()?;
        self.inner
            .peers
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .remove(peer_id);
        Ok(())
    }

    pub async fn ban_peer(
        &self,
        peer_id: &PeerId,
        _reason: PenaltyReason,
    ) -> Result<(), GossipError> {
        self.require_running()?;
        self.inner
            .banned
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .insert(*peer_id);
        self.inner
            .peers
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?
            .remove(peer_id);
        Ok(())
    }

    pub async fn penalize_peer(
        &self,
        peer_id: &PeerId,
        reason: PenaltyReason,
    ) -> Result<(), GossipError> {
        self.require_running()?;
        let add = reason.penalty_points();
        let should_ban = {
            let mut p = self
                .inner
                .penalties
                .lock()
                .map_err(|_| GossipError::ChannelClosed)?;
            let e = p.entry(*peer_id).or_insert(0);
            *e = e.saturating_add(add);
            *e >= PENALTY_BAN_THRESHOLD
        };
        if should_ban {
            self.ban_peer(peer_id, reason).await?;
        }
        Ok(())
    }

    pub async fn discover_from_introducer(&self) -> Result<Vec<TimestampedPeerInfo>, GossipError> {
        self.require_running()?;
        if self.inner.config.introducer.is_none() {
            return Err(GossipError::IntroducerNotConfigured);
        }
        Ok(Vec::new())
    }

    pub async fn register_with_introducer(&self) -> Result<(), GossipError> {
        self.require_running()?;
        if self.inner.config.introducer.is_none() {
            return Err(GossipError::IntroducerNotConfigured);
        }
        Ok(())
    }

    pub async fn request_peers_from(&self, peer_id: &PeerId) -> Result<RespondPeers, GossipError> {
        self.request(*peer_id, RequestPeers::new()).await
    }

    /// Snapshot gossip observability (API-008 / SPEC §3.4).
    ///
    /// Assembled from [`ServiceState`](super::state::ServiceState) with short mutex holds; byte counters stay
    /// at `0` in the stub until CON-* meters wire traffic.
    pub async fn stats(&self) -> GossipStats {
        let messages_sent = self
            .inner
            .messages_sent
            .load(std::sync::atomic::Ordering::Relaxed);
        let messages_received = self
            .inner
            .messages_received
            .load(std::sync::atomic::Ordering::Relaxed);
        let bytes_sent = self
            .inner
            .bytes_sent
            .load(std::sync::atomic::Ordering::Relaxed);
        let bytes_received = self
            .inner
            .bytes_received
            .load(std::sync::atomic::Ordering::Relaxed);
        let total_connections = self
            .inner
            .total_connections
            .load(std::sync::atomic::Ordering::Relaxed) as usize;

        let (connected_peers, inbound_connections, outbound_connections, seen_messages) = {
            let peers = match self.inner.peers.lock() {
                Ok(g) => g,
                Err(_) => {
                    return GossipStats {
                        total_connections,
                        messages_sent,
                        messages_received,
                        bytes_sent,
                        bytes_received,
                        ..Default::default()
                    };
                }
            };
            let mut inb = 0usize;
            let mut out = 0usize;
            for p in peers.values() {
                if p.is_outbound {
                    out += 1;
                } else {
                    inb += 1;
                }
            }
            let connected = peers.len();
            drop(peers);
            let seen = self
                .inner
                .seen_messages
                .lock()
                .map(|c| c.len())
                .unwrap_or(0);
            (connected, inb, out, seen)
        };

        GossipStats {
            total_connections,
            connected_peers,
            inbound_connections,
            outbound_connections,
            messages_sent,
            messages_received,
            bytes_sent,
            bytes_received,
            known_addresses: 0,
            seen_messages,
            // Stub until RLY-*: mirror [`RelayStats::connected`] (always false with `RelayStats::default()`).
            relay_connected: false,
            relay_peer_count: 0,
        }
    }

    /// `Some(RelayStats)` only when [`GossipConfig::relay`](crate::types::config::GossipConfig::relay) is set;
    /// values are stubs (`Default`) until RLY-* implements the relay client.
    pub async fn relay_stats(&self) -> Option<RelayStats> {
        if self.inner.config.relay.is_none() {
            None
        } else {
            Some(RelayStats::default())
        }
    }

    /// Test helper: push a synthetic inbound event into the broadcast hub.
    #[doc(hidden)]
    pub fn __inject_inbound_for_tests(
        &self,
        sender: PeerId,
        message: Message,
    ) -> Result<(), GossipError> {
        self.require_running()?;
        let g = self
            .inner
            .inbound_tx
            .lock()
            .map_err(|_| GossipError::ChannelClosed)?;
        let tx = g.as_ref().ok_or(GossipError::ServiceNotStarted)?;
        let _ = tx.send((sender, message));
        self.inner
            .messages_received
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

fn encode_message<T: Streamable + ChiaProtocolMessage>(body: &T) -> Result<Message, GossipError> {
    Ok(Message {
        msg_type: T::msg_type(),
        id: None,
        data: body
            .to_bytes()
            .map_err(|e| GossipError::from(chia_sdk_client::ClientError::Streamable(e)))?
            .into(),
    })
}

fn empty_respond_peers() -> Result<RespondPeers, GossipError> {
    Ok(RespondPeers::new(vec![]))
}
