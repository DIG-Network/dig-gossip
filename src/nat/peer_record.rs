//! The `dig.getPeers` / `dig.announce` peer-record wire shapes (L7 peer-network spec §7, frozen in
//! §11 Conformance) + conversions to/from the two peer-exchange sources dig-gossip already speaks:
//! the Chia-streamable [`TimestampedPeerInfo`] (node↔node `RequestPeers`/`RespondPeers`, §4b) and the
//! relay `RelayPeerInfo` (relay introducer `get_peers`, §4a).
//!
//! A [`PeerRecord`] is the UNIFIED representation of a discovered peer across both sources, so the
//! discovery layer ([`super::discovery`]) can merge relay-introduced and node-gossiped peers into one
//! address book, and a node's `dig.getPeers` RPC can return the exact shape an agent or `dig-node`
//! expects. The JSON field names + the `kind`/`via` lowercase tokens are the wire contract and must
//! match the spec byte-for-byte (see `tests/nat_transport_tests.rs`).

use dig_protocol::TimestampedPeerInfo;
use serde::{Deserialize, Serialize};

#[cfg(feature = "relay")]
use crate::relay::relay_types::RelayPeerInfo;

/// How a candidate address was learned (L7 spec §7 `dig.getPeers` `addresses[].kind`).
///
/// The lowercase serde token is the frozen wire spelling; ordering (`Direct` first) is the
/// most-direct-first preference a dialer uses when picking which candidate to try.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressKind {
    /// Advertised/observed directly reachable address (publicly routable or port-forwarded).
    Direct,
    /// A STUN-discovered public reflexive address ([spec §3](crate)).
    Reflexive,
    /// A UPnP / NAT-PMP / PCP-mapped external address.
    Mapped,
    /// Reachable through the relay (no direct candidate yet).
    Relay,
}

impl AddressKind {
    /// Most-direct-first rank (lower is more direct) — mirrors the dialer's candidate preference.
    pub fn rank(self) -> u8 {
        match self {
            AddressKind::Direct => 0,
            AddressKind::Mapped => 1,
            AddressKind::Reflexive => 2,
            AddressKind::Relay => 3,
        }
    }

    /// Whether an address of this kind is something a node can dial directly (everything but a bare
    /// relay marker).
    pub fn is_dialable(self) -> bool {
        !matches!(self, AddressKind::Relay)
    }
}

/// How this node currently reaches a peer (L7 spec §7 `dig.getPeers` `via`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Via {
    /// A direct peer link (any tier whose data path is peer-to-peer, incl. a brokered hole punch).
    Direct,
    /// The peer's data currently flows through the relay (last-resort transport).
    Relay,
}

/// One candidate address for a peer: `{ host, port, kind }` (L7 spec §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAddress {
    /// IPv4/IPv6 literal or hostname.
    pub host: String,
    /// P2P port.
    pub port: u16,
    /// How this address was learned.
    pub kind: AddressKind,
}

/// A discovered peer in the unified `dig.getPeers` shape (L7 spec §7 / §11 Conformance):
/// `{ peer_id, addresses:[{host,port,kind}], network_id, last_seen, via }`.
///
/// This is the interop record the node RPC returns and the discovery layer merges. It is produced
/// from BOTH discovery sources ([`Self::from_relay_peer_info`], [`Self::from_timestamped_peer_info`])
/// and reduced to the Chia peer-exchange row ([`Self::to_timestamped_peer_info`]) for the address
/// manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    /// The peer's identity — 64-hex `peer_id = SHA-256(SPKI DER)`.
    pub peer_id: String,
    /// Candidate addresses, most-direct-first is not guaranteed on the wire (the consumer sorts).
    pub addresses: Vec<PeerAddress>,
    /// The network the peer registered under (e.g. `DIG_MAINNET`).
    pub network_id: String,
    /// Unix seconds the peer was last seen.
    pub last_seen: u64,
    /// How this node currently reaches the peer.
    pub via: Via,
}

impl PeerRecord {
    /// Build a record from the relay introducer's identity-only [`RelayPeerInfo`] (§4a).
    ///
    /// The relay returns no `IP:port` (it addresses peers by `peer_id`), so the record has **no
    /// dialable address** and is marked [`Via::Relay`]: the caller knows to reach the peer via the
    /// relay / a relay-coordinated hole punch until a direct candidate is discovered.
    #[cfg(feature = "relay")]
    pub fn from_relay_peer_info(rpi: &RelayPeerInfo) -> Self {
        PeerRecord {
            peer_id: rpi.peer_id.clone(),
            addresses: Vec::new(),
            network_id: rpi.network_id.clone(),
            last_seen: rpi.last_seen,
            via: Via::Relay,
        }
    }

    /// Build a record from `dig-nat`'s live-reservation [`RelayPeerInfo`](dig_nat::wire::RelayPeerInfo)
    /// (#870 / #924 — the peer set discovered over the persistent reservation socket, RLY-005 `Peers` +
    /// `PeerConnected` pushes).
    ///
    /// **#924 B1 — dialable fold.** When the relay resolved dialable candidate address(es) for the peer
    /// (`rpi.addresses` non-empty — the relay substituted its observed reflexive IP for the node's
    /// advertised gossip listen port), this builds a **dialable** record: each candidate becomes a
    /// [`AddressKind::Direct`] [`PeerAddress`] and the record is [`Via::Direct`], so
    /// [`Self::to_timestamped_peer_info`] returns `Some` and the record SURVIVES the dialable-only
    /// address-book merge — the pool then direct-dials the peer over the existing mTLS path. Candidates
    /// are ordered **IPv6-first** (§5.2) so the dialer prefers IPv6 and falls back to IPv4.
    ///
    /// When `rpi.addresses` is empty (a legacy peer the relay addresses by `peer_id` only), this is an
    /// identity-only record with **no dialable address** ([`Via::Relay`]), exactly as before: it counts
    /// as relay-reachable but is never placed in the by-address book.
    ///
    /// The two `RelayPeerInfo` types (dig-nat's and dig-gossip's) carry byte-identical fields — this is
    /// the seam where the consumer folds dig-nat's discovery output into dig-gossip's unified
    /// [`PeerRecord`].
    #[cfg(feature = "relay")]
    pub fn from_nat_relay_peer_info(rpi: &dig_nat::wire::RelayPeerInfo) -> Self {
        if rpi.addresses.is_empty() {
            return PeerRecord {
                peer_id: rpi.peer_id.clone(),
                addresses: Vec::new(),
                network_id: rpi.network_id.clone(),
                last_seen: rpi.last_seen,
                via: Via::Relay,
            };
        }

        // IPv6-first (§5.2): a stable sort keyed on the canonical [`dig_ip::Family`] (which orders
        // `V6` before `V4`) preserves the relay's ordering within each family while surfacing IPv6
        // candidates first for the happy-eyeballs dialer — one family authority, no hand-rolled key.
        let mut candidates = rpi.addresses.clone();
        candidates.sort_by_key(dig_ip::Family::of);

        PeerRecord {
            peer_id: rpi.peer_id.clone(),
            addresses: candidates
                .into_iter()
                .map(|addr| PeerAddress {
                    host: addr.ip().to_string(),
                    port: addr.port(),
                    kind: AddressKind::Direct,
                })
                .collect(),
            network_id: rpi.network_id.clone(),
            last_seen: rpi.last_seen,
            via: Via::Direct,
        }
    }

    /// Build a record from a Chia peer-exchange [`TimestampedPeerInfo`] (§4b `RespondPeers`).
    ///
    /// Node peer-exchange carries `{host, port, timestamp}` but not the peer's `peer_id` (identity is
    /// learned from the mTLS cert on connect), so `peer_id` is left empty and the single address is a
    /// [`AddressKind::Direct`] candidate the caller can dial. `network_id` is the discovering node's
    /// network (peer-exchange is network-scoped).
    pub fn from_timestamped_peer_info(tpi: &TimestampedPeerInfo, network_id: &str) -> Self {
        PeerRecord {
            peer_id: String::new(),
            addresses: vec![PeerAddress {
                host: tpi.host.clone(),
                port: tpi.port,
                kind: AddressKind::Direct,
            }],
            network_id: network_id.to_string(),
            last_seen: tpi.timestamp,
            via: Via::Direct,
        }
    }

    /// The most-direct dialable candidate address, if any (used to pick which address to dial).
    pub fn best_address(&self) -> Option<&PeerAddress> {
        self.addresses
            .iter()
            .filter(|a| a.kind.is_dialable())
            .min_by_key(|a| a.kind.rank())
    }

    /// Reduce to the Chia-streamable [`TimestampedPeerInfo`] row the address manager stores, choosing
    /// the most-direct candidate. Returns `None` for a relay-only record (no dialable address) — such
    /// a peer is reached via the relay, not placed in the dial-by-address book.
    pub fn to_timestamped_peer_info(&self) -> Option<TimestampedPeerInfo> {
        let a = self.best_address()?;
        Some(TimestampedPeerInfo::new(
            a.host.clone(),
            a.port,
            self.last_seen,
        ))
    }
}
