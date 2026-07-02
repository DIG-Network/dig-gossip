//! `dig-nat` integration — the unified DIG Node peer transport + discovery.
//!
//! This module is the ADAPTER that routes `dig-gossip`'s peer connections and discovery through
//! [`dig-nat`](dig_nat) — the crate that implements the normative L7 peer-network `connect(peer)`
//! NAT-traversal ladder (direct → UPnP → NAT-PMP → PCP → relay-coordinated hole-punch →
//! relay-last), yielding a mutually-authenticated, `yamux`-multiplexed [`PeerConnection`](dig_nat::PeerConnection).
//! By reusing `dig-nat` instead of a bespoke dialer, a DIG Node's gossip links interoperate
//! byte-for-byte with `dig-node` and `dig-relay`, and reach peers behind NAT without a public IP.
//!
//! **What this module changes and what it deliberately does not.** It swaps the *transport,
//! discovery, and identity* layer for the unified protocol. It does **not** touch the gossip
//! ALGORITHMS — Plumtree ([`crate::gossip::plumtree`]), ERLAY ([`crate::gossip::erlay`]),
//! Dandelion++ ([`crate::privacy::dandelion`]), compact blocks ([`crate::gossip::compact_block`]),
//! priority lanes, and the seen-set/message-cache dedup all operate on opaque [`Message`](dig_protocol::Message)
//! payloads + [`PeerId`](crate::types::peer::PeerId) keys and are transport-agnostic. They sit
//! unchanged on top of whatever byte transport
//! delivers a peer's messages, so routing that transport through `dig-nat`'s multiplexed streams
//! keeps the L2 gossip semantics identical.
//!
//! ## The pieces
//!
//! | Concern | This module | The unified protocol it conforms to |
//! |---|---|---|
//! | **Identity** | [`chia_cert_to_nat_identity`] bridges the node's `ChiaCertificate` (PEM) to a `dig-nat` [`LocalIdentity`](dig_nat::LocalIdentity) | `peer_id = SHA-256(TLS SPKI DER)` — identical in both crates (guarded by `tests/nat_identity_conformance_tests.rs`) |
//! | **Transport** | [`nat_connect`] establishes an mTLS, peer_id-verified, multiplexed [`NatPeerConnection`] via [`dig_nat::connect`] | the L7 `connect(peer)` ladder + streaming/multiplexed transport (spec §2, §8) |
//! | **Discovery** | [`PeerRecord`] + [`discovery`] combine the relay introducer (RLY-005 `get_peers`) with node peer-exchange (`dig.getPeers`) | multi-source discovery (spec §4, §7) |
//!
//! ## Why the identity BRIDGE (and not making `dig-nat` speak `ChiaCertificate`)
//!
//! `dig-nat` is the foundational transport crate: it is deliberately Chia-free (pure-Rust rustls, no
//! OpenSSL, no `chia-ssl`) so `dig-node`/`dig-relay` can depend on it WITHOUT the L2/Chia stack.
//! `ChiaCertificate` is merely `{cert_pem, key_pem}` — PEM wrappers around exactly the DER
//! [`LocalIdentity::from_der`](dig_nat::LocalIdentity::from_der) already takes. So the bridge is a
//! thin PEM→DER decode living in `dig-gossip` (which already carries the Chia deps), not a new Chia
//! dependency pushed down into `dig-nat`. The frozen contract — the `peer_id` derivation — already
//! matches byte-for-byte; only the encoding differs.

pub mod discovery;
pub mod peer_record;
pub mod transport;

pub use discovery::{
    merge_records_into_address_manager, merge_records_into_address_manager_capped,
};
#[cfg(feature = "relay")]
pub use discovery::{relay_get_peers, unified_discover, UnifiedDiscoveryConfig};
pub use peer_record::{AddressKind, PeerAddress, PeerRecord, Via};
pub use transport::{chia_cert_to_nat_identity, nat_connect, peer_target_for, NatPeerConnection};

// Re-export the dig-nat surface a caller (e.g. `dig-node`, the next integration phase) needs so it
// can drive the transport without also depending on `dig-nat` directly.
pub use dig_nat::{
    peer_id_from_leaf_cert_der as nat_peer_id_from_leaf_cert_der,
    peer_id_from_tls_spki_der as nat_peer_id_from_tls_spki_der, LocalIdentity as NatLocalIdentity,
    NatConfig, NatError, PeerConnection as NatConnection, PeerId as NatPeerId,
    PeerSession as NatPeerSession, PeerStream as NatPeerStream, PeerTarget as NatPeerTarget,
    TraversalKind,
};
