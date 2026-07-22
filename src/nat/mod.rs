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
//! priority lanes, and the seen-set/message-cache dedup all operate on opaque [`Message`](dig_peer_protocol::Message)
//! payloads + [`PeerId`](crate::types::peer::PeerId) keys and are transport-agnostic. They sit
//! unchanged on top of whatever byte transport
//! delivers a peer's messages, so routing that transport through `dig-nat`'s multiplexed streams
//! keeps the L2 gossip semantics identical.
//!
//! ## The pieces
//!
//! | Concern | This module | The unified protocol it conforms to |
//! |---|---|---|
//! | **Identity** | [`NatLocalIdentity`] (a [`dig_tls::NodeCert`](dig_nat::NodeCert)) — the node's CA-signed mTLS cert, presented to [`nat_connect`] | `peer_id = SHA-256(TLS SPKI DER)`, chained to the shipped DigNetwork CA + carrying the #1204 BLS-G1 binding (guarded by `tests/nat_identity_conformance_tests.rs`) |
//! | **Transport** | [`nat_connect`] establishes an mTLS, peer_id-verified, multiplexed [`NatPeerConnection`] via [`dig_nat::connect`] | the L7 `connect(peer)` ladder + streaming/multiplexed transport (spec §2, §8) |
//! | **Discovery** | [`PeerRecord`] + [`discovery`] combine the relay introducer (RLY-005 `get_peers`) with node peer-exchange (`dig.getPeers`) | multi-source discovery (spec §4, §7) |
//!
//! ## Identity: a CA-signed `dig-tls` [`NodeCert`], NOT a self-signed chia-ssl bridge (#1268/#1280)
//!
//! `dig-nat` 0.6 consumes [`dig-tls`](dig_tls) for ALL cert/mTLS/peer_id/BLS-binding: a peer presents
//! a [`NodeCert`](dig_nat::NodeCert) — an ECDSA P-256 leaf **signed by the shipped, public DigNetwork
//! CA** and self-attesting its BLS-G1 identity key over the cert SPKI (the #1204 binding). This
//! replaces the previous self-signed `ChiaCertificate`→`LocalIdentity` PEM bridge: a self-signed cert
//! now FAILS dig-nat's DigNetwork-CA chain check, so the transport identity is minted via
//! [`NodeCert::load_or_generate`](dig_nat::NodeCert::load_or_generate) / `generate_signed`. The frozen
//! contract — `peer_id = SHA-256(TLS SPKI DER)` — is unchanged and still matches byte-for-byte across
//! crates.

pub mod discovery;
pub mod peer_record;
pub mod transport;

pub use discovery::{
    merge_records_into_address_manager, merge_records_into_address_manager_capped,
};
#[cfg(feature = "relay")]
pub use discovery::{relay_get_peers, unified_discover, UnifiedDiscoveryConfig};
pub use peer_record::{AddressKind, PeerAddress, PeerRecord, Via};
pub use transport::{nat_connect, nat_connect_with_runtime, peer_target_for, NatPeerConnection};

// Re-export the dig-nat surface a caller (e.g. `dig-node`, the next integration phase) needs so it
// can drive the transport without also depending on `dig-nat` directly. `NatLocalIdentity` is the
// canonical `dig_tls::NodeCert` (re-exported by dig-nat 0.6) — the CA-signed mTLS identity a node
// presents; the `NatBindingPolicy` selects how a peer's #1204 binding is enforced.
pub use dig_nat::{
    peer_id_from_leaf_cert_der as nat_peer_id_from_leaf_cert_der,
    peer_id_from_tls_spki_der as nat_peer_id_from_tls_spki_der, BindingPolicy as NatBindingPolicy,
    NatConfig, NatError, NodeCert as NatLocalIdentity, PeerConnection as NatConnection,
    PeerId as NatPeerId, PeerSession as NatPeerSession, PeerStream as NatPeerStream,
    PeerTarget as NatPeerTarget, TraversalKind,
};
