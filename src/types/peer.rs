//! Peer identity, metadata, and the gossip-layer connection wrapper.
//!
//! **Layout:** STR-002; **re-exports:** STR-003 /
//! [`specs/STR-003.md`](../../../docs/requirements/domains/crate_structure/specs/STR-003.md).
//!
//! **`PeerId`** is a type alias to [`chia_protocol::Bytes32`] — we never invent a parallel
//! identity type. **`PeerConnection`** will accumulate gossip metadata (API-005); for STR-003
//! it only needs to exist as a public type holding the upstream [`chia_sdk_client::Peer`].

use chia_protocol::Bytes32;
use chia_sdk_client::Peer;

/// 32-byte peer identifier (BLS-derived in Chia; same wire type for DIG).
pub type PeerId = Bytes32;

/// Static / semi-static peer metadata used by discovery and address bucketing.
///
/// **Future fields:** IP, ports, services flags, timestamp — see discovery specs.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Stable peer identity on the wire.
    pub peer_id: PeerId,
}

/// Active connection with gossip bookkeeping.
///
/// **Spec intent:** wrap [`Peer`] plus DIG-only fields (reputation snapshot, caps, …).
#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Underlying Chia light-wallet-protocol peer handle (TLS WebSocket).
    pub peer: Peer,
}
