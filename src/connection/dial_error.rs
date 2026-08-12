//! [`DialError`] — the two-armed error a dial can fail with, kept apart because the
//! two arms carry **opposite retry semantics**.
//!
//! A dial has two failure kinds and they are not interchangeable:
//!
//! * **Transport** — the peer was never reached, or the pipe broke: connection refused,
//!   TLS failure, a timeout, a framing error. Retrying the same address is reasonable.
//! * **Policy** — the peer *was* reached, it sent a [`Handshake`](chia_protocol::Handshake),
//!   and we rejected it: wrong `network_id`, wrong `node_type`, an incompatible protocol
//!   version. Retrying the same address changes nothing; the peer is simply not one of ours.
//!
//! [`dig_peer_protocol`] already models that split as two types —
//! [`LinkError`] for the transport and [`ClientError`] for the client-side policy verdict —
//! and [`GossipError`](crate::GossipError) keeps them as two variants. `DialError` is the
//! union a dial function returns so it can report either one **without downgrading**: before
//! it existed, the outbound leg had only `LinkError` available and rendered every policy
//! rejection as `LinkError::Io(_)` carrying a formatted string, which erased the typed
//! [`ClientError::WrongNetwork`] a caller needs to tell "not our network" from "host is down".
//!
//! Both legs of the handshake now agree: the inbound listener returns [`ClientError`] for a
//! policy rejection (`listener::negotiate_inbound_over_ws`) and so does the outbound dial, so
//! an identical rejection surfaces as the same [`GossipError`] variant whoever dialled.
//!
//! Specified by **CON-002** (inbound handshake) and **CON-003** (handshake validation), both of
//! which require `GossipError::ClientError` for a rejection, and by **API-004**, which records the
//! opposite retry semantics of the two arms.

use chia_protocol::ProtocolMessageTypes;
use dig_peer_protocol::{ClientError, LinkError, Streamable};
use thiserror::Error;

use crate::error::GossipError;

/// A dial failed either in the transport or on handshake policy — see the module docs for
/// why the two are kept apart.
#[derive(Debug, Error)]
pub enum DialError {
    /// The peer was reached and rejected on policy (or a client-side TLS/certificate step
    /// failed). Surfaces as [`GossipError::ClientError`]; **not** worth retrying.
    #[error("client error: {0}")]
    Client(#[from] ClientError),

    /// The transport itself failed: refused, timed out, broken framing. Surfaces as
    /// [`GossipError::LinkError`]; retrying the same address may succeed.
    #[error("link error: {0}")]
    Link(#[from] LinkError),

    /// The peer answered the dial with an opcode that has **no** `ProtocolMessageTypes` variant,
    /// so the rejection cannot be expressed as a typed [`ClientError`].
    ///
    /// This is the [`Client`](DialError::Client) arm in every respect but the type: the peer was
    /// reached and rejected on content, so it is **policy**, not transport. It exists because
    /// [`ClientError::InvalidResponse`] takes `ProtocolMessageTypes` and this crate must not
    /// launder an unmappable opcode through a formatted string — the exact downgrade the module
    /// docs above condemn.
    #[error("expected a Handshake, found unknown opcode {0}")]
    UnknownOpcode(u8),
}

/// Classify "the first frame after connect was not a `Handshake`" as the **policy** rejection it
/// is: the peer was reached and rejected on content, so re-dialling the same address meets the
/// same behaviour.
///
/// The typed [`ClientError::InvalidResponse`] is preferred whenever `opcode` names a known
/// [`ProtocolMessageTypes`]; anything outside that enum — a DIG-band opcode, a garbage byte —
/// takes [`DialError::UnknownOpcode`], which carries the raw byte rather than a rendered string.
///
/// `ProtocolMessageTypes` is a `#[repr(u8)]` `Streamable` enum with no `TryFrom<u8>`, so the
/// single-byte decode IS the total mapping from opcode to variant.
#[must_use]
pub(crate) fn non_handshake_first_frame(opcode: u8) -> DialError {
    match ProtocolMessageTypes::from_bytes(&[opcode]) {
        Ok(found) => DialError::Client(ClientError::InvalidResponse(
            vec![ProtocolMessageTypes::Handshake],
            found,
        )),
        Err(_) => DialError::UnknownOpcode(opcode),
    }
}

impl From<DialError> for GossipError {
    fn from(error: DialError) -> Self {
        match error {
            DialError::Client(e) => Self::from(e),
            DialError::Link(e) => Self::from(e),
            // Policy, and the raw byte is the whole diagnostic — so it keeps its own variant
            // rather than being flattened into a `ClientError` that cannot name the opcode.
            DialError::UnknownOpcode(op) => Self::UnknownHandshakeOpcode(op),
        }
    }
}

impl From<crate::connection::handshake::HandshakeValidationError> for DialError {
    /// A handshake-validation verdict is policy by definition, so it always takes the
    /// [`Client`](DialError::Client) arm — preserving typed variants such as
    /// [`ClientError::WrongNetwork`].
    fn from(error: crate::connection::handshake::HandshakeValidationError) -> Self {
        Self::Client(ClientError::from(error))
    }
}

#[cfg(test)]
mod tests {
    //! #2228 — a wrong first frame is POLICY. The two cases are pinned from BOTH sides so the
    //! classification cannot silently collapse into one arm.

    use super::*;
    use crate::connection::chia_opcodes;
    use crate::types::dig_messages::DigMessageType;

    /// A Chia-band opcode maps to a `ProtocolMessageTypes`, so the rejection is expressible as the
    /// typed `ClientError` — never a `LinkError`, which would tell a caller to retry the address.
    #[test]
    fn a_known_opcode_is_a_typed_client_rejection() {
        let err = non_handshake_first_frame(chia_opcodes::REQUEST_PEERS);
        match err {
            DialError::Client(ClientError::InvalidResponse(expected, found)) => {
                assert_eq!(expected, vec![ProtocolMessageTypes::Handshake]);
                assert_eq!(found, ProtocolMessageTypes::RequestPeers);
            }
            other => panic!("expected a typed client rejection, got {other:?}"),
        }
    }

    /// A DIG-band opcode has no `ProtocolMessageTypes` variant. It must still be policy, and it
    /// must carry the raw byte — the reason this arm exists instead of a formatted string.
    #[test]
    fn an_unmappable_opcode_keeps_the_raw_byte_and_stays_policy() {
        let opcode = DigMessageType::NewAttestation as u8;
        assert!(
            ProtocolMessageTypes::from_bytes(&[opcode]).is_err(),
            "the fixture must be OUTSIDE ProtocolMessageTypes or it proves nothing"
        );

        let err = non_handshake_first_frame(opcode);
        assert!(
            matches!(err, DialError::UnknownOpcode(op) if op == opcode),
            "expected the raw opcode to survive, got {err:?}"
        );
        assert!(
            matches!(
                GossipError::from(err),
                GossipError::UnknownHandshakeOpcode(op) if op == opcode
            ),
            "an unmappable opcode must not be laundered into a transport error"
        );
    }
}
