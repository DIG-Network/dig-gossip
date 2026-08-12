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

use dig_peer_protocol::{ClientError, LinkError};
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
}

impl From<DialError> for GossipError {
    fn from(error: DialError) -> Self {
        match error {
            DialError::Client(e) => Self::from(e),
            DialError::Link(e) => Self::from(e),
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
