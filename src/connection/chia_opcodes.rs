//! Wire opcode bytes for the Chia full-node messages dig-gossip exchanges.
//!
//! # Why these exist
//!
//! [`DigMessage::msg_type`](dig_peer_protocol::DigMessage) is a raw wire byte rather
//! than an enum, because the DIG opcode band (200-222) has no `ProtocolMessageTypes`
//! variant to name it — that mismatch is exactly what the vendored `chia-protocol`
//! fork used to paper over (dig_ecosystem#2228).
//!
//! Chia-band traffic still needs its opcodes, so they are derived here from
//! `chia_protocol::ProtocolMessageTypes` rather than written as literals. That keeps
//! `chia-protocol` the single authority for Chia opcode numbering: if upstream ever
//! renumbers one, these follow automatically instead of silently disagreeing.

use chia_protocol::ProtocolMessageTypes;

/// Wire opcode of a `Handshake` frame — the first message of every session.
pub(crate) const HANDSHAKE: u8 = ProtocolMessageTypes::Handshake as u8;

/// Wire opcode of a `RequestPeers` frame.
pub(crate) const REQUEST_PEERS: u8 = ProtocolMessageTypes::RequestPeers as u8;

/// Wire opcode of a `RespondPeers` frame.
pub(crate) const RESPOND_PEERS: u8 = ProtocolMessageTypes::RespondPeers as u8;

#[cfg(test)]
mod tests {
    use super::{HANDSHAKE, REQUEST_PEERS, RESPOND_PEERS};

    /// Each constant equals the single byte `Streamable` puts on the wire for its
    /// enum variant.
    ///
    /// The `as u8` cast and the `Streamable` encoding are two independent paths to
    /// the same number; pinning them against each other is what makes these
    /// constants trustworthy, since `DigLink` frames Chia bodies via the
    /// `Streamable` path while dig-gossip's raw pre-link phase compares against the
    /// cast. A divergence would desynchronise the two halves of one handshake.
    #[test]
    fn constants_match_the_streamable_encoding() {
        use chia_protocol::ProtocolMessageTypes as P;
        use chia_traits::Streamable;

        for (name, variant, constant) in [
            ("Handshake", P::Handshake, HANDSHAKE),
            ("RequestPeers", P::RequestPeers, REQUEST_PEERS),
            ("RespondPeers", P::RespondPeers, RESPOND_PEERS),
        ] {
            let encoded = variant.to_bytes().expect("opcode encodes");
            assert_eq!(encoded.len(), 1, "{name} encodes to exactly one byte");
            assert_eq!(
                encoded[0], constant,
                "{name} constant matches the wire byte"
            );
        }
    }
}
