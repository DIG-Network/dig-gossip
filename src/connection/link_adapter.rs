//! Adapts [`dig_peer_protocol::DigLink`] to the currency the rest of this crate speaks.
//!
//! # Why this module exists
//!
//! Every peer link is a [`DigLink`](dig_peer_protocol::DigLink) (dig_ecosystem#2391): unlike the
//! `chia-sdk-client` `Peer` it replaces, it never lets a single inbound frame end the connection —
//! an unknown opcode and an unmatched correlation id both cost that one frame. See
//! `dig_peer_protocol::DigLink`'s inbound-loop documentation for the three differences.
//!
//! `DigLink` frames every message as a [`DigMessage`], whose `msg_type` is a raw `u8`. The rest of
//! dig-gossip is written against [`Message`], whose `msg_type` is the `ProtocolMessageTypes` enum,
//! and depends on that enum in ~80 places (rate-limit classes, gossip priority lanes, handshake
//! validation). Translating at this one seam keeps that body of code unchanged while the link
//! underneath it becomes frame-tolerant.
//!
//! Two directions need translating, and they are asymmetric:
//!
//! * **Outbound** is total — every [`Message`] is a valid [`DigMessage`].
//! * **Inbound** is partial — an opcode with no `ProtocolMessageTypes` variant cannot become a
//!   [`Message`] at all. [`InboundMessages`] therefore *drops* such a frame and reads the next
//!   one. Dropping is the point: propagating the failure would hand back the very kill switch
//!   `DigLink` was adopted to remove.

use dig_peer_protocol::{
    ClientError, DigLink, DigMessage, LinkError, LinkOptions, Message, PeerOptions,
};
use tokio::sync::mpsc;
use tracing::warn;

/// The inbound half of a peer link, yielding the [`Message`] values this crate consumes.
///
/// A thin wrapper rather than a forwarding task: a task would add a second buffer between the
/// link and the application, and the link's own drop-when-full policy is the one that must
/// govern, since it is what keeps correlated replies flowing under load.
#[derive(Debug)]
pub struct InboundMessages {
    frames: mpsc::Receiver<DigMessage>,
}

impl InboundMessages {
    /// Wrap the inbound channel of a freshly-constructed link.
    pub fn new(frames: mpsc::Receiver<DigMessage>) -> Self {
        Self { frames }
    }

    /// The next frame this build can interpret, or `None` once the link is closed.
    ///
    /// Frames carrying an opcode with no `ProtocolMessageTypes` variant are logged and skipped.
    /// That is the expected steady state on a live network, not an error: the 220-255 band is
    /// open, so a peer running a newer build sends opcodes this one has never heard of.
    pub async fn recv(&mut self) -> Option<Message> {
        loop {
            let frame = self.frames.recv().await?;
            let opcode = frame.msg_type;
            match frame.into_chia_message() {
                Some(message) => return Some(message),
                None => warn!(
                    "skipped an inbound frame with unrecognised opcode {opcode}; the link is \
                     unaffected"
                ),
            }
        }
    }
}

/// Translate a [`LinkError`] into this crate's transport-error currency.
///
/// `ClientError` stays the public shape of [`GossipError::ClientError`](crate::GossipError) so
/// adopting `DigLink` changes no error type a consumer can observe. The mapping is lossy in one
/// place and deliberately so: `LinkError` names opcodes as `u8` — it can describe a DIG opcode,
/// which is the whole reason it exists — while `ClientError::InvalidResponse` can only name
/// `ProtocolMessageTypes` variants. Rather than invent a variant for an opcode that has none,
/// such an error is carried as [`ClientError::Io`] with the raw opcodes in its message, so no
/// detail is lost even though the type cannot express it.
pub fn client_error_from_link(error: LinkError) -> ClientError {
    match error {
        LinkError::Streamable(e) => ClientError::Streamable(e),
        LinkError::WebSocket(e) => ClientError::WebSocket(*e),
        LinkError::Io(e) => ClientError::Io(e),
        LinkError::Recv(e) => ClientError::Recv(e),
        LinkError::UnsupportedTls => ClientError::UnsupportedTls,
        other => ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            other.to_string(),
        )),
    }
}

/// Send a fully-formed [`Message`], preserving its correlation id.
///
/// This is how an inbound *request* is answered — the reply must carry the requester's id, which
/// `DigLink::send` cannot express. The conversion is total in this direction: every
/// `ProtocolMessageTypes` variant is a `u8`.
pub async fn send_chia_message(link: &DigLink, message: Message) -> Result<(), LinkError> {
    link.send_message(DigMessage::from_chia_message_owned(message))
        .await
}

/// Carry the configured per-connection tunables onto a link.
///
/// [`GossipConfig::peer_options`](crate::GossipConfig::peer_options) stays a `PeerOptions` so that
/// adopting `DigLink` breaks no caller. The translation is lossless: `PeerOptions` has exactly one
/// field, and `LinkOptions` means the same thing by it. The remaining `LinkOptions` fields are
/// deadlines `PeerOptions` cannot express at all, so they keep their defaults — which is a
/// strictly better position than the old transport, where a request had no deadline whatsoever.
///
/// Assignment rather than a struct expression because `LinkOptions` is `#[non_exhaustive]`.
pub fn link_options_from(options: PeerOptions) -> LinkOptions {
    let mut link_options = LinkOptions::default();
    link_options.rate_limit_factor = options.rate_limit_factor;
    link_options
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_peer_protocol::{ProtocolMessageTypes, RespondPeers, Streamable};

    /// The unallocated DIG free-band opcode used to stand in for "a build newer than this one".
    const UNALLOCATED_DIG_OPCODE: u8 = 223;

    fn respond_peers_frame() -> DigMessage {
        DigMessage::new(
            ProtocolMessageTypes::RespondPeers as u8,
            None,
            RespondPeers::new(vec![]).to_bytes().unwrap().into(),
        )
    }

    /// An uninterpretable frame must cost exactly itself: the frame *after* it still arrives.
    ///
    /// The trailing known frame is the load-bearing part. Asserting only that the unknown frame
    /// did not surface would pass against an adapter that stopped reading altogether.
    #[tokio::test]
    async fn unknown_opcode_is_skipped_and_the_next_frame_still_arrives() {
        let (tx, rx) = mpsc::channel(4);
        tx.send(DigMessage::new(
            UNALLOCATED_DIG_OPCODE,
            None,
            vec![1, 2, 3].into(),
        ))
        .await
        .unwrap();
        tx.send(respond_peers_frame()).await.unwrap();

        let mut inbound = InboundMessages::new(rx);
        let message = inbound.recv().await.expect("the known frame after it");
        assert_eq!(message.msg_type, ProtocolMessageTypes::RespondPeers);
    }

    /// A closed link ends the stream rather than spinning.
    #[tokio::test]
    async fn a_closed_link_yields_none() {
        let (tx, rx) = mpsc::channel::<DigMessage>(1);
        drop(tx);
        assert!(InboundMessages::new(rx).recv().await.is_none());
    }

    /// A non-default rate-limit factor must reach the link, not be silently replaced by the
    /// default. `0.6` is both types' default, so the fixture uses a value neither would produce
    /// on its own — a test using `0.6` would pass against a function that ignored its argument.
    #[test]
    fn the_configured_rate_limit_factor_reaches_the_link() {
        let options = PeerOptions {
            rate_limit_factor: 0.25,
        };
        assert!((link_options_from(options).rate_limit_factor - 0.25).abs() < f64::EPSILON);
    }

    /// A correlation id is preserved across the translation: replies are matched by it.
    #[tokio::test]
    async fn the_correlation_id_survives_translation() {
        let (tx, rx) = mpsc::channel(1);
        let mut frame = respond_peers_frame();
        frame.id = Some(7);
        tx.send(frame).await.unwrap();

        let message = InboundMessages::new(rx).recv().await.expect("frame");
        assert_eq!(message.id, Some(7));
    }
}
