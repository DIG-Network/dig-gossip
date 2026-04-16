//! [`DigMessage`] — wire-compatible `Message` with raw `u8` opcode support.
//!
//! ## Problem
//!
//! `chia_protocol::Message` stores `msg_type` as `ProtocolMessageTypes` (a closed `#[repr(u8)]`
//! enum). `Message::from_bytes` rejects any opcode not in that enum, which means DIG extension
//! opcodes (200–219) cannot be decoded without patching the upstream crate.
//!
//! ## Solution
//!
//! `DigMessage` uses the same wire layout (`u8 + Option<u16> + Bytes`) but stores `msg_type`
//! as a plain `u8`. This allows encoding and decoding any opcode — Chia or DIG — without
//! modifying upstream types. Conversion to/from `chia_protocol::Message` is provided for
//! opcodes that the Chia enum recognizes.

use chia_protocol::{Bytes, Message, ProtocolMessageTypes};
use chia_traits::Streamable;

/// Wire message with raw `u8` opcode — handles both Chia (0–107) and DIG (200–219) opcodes.
///
/// Same binary layout as `chia_protocol::Message`:
/// ```text
/// [u8 msg_type] [bool has_id] [u16 id (if has_id)] [u32 data_len] [u8... data]
/// ```
///
/// Use [`DigMessage::to_bytes`] / [`DigMessage::from_bytes`] for wire serialization.
/// Use [`DigMessage::try_into_chia_message`] to convert to stock `Message` when the opcode
/// is a known Chia type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigMessage {
    /// Raw wire opcode — no enum restriction.
    pub msg_type: u8,
    /// Correlation ID for request/response pairing (same as `Message.id`).
    pub id: Option<u16>,
    /// Serialized payload body.
    pub data: Bytes,
}

impl DigMessage {
    /// Construct a new DIG message.
    pub fn new(msg_type: u8, id: Option<u16>, data: Bytes) -> Self {
        Self { msg_type, id, data }
    }

    /// Serialize to wire bytes (same format as `Message::to_bytes`).
    ///
    /// Layout: `[u8 msg_type] [u8 has_id (0/1)] [u16 id if present] [u32 data_len] [data...]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 1 + 2 + 4 + self.data.len());
        buf.push(self.msg_type);
        match self.id {
            Some(id) => {
                buf.push(1); // has_id = true
                buf.extend_from_slice(&id.to_be_bytes());
            }
            None => {
                buf.push(0); // has_id = false
            }
        }
        buf.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Deserialize from wire bytes. Accepts any `msg_type` value — no enum validation.
    ///
    /// Returns `None` if the buffer is too short or the length prefix doesn't match.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        let msg_type = bytes[0];
        let has_id = bytes[1];
        let mut offset = 2;

        let id = if has_id != 0 {
            if bytes.len() < offset + 2 {
                return None;
            }
            let id = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            offset += 2;
            Some(id)
        } else {
            None
        };

        if bytes.len() < offset + 4 {
            return None;
        }
        let data_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        if bytes.len() < offset + data_len {
            return None;
        }
        let data = Bytes::new(bytes[offset..offset + data_len].to_vec());

        Some(Self { msg_type, id, data })
    }

    /// Convert from a stock `chia_protocol::Message` (lossless — opcode stored as u8).
    pub fn from_chia_message(msg: &Message) -> Self {
        Self {
            msg_type: msg.msg_type as u8,
            id: msg.id,
            data: msg.data.clone(),
        }
    }

    /// Try to convert to a stock `chia_protocol::Message`.
    ///
    /// Fails if `msg_type` is not a valid `ProtocolMessageTypes` discriminant
    /// (i.e., DIG extension opcodes 200+ will fail here — use `DigMessage` directly
    /// for those).
    pub fn try_into_chia_message(&self) -> Option<Message> {
        // ProtocolMessageTypes implements Streamable; from_bytes on a single u8
        let pmt = ProtocolMessageTypes::from_bytes(&[self.msg_type]).ok()?;
        Some(Message {
            msg_type: pmt,
            id: self.id,
            data: self.data.clone(),
        })
    }

    /// Whether this message carries a DIG extension opcode (>= 200).
    pub fn is_dig_extension(&self) -> bool {
        self.msg_type >= 200
    }

    /// Whether this message carries a standard Chia opcode (< 200).
    pub fn is_chia_standard(&self) -> bool {
        self.msg_type < 200
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_chia_opcode() {
        // NewPeak = 20
        let msg = DigMessage::new(20, Some(42), Bytes::new(vec![1, 2, 3]));
        let wire = msg.to_bytes();
        let decoded = DigMessage::from_bytes(&wire).expect("decode");
        assert_eq!(decoded.msg_type, 20);
        assert_eq!(decoded.id, Some(42));
        assert_eq!(decoded.data.as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn round_trip_dig_opcode() {
        // RegisterPeer = 218
        let msg = DigMessage::new(218, None, Bytes::new(vec![0xAB]));
        let wire = msg.to_bytes();
        let decoded = DigMessage::from_bytes(&wire).expect("decode");
        assert_eq!(decoded.msg_type, 218);
        assert_eq!(decoded.id, None);
        assert!(decoded.is_dig_extension());
        assert!(!decoded.is_chia_standard());
    }

    #[test]
    fn from_chia_message() {
        let chia_msg = Message {
            msg_type: ProtocolMessageTypes::NewPeak,
            id: Some(7),
            data: Bytes::new(vec![0xFF]),
        };
        let dig = DigMessage::from_chia_message(&chia_msg);
        assert_eq!(dig.msg_type, 20); // NewPeak = 20
        assert_eq!(dig.id, Some(7));

        // Round-trip back to Chia
        let back = dig.try_into_chia_message().expect("known opcode");
        assert_eq!(back.msg_type, ProtocolMessageTypes::NewPeak);
    }

    #[test]
    fn unknown_opcode_cannot_convert_to_chia_message() {
        // Use an opcode that is NOT in ProtocolMessageTypes (neither Chia nor vendored DIG).
        let dig = DigMessage::new(250, None, Bytes::default());
        assert!(dig.try_into_chia_message().is_none());
    }

    #[test]
    fn empty_buffer_returns_none() {
        assert!(DigMessage::from_bytes(&[]).is_none());
        assert!(DigMessage::from_bytes(&[20]).is_none());
    }
}
