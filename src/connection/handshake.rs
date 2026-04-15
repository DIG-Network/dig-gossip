//! CON-003 — validate remote [`Handshake`] before accepting a P2P session.
//!
//! ## Normative trace
//!
//! - [`CON-003.md`](../../../docs/requirements/domains/connection/specs/CON-003.md) (test plan + acceptance criteria)
//! - [`NORMATIVE.md`](../../../docs/requirements/domains/connection/NORMATIVE.md) §CON-003
//! - Chia reference for Cc/Cf stripping: `ws_connection.py` (lines cited in CON-003 / CON-008)
//!
//! ## Design
//!
//! - **Single policy function** [`validate_remote_handshake`] is invoked from **both** outbound
//!   ([`crate::connection::outbound::connect_outbound_peer`]) and inbound
//!   ([`crate::connection::listener::negotiate_inbound_over_ws`]) so “both directions validated” is
//!   a literal shared code path (see `tests/con_003_tests.rs`).
//! - We map semantic failures onto existing [`chia_sdk_client::ClientError`] variants where they
//!   fit ([`ClientError::WrongNetwork`]); remaining policy failures use [`ClientError::Io`] with a
//!   stable prefix so integration tests can substring-match without inventing new upstream enum
//!   variants (chia-sdk-client 0.28’s [`ClientError`](chia_sdk_client::ClientError) is closed).
//! - **Protocol versions** are compared as dot-separated numeric tuples (Chia’s wire convention).
//!   [`MIN_COMPATIBLE_PROTOCOL_VERSION`] is the inclusive floor; peers below it are rejected.
//! - **Software version** length is measured in **UTF-8 bytes** after Cc/Cf stripping, per CON-003.

#![allow(clippy::result_large_err)]

use chia_protocol::Handshake;
use chia_sdk_client::ClientError;
use thiserror::Error;
use unicode_general_category::{get_general_category, GeneralCategory};

/// Maximum UTF-8 byte length of [`Handshake::software_version`] **after** [`sanitize_software_version`].
///
/// **Spec:** [`CON-003.md`](../../../docs/requirements/domains/connection/specs/CON-003.md) — same
/// numeric bound appears in [`PeerConnection::software_version`](crate::types::peer::PeerConnection)
/// documentation (API-005 / CON-006).
pub const MAX_SOFTWARE_VERSION_BYTES: usize = 128;

/// Inclusive minimum `major.minor.patch` accepted from peers (Chia-style dotted triple).
///
/// **Rationale:** DIG reuses the light-wallet protocol stack; outbound historically advertised
/// `"0.0.37"` in [`crate::connection::outbound::connect_outbound_peer`]. We reject peers older than
/// the baseline that can interoperate with current wallet protocol features.
pub const MIN_COMPATIBLE_PROTOCOL_VERSION: &str = "0.0.30";

/// Protocol version string DIG advertises on the wire (listener reply + outbound client hello).
///
/// Kept in one place so CON-003 compatibility checks stay aligned with what we send.
pub const ADVERTISED_PROTOCOL_VERSION: &str = "0.0.37";

/// Sanitize [`Handshake::software_version`] by removing Unicode **Cc** (control) and **Cf** (format)
/// characters — mirrors Chia `ws_connection.py` behavior referenced in CON-003 / CON-008.
///
/// ## Empty result
///
/// A string consisting only of stripped characters becomes `""`, which is **valid** for length
/// checks (CON-003 implementation notes).
pub fn sanitize_software_version(version: &str) -> String {
    version
        .chars()
        .filter(|c| {
            let cat = get_general_category(*c);
            cat != GeneralCategory::Control && cat != GeneralCategory::Format
        })
        .collect()
}

/// Parse `major.minor.patch` with missing segments treated as `0` (Chia-style).
fn parse_protocol_triple(version: &str) -> Option<(u32, u32, u32)> {
    let v = version.trim();
    if v.is_empty() {
        return None;
    }
    let parts: Vec<&str> = v.split('.').collect();
    let a = parts.first()?.parse().ok()?;
    let b = parts.get(1).map(|s| s.parse().ok()).unwrap_or(Some(0))?;
    let c = parts.get(2).map(|s| s.parse().ok()).unwrap_or(Some(0))?;
    Some((a, b, c))
}

/// `true` if `version` parses and is **≥** [`MIN_COMPATIBLE_PROTOCOL_VERSION`] lexicographically
/// as a `(major, minor, patch)` triple.
pub fn is_compatible_protocol_version(version: &str) -> bool {
    let Some(peer) = parse_protocol_triple(version) else {
        return false;
    };
    let Some(min) = parse_protocol_triple(MIN_COMPATIBLE_PROTOCOL_VERSION) else {
        debug_assert!(false, "MIN_COMPATIBLE_PROTOCOL_VERSION must parse");
        return false;
    };
    peer >= min
}

/// Structured failure before the connection is accepted — converted to [`ClientError`] at the edge.
///
/// **Tests:** unit tests match on this enum; production code maps into [`ClientError`] immediately.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HandshakeValidationError {
    #[error("expected network_id {expected}, got {actual}")]
    NetworkIdMismatch { expected: String, actual: String },
    #[error("incompatible protocol_version: {version}")]
    IncompatibleProtocolVersion { version: String },
    #[error("empty network_id in remote handshake")]
    EmptyNetworkId,
    #[error("empty protocol_version in remote handshake")]
    EmptyProtocolVersion,
    #[error("software_version too long after sanitization ({len} bytes, max {max})")]
    SoftwareVersionTooLong { len: usize, max: usize },
}

impl From<HandshakeValidationError> for ClientError {
    fn from(e: HandshakeValidationError) -> Self {
        match e {
            HandshakeValidationError::NetworkIdMismatch { expected, actual } => {
                ClientError::WrongNetwork(expected, actual)
            }
            HandshakeValidationError::IncompatibleProtocolVersion { version } => ClientError::Io(
                std::io::Error::other(format!("dig_gossip: incompatible protocol_version: {version}")),
            ),
            HandshakeValidationError::EmptyNetworkId => {
                ClientError::Io(std::io::Error::other(
                    "dig_gossip: empty network_id in remote handshake",
                ))
            }
            HandshakeValidationError::EmptyProtocolVersion => {
                ClientError::Io(std::io::Error::other(
                    "dig_gossip: empty protocol_version in remote handshake",
                ))
            }
            HandshakeValidationError::SoftwareVersionTooLong { len, max } => ClientError::Io(
                std::io::Error::other(format!(
                    "dig_gossip: software_version too long after sanitization ({len} bytes, max {max})"
                )),
            ),
        }
    }
}

/// Validate `their_handshake` against our expected network id string (hex genesis id from
/// [`crate::connection::outbound::network_id_handshake_string`]).
///
/// Returns the **sanitized** software version string for storage on [`crate::service::state::LiveSlot`]
/// / future [`crate::types::peer::PeerConnection`] (CON-003 acceptance: “stored sanitized”).
pub fn validate_remote_handshake(
    their_handshake: &Handshake,
    expected_network_id: &str,
) -> Result<String, HandshakeValidationError> {
    if their_handshake.network_id.is_empty() {
        return Err(HandshakeValidationError::EmptyNetworkId);
    }
    if their_handshake.protocol_version.trim().is_empty() {
        return Err(HandshakeValidationError::EmptyProtocolVersion);
    }
    if their_handshake.network_id != expected_network_id {
        return Err(HandshakeValidationError::NetworkIdMismatch {
            expected: expected_network_id.to_string(),
            actual: their_handshake.network_id.clone(),
        });
    }
    if !is_compatible_protocol_version(&their_handshake.protocol_version) {
        return Err(HandshakeValidationError::IncompatibleProtocolVersion {
            version: their_handshake.protocol_version.clone(),
        });
    }

    let sanitized = sanitize_software_version(&their_handshake.software_version);
    if sanitized.len() > MAX_SOFTWARE_VERSION_BYTES {
        return Err(HandshakeValidationError::SoftwareVersionTooLong {
            len: sanitized.len(),
            max: MAX_SOFTWARE_VERSION_BYTES,
        });
    }
    Ok(sanitized)
}
