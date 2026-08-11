//! **CON-003** — validate remote [`Handshake`] before accepting a P2P session.
//!
//! **CON-008** — [`sanitize_software_version`] strips Unicode **Cc** (control) and **Cf** (format)
//! from [`Handshake::software_version`] before length checks or storage, matching Chia
//! `ws_connection.py:61-63`. Outbound ([`crate::connection::outbound::connect_outbound_peer`]) and
//! inbound ([`crate::connection::listener::negotiate_inbound_over_ws`]) both call
//! [`validate_remote_handshake`], which delegates sanitization to this module — see
//! `tests/con_008_tests.rs` for the CON-008–specific acceptance matrix.
//!
//! ## SPEC traceability
//!
//! - **SPEC §5.1 step 3** — outbound: the dial
//!   ([`connect_outbound_peer`](crate::connection::outbound::connect_outbound_peer)) “receives and
//!   validates Handshake response”.
//! - **SPEC §5.2 step 5** — inbound: “Receive Handshake, validate `network_id`.”
//! - **SPEC §1.5 #1** — capabilities negotiated via `chia-protocol::Handshake` (the outbound dial
//!   sends the capabilities list). Validation here ensures the remote meets DIG compatibility.
//! - **SPEC §1.5 #7** — the outbound dial rejects peers with mismatched `network_id`.
//! - **SPEC §1.4** — `Handshake` type used directly from `chia-protocol` (not redefined).
//!
//! ## Normative trace
//!
//! - [`CON-003.md`](../../../docs/requirements/domains/connection/specs/CON-003.md) (test plan + acceptance criteria)
//! - [`CON-008.md`](../../../docs/requirements/domains/connection/specs/CON-008.md) (Cc/Cf sanitization matrix)
//! - [`NORMATIVE.md`](../../../docs/requirements/domains/connection/NORMATIVE.md) §CON-003, §CON-008
//! - Chia reference for Cc/Cf stripping: `ws_connection.py` (lines cited in CON-003 / CON-008)
//!
//! ## Design
//!
//! - **Single policy function** [`validate_remote_handshake`] is invoked from **both** outbound
//!   ([`crate::connection::outbound::connect_outbound_peer`]) and inbound
//!   ([`crate::connection::listener::negotiate_inbound_over_ws`]) so “both directions validated” is
//!   a literal shared code path (see `tests/con_003_tests.rs` integration + `tests/con_008_tests.rs`
//!   for the sanitization-focused traceability suite).
//! - We map semantic failures onto existing [`dig_peer_protocol::ClientError`] variants where they
//!   fit ([`ClientError::WrongNetwork`]); remaining policy failures use [`ClientError::Io`] with a
//!   stable prefix so integration tests can substring-match without inventing new upstream enum
//!   variants (chia-sdk-client 0.28’s [`ClientError`](dig_peer_protocol::ClientError) is closed).
//! - **Protocol versions** are compared as dot-separated numeric tuples (Chia’s wire convention).
//!   [`MIN_COMPATIBLE_PROTOCOL_VERSION`] is the inclusive floor; peers below it are rejected.
//! - **Software version** length is measured in **UTF-8 bytes** after Cc/Cf stripping, per CON-003.

#![allow(clippy::result_large_err)]

use chia_protocol::Handshake;
use dig_peer_protocol::ClientError;
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
/// characters — mirrors Chia `ws_connection.py:61-63` behavior.
///
/// **Normative:** [`CON-008.md`](../../../docs/requirements/domains/connection/specs/CON-008.md),
/// [`NORMATIVE.md`](../../../docs/requirements/domains/connection/NORMATIVE.md) §CON-008.
///
/// ## Implementation choice (Cf vs `char::is_control`)
///
/// Rust’s [`char::is_control`] covers **Cc** but not **Cf** (e.g. zero-width space, BOM). We use the
/// `unicode-general-category` crate’s [`get_general_category`](unicode_general_category::get_general_category)
/// so category membership tracks the same Unicode data files Chia’s Python `unicodedata.category`
/// consults — this is the “matches Chia” row in CON-008’s test plan (`test_matches_chia_category_policy`).
///
/// SPEC §1.6 #1 — "Peer exchange on outbound connect" implies the handshake carries metadata whose
/// `software_version` must be sanitized before storage.
///
/// ## Empty result
///
/// A string consisting only of stripped characters becomes `""`, which is **valid** for length
/// checks (CON-003 / CON-008 implementation notes).
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
///
/// SPEC §1.5 #7 — `connect_peer()` rejects peers with mismatched `network_id`; this function
/// extends that gate to protocol version compatibility so DIG can reject outdated peers.
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
/// SPEC §5.1 step 3 / §5.2 step 5 — handshake validation can fail for network mismatch,
/// incompatible protocol version, or oversized software version. Each variant maps to a
/// specific wire-level rejection reason.
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

impl From<HandshakeValidationError> for dig_peer_protocol::LinkError {
    /// Mirror the [`ClientError`] mapping onto the link transport's error type.
    ///
    /// `LinkError` has no dedicated wrong-network variant, so a network mismatch is
    /// rendered as an I/O error carrying both ids — the same information, in the one
    /// variant that can hold it.
    fn from(e: HandshakeValidationError) -> Self {
        let message = match e {
            HandshakeValidationError::NetworkIdMismatch { expected, actual } => {
                format!("dig_gossip: wrong network: expected {expected}, got {actual}")
            }
            other => ClientError::from(other).to_string(),
        };
        dig_peer_protocol::LinkError::Io(std::io::Error::other(message))
    }
}

/// Validate `their_handshake` against our expected network id string (hex genesis id from
/// [`crate::connection::outbound::network_id_handshake_string`]).
///
/// SPEC §5.1 step 3 — “Receives and validates Handshake response” (outbound path).
/// SPEC §5.2 step 5 — “Receive Handshake, validate `network_id`” (inbound path).
/// SPEC §1.1 — “Chia protocol parity”: the handshake, message framing, and peer exchange
/// protocols match Chia's networking protocol.
///
/// Returns the **sanitized** software version string for storage on [`crate::service::state::LiveSlot`]
/// ([`crate::service::state::LiveSlot::remote_software_version_sanitized`]) and for any
/// [`crate::types::peer::PeerConnection::software_version`] snapshot built from that field
/// (CON-003 / CON-008: “stored sanitized”).
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

// ============================================================================
// NodeType bridge — the chia/DIG boundary
// ============================================================================

/// Translate the `node_type` carried on a Chia [`Handshake`] into the DIG role enum.
///
/// # Why a bridge and not a cast
///
/// `Handshake` is a Chia full-node message, so its `node_type` is
/// `chia_protocol::NodeType`; every DIG-side surface (peer records, introducer
/// registration, SPEC §6.5) speaks [`dig_peer_protocol::NodeType`]. The two enums
/// enumerate the same seven roles with the same wire discriminants `1..=7`, but they
/// are distinct Rust types, and an `as`-cast between them would silently paper over
/// any future divergence in either crate.
///
/// # Why this is total
///
/// Both are closed Rust enums, so a value of either type is necessarily one of the
/// seven roles — there is no unknown-discriminant case to handle, and therefore no
/// temptation to default one. (An unparseable byte is rejected earlier, when
/// `Handshake` itself is decoded.) The exhaustive match means adding a role to
/// either crate breaks the build here rather than silently mapping to a wrong role.
#[must_use]
pub fn dig_node_type_of(node_type: chia_protocol::NodeType) -> dig_peer_protocol::NodeType {
    match node_type {
        chia_protocol::NodeType::FullNode => dig_peer_protocol::NodeType::FullNode,
        chia_protocol::NodeType::Harvester => dig_peer_protocol::NodeType::Harvester,
        chia_protocol::NodeType::Farmer => dig_peer_protocol::NodeType::Farmer,
        chia_protocol::NodeType::Timelord => dig_peer_protocol::NodeType::Timelord,
        chia_protocol::NodeType::Introducer => dig_peer_protocol::NodeType::Introducer,
        chia_protocol::NodeType::Wallet => dig_peer_protocol::NodeType::Wallet,
        chia_protocol::NodeType::DataLayer => dig_peer_protocol::NodeType::DataLayer,
    }
}

/// Translate a DIG role into the `node_type` a Chia [`Handshake`] carries.
///
/// The exact inverse of [`dig_node_type_of`]; see that function for why the two
/// enums need a bridge at all and why both directions are total.
#[must_use]
pub fn chia_node_type_of(node_type: dig_peer_protocol::NodeType) -> chia_protocol::NodeType {
    match node_type {
        dig_peer_protocol::NodeType::FullNode => chia_protocol::NodeType::FullNode,
        dig_peer_protocol::NodeType::Harvester => chia_protocol::NodeType::Harvester,
        dig_peer_protocol::NodeType::Farmer => chia_protocol::NodeType::Farmer,
        dig_peer_protocol::NodeType::Timelord => chia_protocol::NodeType::Timelord,
        dig_peer_protocol::NodeType::Introducer => chia_protocol::NodeType::Introducer,
        dig_peer_protocol::NodeType::Wallet => chia_protocol::NodeType::Wallet,
        dig_peer_protocol::NodeType::DataLayer => chia_protocol::NodeType::DataLayer,
    }
}

#[cfg(test)]
mod node_type_bridge_tests {
    use super::{chia_node_type_of, dig_node_type_of};

    /// Every DIG role round-trips through the Chia enum and back to itself, and
    /// lands on the same wire byte in both representations.
    ///
    /// Asserting the byte as well as the round-trip is what makes this test
    /// load-bearing: a bridge that mapped two roles onto each other consistently
    /// in both directions would round-trip perfectly while putting the wrong
    /// discriminant on the wire.
    #[test]
    fn node_type_bridge_covers_every_role() {
        use dig_peer_protocol::NodeType as Dig;

        let roles = [
            Dig::FullNode,
            Dig::Harvester,
            Dig::Farmer,
            Dig::Timelord,
            Dig::Introducer,
            Dig::Wallet,
            Dig::DataLayer,
        ];
        assert_eq!(roles.len(), 7, "all seven roles are covered");

        for role in roles {
            let chia = chia_node_type_of(role);
            assert_eq!(
                chia as u8,
                role.to_byte(),
                "{role:?} must occupy the same wire byte in both enums"
            );
            assert_eq!(dig_node_type_of(chia), role, "{role:?} round-trips");
        }
    }

    /// The bridge is a bijection: mapping DIG -> Chia -> DIG returns the original
    /// role for all seven, so no two roles collapse onto one.
    #[test]
    fn node_type_bridge_is_a_bijection() {
        use dig_peer_protocol::NodeType as Dig;

        let roles = [
            Dig::FullNode,
            Dig::Harvester,
            Dig::Farmer,
            Dig::Timelord,
            Dig::Introducer,
            Dig::Wallet,
            Dig::DataLayer,
        ];
        let mapped: Vec<u8> = roles.iter().map(|r| chia_node_type_of(*r) as u8).collect();
        let mut unique = mapped.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            roles.len(),
            "no two DIG roles share a Chia role"
        );
    }
}
