//! Peer reputation and penalty reasons (API-006).

/// Rolling penalties, ban state, and decay — placeholder until API-006 fills behavior.
#[derive(Debug, Clone, Default)]
pub struct PeerReputation {}

/// Why a penalty was applied (rate limit, invalid message, protocol abuse, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PenaltyReason {
    /// Placeholder — variants will mirror API-006.
    Unspecified,
}
