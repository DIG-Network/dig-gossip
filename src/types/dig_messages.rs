//! DIG-specific protocol message type IDs (200+ range), distinct from Chia’s enum.

/// Wire discriminator for DIG extensions (attestations, checkpoints, status, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigMessageType {
    /// Lower bound of the DIG-reserved band (API-009 will assign real IDs).
    ReservedBase = 200,
}
