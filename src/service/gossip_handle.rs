//! Cheap clone handle for callers to broadcast, query stats, and shut down.
//!
//! **Requirement:** API-001 (lifecycle gate) + API-002 (full RPC surface) /
//! [`API-002.md`](../../../docs/requirements/domains/crate_api/specs/API-002.md).
//!
//! Every method must verify [`ServiceState::lifecycle`](super::state::ServiceState::lifecycle)
//! until CNC-* centralizes shutdown. API-001 exposes [`Self::health_check`] as a stand-in for the
//! richer async API coming in API-002.

use std::sync::Arc;

use crate::error::GossipError;

use super::state::ServiceState;

/// Cloneable façade over the shared [`ServiceState`] (`Arc` — API-002 will add channels).
#[derive(Debug, Clone)]
pub struct GossipHandle {
    pub(crate) inner: Arc<ServiceState>,
}

impl GossipHandle {
    /// Returns `Ok(())` only while the service lifecycle is **running** (between `start` and `stop`).
    ///
    /// **Rationale:** API-001 verification requires a public async surface that fails with
    /// [`GossipError::ServiceNotStarted`] after `stop()` without implementing the full broadcast
    /// graph yet.
    pub async fn health_check(&self) -> Result<(), GossipError> {
        if self.inner.is_running() {
            Ok(())
        } else {
            Err(GossipError::ServiceNotStarted)
        }
    }
}
