//! Address manager (tried/new tables, bucketing, eviction).
//!
//! **Re-export:** STR-003; **logic:** DSC-001+.
//!
//! ## CON-001 stub (`add_to_new_table`)
//!
//! NORMATIVE ([`CON-001`](../../../docs/requirements/domains/connection/specs/CON-001.md)) requires that
//! after outbound `RequestPeers`, the `RespondPeers.peer_list` is merged into the **new** table with
//! source attribution. DSC-001 will port Chia `address_manager.py` in full; until then we record
//! batches in-memory so integration tests can prove the gossip service invoked the hook with the
//! expected [`TimestampedPeerInfo`](chia_protocol::TimestampedPeerInfo) rows.

use std::sync::Mutex;

use chia_protocol::TimestampedPeerInfo;

use crate::types::peer::PeerInfo;

/// Port of Chia `address_manager.py` — CON-001 records outbound discovery batches; DSC-001 expands structure.
#[derive(Debug)]
pub struct AddressManager {
    /// Last `add_to_new_table` call (test introspection / future metrics).
    last_new_batch: Mutex<Option<(Vec<TimestampedPeerInfo>, PeerInfo)>>,
}

impl Default for AddressManager {
    fn default() -> Self {
        Self {
            last_new_batch: Mutex::new(None),
        }
    }
}

impl AddressManager {
    /// Append peers learned from `RequestPeers` / `RespondPeers` into the **new** table.
    ///
    /// **Parameters (Chia `node_discovery.py:135-136` shape):**
    /// - `peer_list` — addresses returned by the remote full node.
    /// - `src` — our view of **who told us** (outbound target as [`PeerInfo`]).
    /// - `_source_time` — reserved for timestamp / horizon policy (DSC-001); unused in stub.
    ///
    /// **Async in spec:** DSC-001 will await bucket locks; synchronous stub keeps call sites simple.
    pub fn add_to_new_table(
        &self,
        peer_list: &[TimestampedPeerInfo],
        src: &PeerInfo,
        _source_time: u32,
    ) {
        let mut g = self
            .last_new_batch
            .lock()
            .expect("address_manager last_new_batch mutex poisoned");
        *g = Some((peer_list.to_vec(), src.clone()));
    }

    /// Test hook: snapshot the last [`Self::add_to_new_table`] invocation (CON-001 verification).
    #[doc(hidden)]
    pub fn __last_new_table_batch_for_tests(&self) -> Option<(Vec<TimestampedPeerInfo>, PeerInfo)> {
        self.last_new_batch
            .lock()
            .expect("address_manager last_new_batch mutex poisoned")
            .clone()
    }
}
