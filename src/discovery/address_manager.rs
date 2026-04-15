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

/// Port of Chia `address_manager.py` — CON-001 / CON-002 record discovery batches; DSC-001 expands structure.
#[derive(Debug)]
pub struct AddressManager {
    /// Append-only log of [`Self::add_to_new_table`] calls (CON-002 may run after CON-001 outbound).
    ///
    /// **Test hook:** [`Self::__last_new_table_batch_for_tests`] returns the final entry so CON-001
    /// assertions stay unchanged.
    new_table_log: Mutex<Vec<(Vec<TimestampedPeerInfo>, PeerInfo)>>,
}

impl Default for AddressManager {
    fn default() -> Self {
        Self {
            new_table_log: Mutex::new(Vec::new()),
        }
    }
}

impl AddressManager {
    /// Append peers learned from `RequestPeers` / `RespondPeers` (outbound) or inbound acceptance
    /// (CON-002) into the **new** table.
    ///
    /// **Parameters (Chia `node_discovery.py:135-136` shape):**
    /// - `peer_list` — addresses returned by the remote full node **or** a single inbound peer row.
    /// - `src` — attribution: for outbound this is the dialed peer; for inbound CON-002 this is
    ///   [`PeerInfo`] describing **this service’s** listen endpoint (see [`CON-002.md`](../../../docs/requirements/domains/connection/specs/CON-002.md)).
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
            .new_table_log
            .lock()
            .expect("address_manager new_table_log mutex poisoned");
        g.push((peer_list.to_vec(), src.clone()));
    }

    /// Test hook: snapshot the last [`Self::add_to_new_table`] invocation (CON-001 verification).
    #[doc(hidden)]
    pub fn __last_new_table_batch_for_tests(&self) -> Option<(Vec<TimestampedPeerInfo>, PeerInfo)> {
        self.new_table_log
            .lock()
            .expect("address_manager new_table_log mutex poisoned")
            .last()
            .cloned()
    }
}
