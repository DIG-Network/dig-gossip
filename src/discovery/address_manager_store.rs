//! Persistent **bincode** snapshot of [`crate::discovery::address_manager::AddressManager`] (DSC-002).
//!
//! **Normative:** [`docs/requirements/domains/discovery/specs/DSC-002.md`](../../../../docs/requirements/domains/discovery/specs/DSC-002.md),
//! [`NORMATIVE.md`](../../../../docs/requirements/domains/discovery/NORMATIVE.md).
//!
//! ## Rationale
//!
//! - **Separation of concerns:** [`super::address_manager::Inner`] owns live mutation + Chia
//!   semantics; this module only defines the **frozen** [`AddressManagerState`] and atomic I/O.
//! - **Format:** `bincode` + `serde` keeps payloads compact and matches the rest of the crate
//!   (see `tests/api_010_tests.rs` for config bincode patterns).
//! - **Atomic writes:** Serialize to `path` + `.tmp` in the **same directory**, then rename into
//!   place so a crash mid-write never leaves a half-written peers file at the final name.
//! - **Spec vs round-trip:** DSC-002’s prose shows `tried_table` / `new_table` as `Option<usize>`
//! **entry indices**. We additionally persist `node_ids`, `random_pos`, collision indices, and
//! scalar counters so [`super::address_manager::Inner::from_address_manager_state`] can restore
//! the exact runtime graph without re-deriving Chia `id_count` semantics.
//!
//! ## Async API
//!
//! Public `save` / `load` are `async` per DSC-002; they delegate to [`tokio::task::spawn_blocking`]
//! because `std::fs` + `bincode` are blocking. [`AddressManager::create`](super::address_manager::AddressManager::create)
//! uses [`Self::load_blocking`] on the synchronous construction path.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tokio::task;

use crate::constants::{BUCKET_SIZE, NEW_BUCKET_COUNT, TRIED_BUCKET_COUNT};
use crate::error::GossipError;
use crate::types::peer::ExtendedPeerInfo;

/// On-disk format version for [`AddressManagerState`]. Bump when breaking the snapshot layout.
pub const ADDRESS_MANAGER_STATE_VERSION: u32 = 1;

/// Serializable snapshot of [`super::address_manager::Inner`].
///
/// **DSC-002** defines `version`, `key`, `entries`, `tried_table`, and `new_table`. The extra
/// fields exist so we can restore Chia-compatible runtime invariants (random selection order,
/// collision queue, allocator watermark) without re-simulating discovery traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressManagerState {
    /// Forward-compat tag; writers set [`ADDRESS_MANAGER_STATE_VERSION`].
    pub version: u32,
    /// 256-bit secret for deterministic bucketing (DSC-001).
    pub key: [u8; 32],
    /// Parallel to [`Self::entries`]: stable graph node id (`map_info` key in Python).
    pub node_ids: Vec<u32>,
    /// One [`ExtendedPeerInfo`] per `node_ids[i]`.
    pub entries: Vec<ExtendedPeerInfo>,
    /// Tried matrix: bucket → slot → optional **index** into `entries` / `node_ids`.
    pub tried_table: Vec<Vec<Option<usize>>>,
    /// New matrix: bucket → slot → optional index.
    pub new_table: Vec<Vec<Option<usize>>>,
    /// Order of [`super::address_manager::Inner::random_pos`] as indices into `entries`.
    pub random_pos: Vec<usize>,
    pub last_good: u64,
    /// [`super::address_manager::Inner::tried_collisions`] as indices into `entries`.
    pub tried_collision_indices: Vec<usize>,
    pub allow_private_subnets: bool,
    pub id_count: u32,
    pub tried_count: u32,
    pub new_count: u32,
}

/// Bincode persistence façade (DSC-002).
pub struct AddressManagerStore;

impl AddressManagerStore {
    /// Validate layout before [`super::address_manager::Inner`] consumes a deserialized snapshot.
    pub fn validate_snapshot(state: &AddressManagerState) -> Result<(), GossipError> {
        if state.version != ADDRESS_MANAGER_STATE_VERSION {
            if state.version > ADDRESS_MANAGER_STATE_VERSION {
                return Err(GossipError::AddressManagerStore(format!(
                    "unsupported snapshot version {} (this build supports {})",
                    state.version, ADDRESS_MANAGER_STATE_VERSION
                )));
            }
            return Err(GossipError::AddressManagerStore(format!(
                "invalid snapshot version {}",
                state.version
            )));
        }
        if state.node_ids.len() != state.entries.len() {
            return Err(GossipError::AddressManagerStore(
                "node_ids length must match entries".into(),
            ));
        }
        if state.entries.is_empty() {
            if !state.node_ids.is_empty() || !state.random_pos.is_empty() {
                return Err(GossipError::AddressManagerStore(
                    "empty entries require empty node_ids and random_pos".into(),
                ));
            }
            if state.id_count != 0 || state.tried_count != 0 || state.new_count != 0 {
                return Err(GossipError::AddressManagerStore(
                    "empty snapshot requires zero id/tried/new counts".into(),
                ));
            }
        }
        if state.tried_table.len() != TRIED_BUCKET_COUNT {
            return Err(GossipError::AddressManagerStore(format!(
                "tried_table: expected {} buckets, got {}",
                TRIED_BUCKET_COUNT,
                state.tried_table.len()
            )));
        }
        for row in &state.tried_table {
            if row.len() != BUCKET_SIZE {
                return Err(GossipError::AddressManagerStore(format!(
                    "tried row width: expected {}, got {}",
                    BUCKET_SIZE,
                    row.len()
                )));
            }
            for ix in row.iter().flatten() {
                if *ix >= state.entries.len() {
                    return Err(GossipError::AddressManagerStore(
                        "tried_table index out of range".into(),
                    ));
                }
            }
        }
        if state.new_table.len() != NEW_BUCKET_COUNT {
            return Err(GossipError::AddressManagerStore(format!(
                "new_table: expected {} buckets, got {}",
                NEW_BUCKET_COUNT,
                state.new_table.len()
            )));
        }
        for row in &state.new_table {
            if row.len() != BUCKET_SIZE {
                return Err(GossipError::AddressManagerStore(format!(
                    "new row width: expected {}, got {}",
                    BUCKET_SIZE,
                    row.len()
                )));
            }
            for ix in row.iter().flatten() {
                if *ix >= state.entries.len() {
                    return Err(GossipError::AddressManagerStore(
                        "new_table index out of range".into(),
                    ));
                }
            }
        }
        let n = state.entries.len();
        for &ix in &state.random_pos {
            if ix >= n {
                return Err(GossipError::AddressManagerStore(
                    "random_pos index out of range".into(),
                ));
            }
        }
        for &ix in &state.tried_collision_indices {
            if ix >= n {
                return Err(GossipError::AddressManagerStore(
                    "tried_collision_indices out of range".into(),
                ));
            }
        }
        Ok(())
    }

    /// Serialize and atomically replace `path` (temp sibling + rename).
    pub async fn save(state: &AddressManagerState, path: &Path) -> Result<(), GossipError> {
        let state = state.clone();
        let path = path.to_path_buf();
        task::spawn_blocking(move || save_sync(&state, &path))
            .await
            .map_err(|e| GossipError::AddressManagerStore(e.to_string()))?
    }

    /// Deserialize a snapshot from `path`.
    ///
    /// - **Missing file:** [`Ok`]`(None)`
    /// - **Empty file:** treated as absent (`Ok(None)`) so operators can `touch` a placeholder.
    /// - **Invalid bytes:** [`Err`](GossipError::AddressManagerStore)
    pub async fn load(path: &Path) -> Result<Option<AddressManagerState>, GossipError> {
        let path = path.to_path_buf();
        task::spawn_blocking(move || load_sync(&path))
            .await
            .map_err(|e| GossipError::AddressManagerStore(e.to_string()))?
    }

    /// Blocking save — used from async wrapper and from tests.
    pub fn save_blocking(state: &AddressManagerState, path: &Path) -> Result<(), GossipError> {
        save_sync(state, path)
    }

    /// Blocking load — used by [`super::address_manager::AddressManager::create`].
    pub fn load_blocking(path: &Path) -> Result<Option<AddressManagerState>, GossipError> {
        load_sync(path)
    }
}

fn save_sync(state: &AddressManagerState, path: &Path) -> Result<(), GossipError> {
    AddressManagerStore::validate_snapshot(state)?;
    if path.as_os_str().is_empty() {
        return Err(GossipError::InvalidConfig(
            "peers_file_path is empty; cannot save address manager".into(),
        ));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            GossipError::IoError(format!(
                "peers file path has no parent directory: {}",
                path.display()
            ))
        })?;
    std::fs::create_dir_all(parent).map_err(|e| GossipError::IoError(e.to_string()))?;
    let bytes = bincode::serialize(state)
        .map_err(|e| GossipError::AddressManagerStore(format!("bincode serialize: {e}")))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| GossipError::IoError(e.to_string()))?;
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| GossipError::IoError(e.to_string()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| GossipError::IoError(e.to_string()))?;
    Ok(())
}

fn load_sync(path: &Path) -> Result<Option<AddressManagerState>, GossipError> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path).map_err(|e| GossipError::IoError(e.to_string()))?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let state: AddressManagerState = bincode::deserialize(&bytes)
        .map_err(|e| GossipError::AddressManagerStore(format!("bincode deserialize: {e}")))?;
    AddressManagerStore::validate_snapshot(&state)?;
    Ok(Some(state))
}
