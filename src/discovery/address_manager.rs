//! Address manager (tried/new tables, bucketing, eviction).
//!
//! **Re-export:** STR-003; **logic:** DSC-001 / DSC-002 (persistence deferred).
//!
//! ## SPEC citations
//!
//! - SPEC §6.3 — Address Manager: Rust port of `address_manager.py` (Bitcoin `CAddrMan`
//!   tried/new bucket tables, collision resolution, eviction).
//! - [`docs/requirements/domains/discovery/specs/DSC-001.md`](../../../../docs/requirements/domains/discovery/specs/DSC-001.md)
//!   — public API and acceptance tests.
//! - Chia source (authoritative for bucket math and eviction):
//!   <https://github.com/Chia-Network/chia-blockchain/blob/main/chia/server/address_manager.py>
//!
//! ## Design decisions
//!
//! - **Hash function:** Chia’s `std_hash` is SHA-256 ([`chia.util.hash.std_hash`](https://github.com/Chia-Network/chia-blockchain/blob/main/chia/util/hash.py));
//!   bucket indices use the **first 8 bytes big-endian** as `u64`, matching Python
//!   `int.from_bytes(std_hash(...)[:8], "big")`.
//! - **`map_addr` key:** Chia indexes `map_addr` by **host string only** (not port); we mirror
//!   that for wire-compat even though it collapses multi-port hosts.
//! - **Sync API:** DSC-001 prose shows `async fn`; gossip call sites ([`GossipHandle`](crate::service::gossip_handle::GossipHandle),
//!   [`listener`](crate::connection::listener)) invoke ingestion **synchronously**. This type uses
//!   one [`Mutex`] (`std::sync`, not `tokio::sync`) so `add_to_new_table` stays non-`.await`.
//! - **Persistence (DSC-002):** [`Self::create`] loads a [`super::address_manager_store::AddressManagerState`]
//!   snapshot when [`Inner::peers_file_path`] exists and is non-empty; [`Self::save`] writes atomically
//!   via [`super::address_manager_store::AddressManagerStore`].
//! - **Private addresses:** Chia skips RFC1918 unless `allow_private_subnets`; tests and localnets
//!   call [`Self::set_allow_private_subnets`].
//!
//! ## CON-001
//!
//! [`Self::add_to_new_table`] still appends to [`Inner::new_table_log`] so
//! [`Self::__last_new_table_batch_for_tests`] remains stable for `tests/con_001_tests.rs`.

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use dig_protocol::TimestampedPeerInfo;
use rand::Rng;
use rand::RngCore;

use crate::constants::{
    BUCKET_SIZE, LOG_BUCKET_SIZE, LOG_NEW_BUCKET_COUNT, LOG_TRIED_BUCKET_COUNT,
    NEW_BUCKETS_PER_ADDRESS, NEW_BUCKET_COUNT, TRIED_BUCKET_COUNT, TRIED_COLLISION_SIZE,
};
use crate::error::GossipError;
use crate::types::peer::{metric_unix_timestamp_secs, ExtendedPeerInfo, PeerInfo};

use super::address_manager_store::{
    AddressManagerState, AddressManagerStore, ADDRESS_MANAGER_STATE_VERSION,
};

type NodeId = u32;
const EMPTY: i32 = -1;

/// Backing storage for [`AddressManager`] — all fields mirror Chia `AddressManager` dataclass
/// (`address_manager.py:222+`) where applicable.
struct Inner {
    /// 256-bit secret mixed into every bucket hash (Chia `key: int` big-endian).
    key: [u8; 32],
    /// Monotonic id allocator; first assigned id is `1` (Python pre-increments).
    id_count: NodeId,
    tried_matrix: Vec<Vec<i32>>,
    new_matrix: Vec<Vec<i32>>,
    tried_count: u32,
    new_count: u32,
    /// Host string → node id (Chia `map_addr` — **host only**).
    map_addr: HashMap<String, NodeId>,
    map_info: HashMap<NodeId, ExtendedPeerInfo>,
    random_pos: Vec<NodeId>,
    last_good: u64,
    tried_collisions: Vec<NodeId>,
    used_new_matrix_positions: HashSet<(usize, usize)>,
    used_tried_matrix_positions: HashSet<(usize, usize)>,
    allow_private_subnets: bool,
    /// CON-001 / CON-002 — last merge batches for integration tests.
    new_table_log: Vec<(Vec<TimestampedPeerInfo>, PeerInfo)>,
    /// Target path for DSC-002 save/load (recorded at construction).
    peers_file_path: PathBuf,
}

impl Inner {
    fn new(key: [u8; 32], peers_file_path: PathBuf) -> Self {
        Self {
            key,
            id_count: 0,
            tried_matrix: vec![vec![EMPTY; BUCKET_SIZE]; TRIED_BUCKET_COUNT],
            new_matrix: vec![vec![EMPTY; BUCKET_SIZE]; NEW_BUCKET_COUNT],
            tried_count: 0,
            new_count: 0,
            map_addr: HashMap::new(),
            map_info: HashMap::new(),
            random_pos: Vec::new(),
            last_good: 1,
            tried_collisions: Vec::new(),
            used_new_matrix_positions: HashSet::new(),
            used_tried_matrix_positions: HashSet::new(),
            allow_private_subnets: false,
            new_table_log: Vec::new(),
            peers_file_path,
        }
    }

    fn peer_row_from_ts(addr: &TimestampedPeerInfo, src: &PeerInfo) -> ExtendedPeerInfo {
        ExtendedPeerInfo {
            peer_info: PeerInfo {
                host: addr.host.clone(),
                port: addr.port,
            },
            timestamp: addr.timestamp,
            src: src.clone(),
            random_pos: None,
            is_tried: false,
            ref_count: 0,
            last_success: 0,
            last_try: 0,
            num_attempts: 0,
            last_count_attempt: 0,
        }
    }

    /// Chia filters `IPAddress.is_private` (RFC1918 + IPv6 ULA); hostnames are never “private”.
    fn host_is_private(host: &str) -> bool {
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => v4.is_private(),
            Ok(IpAddr::V6(v6)) => v6.is_unique_local(),
            Err(_) => false,
        }
    }

    fn find(&self, addr: &PeerInfo) -> (Option<NodeId>, Option<&ExtendedPeerInfo>) {
        let Some(&node_id) = self.map_addr.get(&addr.host) else {
            return (None, None);
        };
        let Some(info) = self.map_info.get(&node_id) else {
            return (Some(node_id), None);
        };
        (Some(node_id), Some(info))
    }

    fn swap_random(&mut self, r1: usize, r2: usize) {
        if r1 == r2 {
            return;
        }
        debug_assert!(r1 < self.random_pos.len() && r2 < self.random_pos.len());
        let id1 = self.random_pos[r1];
        let id2 = self.random_pos[r2];
        if let Some(i1) = self.map_info.get_mut(&id1) {
            i1.random_pos = Some(r2);
        }
        if let Some(i2) = self.map_info.get_mut(&id2) {
            i2.random_pos = Some(r1);
        }
        self.random_pos.swap(r1, r2);
    }

    fn set_new_matrix(&mut self, row: usize, col: usize, value: i32) {
        self.new_matrix[row][col] = value;
        let pos = (row, col);
        if value == EMPTY {
            self.used_new_matrix_positions.remove(&pos);
        } else {
            self.used_new_matrix_positions.insert(pos);
        }
    }

    fn set_tried_matrix(&mut self, row: usize, col: usize, value: i32) {
        self.tried_matrix[row][col] = value;
        let pos = (row, col);
        if value == EMPTY {
            self.used_tried_matrix_positions.remove(&pos);
        } else {
            self.used_tried_matrix_positions.insert(pos);
        }
    }

    fn clear_new(&mut self, bucket: usize, pos: usize) {
        if self.new_matrix[bucket][pos] == EMPTY {
            return;
        }
        let delete_id = self.new_matrix[bucket][pos] as NodeId;
        if let Some(delete_info) = self.map_info.get_mut(&delete_id) {
            debug_assert!(delete_info.ref_count > 0);
            delete_info.ref_count -= 1;
        }
        self.set_new_matrix(bucket, pos, EMPTY);
        if let Some(delete_info) = self.map_info.get(&delete_id) {
            if delete_info.ref_count == 0 {
                self.delete_new_entry(delete_id);
            }
        }
    }

    fn delete_new_entry(&mut self, node_id: NodeId) {
        let Some(info) = self.map_info.get(&node_id) else {
            return;
        };
        let Some(rp) = info.random_pos else {
            return;
        };
        self.swap_random(rp, self.random_pos.len() - 1);
        self.random_pos.pop();
        let info = self.map_info.remove(&node_id).expect("node exists");
        self.map_addr.remove(&info.peer_info.host);
        self.new_count -= 1;
    }

    fn create_row(&mut self, addr: &TimestampedPeerInfo, addr_src: &PeerInfo) -> NodeId {
        self.id_count = self.id_count.saturating_add(1);
        let node_id = self.id_count;
        let mut row = Self::peer_row_from_ts(addr, addr_src);
        row.random_pos = Some(self.random_pos.len());
        self.map_addr.insert(row.peer_info.host.clone(), node_id);
        self.map_info.insert(node_id, row);
        self.random_pos.push(node_id);
        node_id
    }

    /// Move `node_id` from the new table into tried (Chia `make_tried_`, `address_manager.py:426+`).
    ///
    /// **Rationale:** This follows the Python control flow literally—including the “evict tried
    /// occupant back into one new slot” path—so future DSC-002 snapshots stay compatible.
    fn make_tried(&mut self, node_id: NodeId) {
        for bucket in 0..NEW_BUCKET_COUNT {
            let pos = {
                let info = self.map_info.get(&node_id).expect("make_tried row");
                info.bucket_position(&self.key, true, bucket)
            };
            if self.new_matrix[bucket][pos] == node_id as i32 {
                if let Some(info) = self.map_info.get_mut(&node_id) {
                    info.ref_count = info.ref_count.saturating_sub(1);
                }
                self.set_new_matrix(bucket, pos, EMPTY);
            }
        }
        debug_assert_eq!(
            self.map_info.get(&node_id).expect("row").ref_count,
            0,
            "all new refs cleared before tried promotion"
        );
        self.new_count = self.new_count.saturating_sub(1);

        let (cur_bucket, cur_bucket_pos) = {
            let info = self.map_info.get(&node_id).expect("row");
            let b = info.tried_bucket_index(&self.key);
            let p = info.bucket_position(&self.key, false, b);
            (b, p)
        };

        if self.tried_matrix[cur_bucket][cur_bucket_pos] != EMPTY {
            let node_id_evict = self.tried_matrix[cur_bucket][cur_bucket_pos] as NodeId;
            let mut ev = self
                .map_info
                .remove(&node_id_evict)
                .expect("evicted tried row");
            ev.is_tried = false;
            self.set_tried_matrix(cur_bucket, cur_bucket_pos, EMPTY);
            self.tried_count -= 1;
            let nb = ev.new_bucket_index(&self.key, &ev.src);
            let np = ev.bucket_position(&self.key, true, nb);
            self.clear_new(nb, np);
            ev.ref_count = 1;
            self.set_new_matrix(nb, np, node_id_evict as i32);
            self.new_count += 1;
            self.map_info.insert(node_id_evict, ev);
        }

        self.set_tried_matrix(cur_bucket, cur_bucket_pos, node_id as i32);
        self.tried_count += 1;
        if let Some(e) = self.map_info.get_mut(&node_id) {
            e.is_tried = true;
        }
    }

    fn mark_good_(
        &mut self,
        addr: &PeerInfo,
        test_before_evict: bool,
        timestamp: u64,
        rng: &mut impl Rng,
    ) {
        self.last_good = timestamp;
        let (node_id_opt, info_opt) = self.find(addr);
        let Some(node_id) = node_id_opt else {
            return;
        };
        let Some(info) = info_opt else {
            return;
        };
        if Self::host_is_private(&addr.host) && !self.allow_private_subnets {
            return;
        }
        if info.peer_info != *addr {
            return;
        }
        let mut info = info.clone();
        info.last_success = timestamp;
        info.last_try = timestamp;
        info.num_attempts = 0;
        self.map_info.insert(node_id, info.clone());

        if info.is_tried {
            return;
        }

        let bucket_rand = rng.gen_range(0..NEW_BUCKET_COUNT);
        let mut new_bucket = usize::MAX;
        for n in 0..NEW_BUCKET_COUNT {
            let cur_new_bucket = (n + bucket_rand) % NEW_BUCKET_COUNT;
            let cur_new_bucket_pos = info.bucket_position(&self.key, true, cur_new_bucket);
            if self.new_matrix[cur_new_bucket][cur_new_bucket_pos] == node_id as i32 {
                new_bucket = cur_new_bucket;
                break;
            }
        }
        if new_bucket == usize::MAX {
            return;
        }

        let tried_bucket = info.tried_bucket_index(&self.key);
        let tried_bucket_pos = info.bucket_position(&self.key, false, tried_bucket);

        if test_before_evict && self.tried_matrix[tried_bucket][tried_bucket_pos] != EMPTY {
            if self.tried_collisions.len() < TRIED_COLLISION_SIZE {
                if !self.tried_collisions.contains(&node_id) {
                    self.tried_collisions.push(node_id);
                }
            } else {
                self.make_tried(node_id);
            }
        } else {
            self.make_tried(node_id);
        }
    }

    fn add_to_new_table_(
        &mut self,
        addr: &TimestampedPeerInfo,
        source: &PeerInfo,
        penalty: u64,
        rng: &mut impl Rng,
    ) -> bool {
        let mut is_unique = false;
        let peer_info = PeerInfo {
            host: addr.host.clone(),
            port: addr.port,
        };
        if Self::host_is_private(&peer_info.host) && !self.allow_private_subnets {
            return false;
        }
        let now = metric_unix_timestamp_secs();
        let (existing_id, existing_info) = self.find(&peer_info);
        let mut penalty = penalty;
        if let Some(info) = existing_info {
            if info.peer_info == peer_info {
                penalty = 0;
            }
        }

        let node_id = if let Some(ex) = existing_info {
            let node_id = existing_id.expect("paired id with row");
            let mut info = ex.clone();
            let currently_online = now.saturating_sub(addr.timestamp) < 24 * 60 * 60;
            let update_interval: u64 = if currently_online {
                60 * 60
            } else {
                24 * 60 * 60
            };
            if addr.timestamp > 0
                && (info.timestamp > 0
                    || info.timestamp
                        < addr
                            .timestamp
                            .saturating_sub(update_interval.saturating_add(penalty)))
            {
                info.timestamp = addr.timestamp.saturating_sub(penalty);
                self.map_info.insert(node_id, info);
            }
            let info = self.map_info.get(&node_id).expect("row").clone();
            if addr.timestamp == 0 || (info.timestamp > 0 && addr.timestamp <= info.timestamp) {
                return false;
            }
            if info.is_tried {
                return false;
            }
            if info.ref_count >= NEW_BUCKETS_PER_ADDRESS as u32 {
                return false;
            }
            let factor = 1u32 << info.ref_count.min(31);
            if factor > 1 && rng.gen_range(0..factor) != 0 {
                return false;
            }
            node_id
        } else {
            let node_id = self.create_row(addr, source);
            let ts = addr.timestamp.saturating_sub(penalty);
            self.map_info.get_mut(&node_id).expect("row").timestamp = ts;
            self.new_count += 1;
            is_unique = true;
            node_id
        };

        let info = self.map_info.get(&node_id).expect("row").clone();
        let new_bucket = info.new_bucket_index(&self.key, source);
        let new_bucket_pos = info.bucket_position(&self.key, true, new_bucket);
        if self.new_matrix[new_bucket][new_bucket_pos] != node_id as i32 {
            let mut add_to_new = self.new_matrix[new_bucket][new_bucket_pos] == EMPTY;
            if !add_to_new {
                let existing_slot = self.new_matrix[new_bucket][new_bucket_pos] as NodeId;
                let info_existing = self.map_info.get(&existing_slot).expect("existing");
                let now2 = metric_unix_timestamp_secs();
                if info_existing.is_terrible(now2)
                    || (info_existing.ref_count > 1 && info.ref_count == 0)
                {
                    add_to_new = true;
                }
            }
            if add_to_new {
                self.clear_new(new_bucket, new_bucket_pos);
                self.map_info.get_mut(&node_id).expect("row").ref_count += 1;
                self.set_new_matrix(new_bucket, new_bucket_pos, node_id as i32);
            } else if self.map_info.get(&node_id).expect("row").ref_count == 0 {
                self.delete_new_entry(node_id);
            }
        }
        is_unique
    }

    fn attempt_(&mut self, addr: &PeerInfo, count_failures: bool, timestamp: u64) {
        let (id_opt, info_opt) = self.find(addr);
        let Some(id) = id_opt else {
            return;
        };
        let Some(info) = info_opt else {
            return;
        };
        if info.peer_info != *addr {
            return;
        }
        let mut info = info.clone();
        info.last_try = timestamp;
        if count_failures && info.last_count_attempt < self.last_good {
            info.last_count_attempt = timestamp;
            info.num_attempts = info.num_attempts.saturating_add(1);
        }
        self.map_info.insert(id, info);
    }

    fn connect_(&mut self, addr: &PeerInfo, timestamp: u64) {
        let (id_opt, info_opt) = self.find(addr);
        let Some(id) = id_opt else {
            return;
        };
        let Some(info) = info_opt else {
            return;
        };
        if info.peer_info != *addr {
            return;
        }
        let mut info = info.clone();
        let update_interval = 20 * 60;
        if timestamp.saturating_sub(info.timestamp) > update_interval {
            info.timestamp = timestamp;
        }
        self.map_info.insert(id, info);
    }

    fn select_peer_(&mut self, new_only: bool, rng: &mut impl Rng) -> Option<ExtendedPeerInfo> {
        if self.random_pos.is_empty() {
            return None;
        }
        if new_only && self.new_count == 0 {
            return None;
        }
        let now = metric_unix_timestamp_secs();
        if !new_only && self.tried_count > 0 && (self.new_count == 0 || rng.gen_range(0..2) == 0) {
            let sqrt_slots = ((TRIED_BUCKET_COUNT * BUCKET_SIZE) as f64).sqrt() as usize;
            let mut chance = 1.0_f64;
            let cached = if self.used_tried_matrix_positions.len() < sqrt_slots {
                Some(
                    self.used_tried_matrix_positions
                        .iter()
                        .copied()
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            };
            let mut iters = 0u32;
            loop {
                iters += 1;
                if iters > 50_000 {
                    return None;
                }
                let (tried_bucket, tried_bucket_pos) = if let Some(ref c) = cached {
                    if c.is_empty() {
                        return None;
                    }
                    let idx = rng.gen_range(0..c.len());
                    c[idx]
                } else {
                    let mut tried_bucket = rng.gen_range(0..TRIED_BUCKET_COUNT);
                    let mut tried_bucket_pos = rng.gen_range(0..BUCKET_SIZE);
                    while self.tried_matrix[tried_bucket][tried_bucket_pos] == EMPTY {
                        tried_bucket = (tried_bucket
                            + (rng.gen::<usize>() % (1usize << LOG_TRIED_BUCKET_COUNT)))
                            % TRIED_BUCKET_COUNT;
                        tried_bucket_pos = (tried_bucket_pos
                            + (rng.gen::<usize>() % (1usize << LOG_BUCKET_SIZE)))
                            % BUCKET_SIZE;
                    }
                    (tried_bucket, tried_bucket_pos)
                };
                let node_id = self.tried_matrix[tried_bucket][tried_bucket_pos];
                if node_id == EMPTY {
                    continue;
                }
                let info = self.map_info.get(&(node_id as NodeId))?.clone();
                let threshold =
                    (chance * info.get_selection_chance(now) * (1u64 << 30) as f64) as u32;
                if rng.gen::<u32>() & ((1u32 << 30) - 1) < threshold {
                    return Some(info);
                }
                chance *= 1.2;
            }
        } else {
            let sqrt_slots = ((NEW_BUCKET_COUNT * BUCKET_SIZE) as f64).sqrt() as usize;
            let mut chance = 1.0_f64;
            let cached = if self.used_new_matrix_positions.len() < sqrt_slots {
                Some(
                    self.used_new_matrix_positions
                        .iter()
                        .copied()
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            };
            let mut iters = 0u32;
            loop {
                iters += 1;
                if iters > 50_000 {
                    return None;
                }
                let (new_bucket, new_bucket_pos) = if let Some(ref c) = cached {
                    if c.is_empty() {
                        return None;
                    }
                    let idx = rng.gen_range(0..c.len());
                    c[idx]
                } else {
                    let mut new_bucket = rng.gen_range(0..NEW_BUCKET_COUNT);
                    let mut new_bucket_pos = rng.gen_range(0..BUCKET_SIZE);
                    while self.new_matrix[new_bucket][new_bucket_pos] == EMPTY {
                        new_bucket = (new_bucket
                            + (rng.gen::<usize>() % (1usize << LOG_NEW_BUCKET_COUNT)))
                            % NEW_BUCKET_COUNT;
                        new_bucket_pos = (new_bucket_pos
                            + (rng.gen::<usize>() % (1usize << LOG_BUCKET_SIZE)))
                            % BUCKET_SIZE;
                    }
                    (new_bucket, new_bucket_pos)
                };
                let node_id = self.new_matrix[new_bucket][new_bucket_pos];
                if node_id == EMPTY {
                    continue;
                }
                let info = self.map_info.get(&(node_id as NodeId))?.clone();
                let threshold =
                    (chance * info.get_selection_chance(now) * (1u64 << 30) as f64) as u32;
                if rng.gen::<u32>() & ((1u32 << 30) - 1) < threshold {
                    return Some(info);
                }
                chance *= 1.2;
            }
        }
    }

    fn resolve_tried_collisions_(&mut self, now: u64, rng: &mut impl Rng) {
        let pending: Vec<NodeId> = self.tried_collisions.clone();
        for node_id in pending {
            let mut resolved = false;
            if !self.map_info.contains_key(&node_id) {
                resolved = true;
            } else if let Some(info) = self.map_info.get(&node_id).cloned() {
                let peer = info.peer_info.clone();
                let tried_bucket = info.tried_bucket_index(&self.key);
                let tried_bucket_pos = info.bucket_position(&self.key, false, tried_bucket);
                if self.tried_matrix[tried_bucket][tried_bucket_pos] != EMPTY {
                    let old_id = self.tried_matrix[tried_bucket][tried_bucket_pos] as NodeId;
                    if let Some(old_info) = self.map_info.get(&old_id) {
                        if now.saturating_sub(old_info.last_success) < 4 * 60 * 60 {
                            resolved = true;
                        } else if now.saturating_sub(old_info.last_try) < 4 * 60 * 60 {
                            if now.saturating_sub(old_info.last_try) > 60 {
                                self.mark_good_(&peer, false, now, rng);
                                resolved = true;
                            }
                        } else if now.saturating_sub(info.last_success) > 40 * 60 {
                            self.mark_good_(&peer, false, now, rng);
                            resolved = true;
                        } else {
                            self.mark_good_(&peer, false, now, rng);
                            resolved = true;
                        }
                    }
                }
            }
            if resolved {
                self.tried_collisions.retain(|&x| x != node_id);
            }
        }
    }

    fn select_tried_collision_(&mut self) -> Option<ExtendedPeerInfo> {
        self.tried_collisions
            .retain(|id| self.map_info.contains_key(id));
        if self.tried_collisions.is_empty() {
            return None;
        }
        let mut rng = rand::thread_rng();
        let new_id = *self
            .tried_collisions
            .get(rng.gen_range(0..self.tried_collisions.len()))?;
        if !self.map_info.contains_key(&new_id) {
            return None;
        }
        let new_info = self.map_info.get(&new_id)?;
        let tried_bucket = new_info.tried_bucket_index(&self.key);
        let tried_bucket_pos = new_info.bucket_position(&self.key, false, tried_bucket);
        let old_id = self.tried_matrix[tried_bucket][tried_bucket_pos];
        if old_id == EMPTY {
            return None;
        }
        self.map_info.get(&(old_id as NodeId)).cloned()
    }

    /// Recompute [`Inner::used_new_matrix_positions`] / [`Inner::used_tried_matrix_positions`] from matrices.
    fn rebuild_used_positions(&mut self) {
        self.used_new_matrix_positions.clear();
        self.used_tried_matrix_positions.clear();
        for bucket in 0..NEW_BUCKET_COUNT {
            for pos in 0..BUCKET_SIZE {
                if self.new_matrix[bucket][pos] != EMPTY {
                    self.used_new_matrix_positions.insert((bucket, pos));
                }
            }
        }
        for bucket in 0..TRIED_BUCKET_COUNT {
            for pos in 0..BUCKET_SIZE {
                if self.tried_matrix[bucket][pos] != EMPTY {
                    self.used_tried_matrix_positions.insert((bucket, pos));
                }
            }
        }
    }

    fn to_address_manager_state(&self) -> AddressManagerState {
        let mut pairs: Vec<(NodeId, ExtendedPeerInfo)> =
            self.map_info.iter().map(|(&k, v)| (k, v.clone())).collect();
        pairs.sort_by_key(|(k, _)| *k);
        let node_ids: Vec<NodeId> = pairs.iter().map(|(k, _)| *k).collect();
        let entries: Vec<ExtendedPeerInfo> = pairs.iter().map(|(_, v)| v.clone()).collect();
        let id_to_idx: HashMap<NodeId, usize> = node_ids
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, i))
            .collect();
        let idx = |nid: NodeId| -> usize { *id_to_idx.get(&nid).expect("snapshot node id") };

        let mut tried_table = vec![vec![None; BUCKET_SIZE]; TRIED_BUCKET_COUNT];
        for b in 0..TRIED_BUCKET_COUNT {
            for p in 0..BUCKET_SIZE {
                let c = self.tried_matrix[b][p];
                if c != EMPTY {
                    tried_table[b][p] = Some(idx(c as NodeId));
                }
            }
        }
        let mut new_table = vec![vec![None; BUCKET_SIZE]; NEW_BUCKET_COUNT];
        for b in 0..NEW_BUCKET_COUNT {
            for p in 0..BUCKET_SIZE {
                let c = self.new_matrix[b][p];
                if c != EMPTY {
                    new_table[b][p] = Some(idx(c as NodeId));
                }
            }
        }
        let random_pos: Vec<usize> = self.random_pos.iter().map(|&nid| idx(nid)).collect();
        let tried_collision_indices: Vec<usize> =
            self.tried_collisions.iter().map(|&nid| idx(nid)).collect();

        AddressManagerState {
            version: ADDRESS_MANAGER_STATE_VERSION,
            key: self.key,
            node_ids,
            entries,
            tried_table,
            new_table,
            random_pos,
            last_good: self.last_good,
            tried_collision_indices,
            allow_private_subnets: self.allow_private_subnets,
            id_count: self.id_count,
            tried_count: self.tried_count,
            new_count: self.new_count,
        }
    }

    fn from_address_manager_state(
        state: AddressManagerState,
        peers_file_path: PathBuf,
    ) -> Result<Self, GossipError> {
        AddressManagerStore::validate_snapshot(&state)?;
        let mut inner = Inner::new(state.key, peers_file_path);
        inner.allow_private_subnets = state.allow_private_subnets;
        inner.last_good = state.last_good;
        inner.id_count = state.id_count;
        inner.tried_count = state.tried_count;
        inner.new_count = state.new_count;

        if state.entries.is_empty() {
            inner.rebuild_used_positions();
            return Ok(inner);
        }

        for i in 0..state.entries.len() {
            let nid = state.node_ids[i];
            let info = state.entries[i].clone();
            inner.map_addr.insert(info.peer_info.host.clone(), nid);
            inner.map_info.insert(nid, info);
        }

        for b in 0..TRIED_BUCKET_COUNT {
            for p in 0..BUCKET_SIZE {
                inner.tried_matrix[b][p] = match state.tried_table[b][p] {
                    None => EMPTY,
                    Some(ix) => state.node_ids[ix] as i32,
                };
            }
        }
        for b in 0..NEW_BUCKET_COUNT {
            for p in 0..BUCKET_SIZE {
                inner.new_matrix[b][p] = match state.new_table[b][p] {
                    None => EMPTY,
                    Some(ix) => state.node_ids[ix] as i32,
                };
            }
        }

        inner.random_pos = state
            .random_pos
            .iter()
            .map(|&ix| state.node_ids[ix])
            .collect();
        inner.tried_collisions = state
            .tried_collision_indices
            .iter()
            .map(|&ix| state.node_ids[ix])
            .collect();

        for (pos, &nid) in inner.random_pos.iter().enumerate() {
            if let Some(info) = inner.map_info.get_mut(&nid) {
                info.random_pos = Some(pos);
            }
        }

        inner.rebuild_used_positions();
        Ok(inner)
    }
}

/// Port of Chia `address_manager.py` / Bitcoin `CAddrMan` — DSC-001.
pub struct AddressManager {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for AddressManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddressManager").finish_non_exhaustive()
    }
}

impl Default for AddressManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressManager {
    fn new_inner_random_key(peers_file_path: PathBuf) -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self {
            inner: Mutex::new(Inner::new(key, peers_file_path)),
        }
    }

    /// Empty manager with a random 256-bit key (Chia `randbits(256)`).
    ///
    /// **DSC-002:** Uses an empty [`PathBuf`] peers path — [`Self::save`] becomes a no-op until a
    /// path is supplied via [`Self::create`].
    pub fn new() -> Self {
        Self::new_inner_random_key(PathBuf::new())
    }

    /// Construct from disk when `peers_file_path` exists and is non-empty; otherwise fresh tables.
    ///
    /// **DSC-002:** Delegates to [`AddressManagerStore::load_blocking`]. Corrupt snapshots return
    /// [`GossipError::AddressManagerStore`]; callers may map that to a fresh manager if desired.
    /// An **empty** path string skips disk I/O (same as [`Self::new`]).
    pub fn create(peers_file_path: &Path) -> Result<Self, GossipError> {
        let path = peers_file_path.to_path_buf();
        if path.as_os_str().is_empty() {
            return Ok(Self::new_inner_random_key(path));
        }
        let inner = if !path.exists() {
            Self::fresh_inner(path)
        } else {
            let meta = std::fs::metadata(&path).map_err(|e| GossipError::IoError(e.to_string()))?;
            if meta.len() == 0 {
                Self::fresh_inner(path)
            } else {
                match AddressManagerStore::load_blocking(&path)? {
                    Some(state) => Inner::from_address_manager_state(state, path)?,
                    None => Self::fresh_inner(path),
                }
            }
        };
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    fn fresh_inner(peers_file_path: PathBuf) -> Inner {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Inner::new(key, peers_file_path)
    }

    /// Serialize current tables to [`Inner::peers_file_path`] (DSC-002).
    ///
    /// No-op when the path is empty (in-memory-only managers from [`Self::new`]).
    pub async fn save(&self) -> Result<(), GossipError> {
        let (state, path) = {
            let g = self.inner.lock().expect("address_manager mutex poisoned");
            if g.peers_file_path.as_os_str().is_empty() {
                return Ok(());
            }
            (g.to_address_manager_state(), g.peers_file_path.clone())
        };
        AddressManagerStore::save(&state, &path).await
    }

    /// Blocking save for tests and non-async call sites.
    pub fn save_blocking(&self) -> Result<(), GossipError> {
        let (state, path) = {
            let g = self.inner.lock().expect("address_manager mutex poisoned");
            if g.peers_file_path.as_os_str().is_empty() {
                return Ok(());
            }
            (g.to_address_manager_state(), g.peers_file_path.clone())
        };
        AddressManagerStore::save_blocking(&state, &path)
    }

    /// Allow RFC1918 / loopback-style private addresses in tables (Chia `make_private_subnets_valid`).
    pub fn set_allow_private_subnets(&self, allow: bool) {
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        g.allow_private_subnets = allow;
    }

    /// Path passed to [`Self::create`] for upcoming persistence ([`super::address_manager_store`] / DSC-002).
    pub fn peers_file_path(&self) -> PathBuf {
        self.inner
            .lock()
            .expect("address_manager mutex poisoned")
            .peers_file_path
            .clone()
    }

    /// Total distinct tracked nodes (Chia `size` → `len(random_pos)`).
    pub fn size(&self) -> usize {
        let g = self.inner.lock().expect("address_manager mutex poisoned");
        g.random_pos.len()
    }

    /// Merge gossiped timestamps into the **new** table (Chia `add_to_new_table`).
    ///
    /// `penalty` delays re-use by subtracting from the stored timestamp (Chia `penalty` int).
    /// **Call sites:** third parameter is `u64` (was stub `u32` — widened for DSC-001).
    pub fn add_to_new_table(
        &self,
        peer_list: &[TimestampedPeerInfo],
        src: &PeerInfo,
        penalty: u64,
    ) {
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        g.new_table_log.push((peer_list.to_vec(), src.clone()));
        let mut rng = rand::thread_rng();
        for addr in peer_list {
            let _ = g.add_to_new_table_(addr, src, penalty, &mut rng);
        }
    }

    /// Promote a peer to **tried** after a verified successful connection (Chia `mark_good`).
    pub fn mark_good(&self, addr: &PeerInfo) {
        let ts = metric_unix_timestamp_secs();
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        let mut rng = rand::thread_rng();
        g.mark_good_(addr, true, ts, &mut rng);
    }

    /// [`Self::mark_good`] with explicit clock and collision policy — for unit tests.
    #[doc(hidden)]
    pub fn mark_good_at(&self, addr: &PeerInfo, test_before_evict: bool, timestamp: u64) {
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        let mut rng = rand::thread_rng();
        g.mark_good_(addr, test_before_evict, timestamp, &mut rng);
    }

    /// Record dial outcome (Chia `attempt`).
    pub fn attempt(&self, addr: &PeerInfo, count_failure: bool) {
        let ts = metric_unix_timestamp_secs();
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        g.attempt_(addr, count_failure, ts);
    }

    #[doc(hidden)]
    pub fn attempt_at(&self, addr: &PeerInfo, count_failure: bool, timestamp: u64) {
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        g.attempt_(addr, count_failure, timestamp);
    }

    /// Successful transport connect — refreshes gossip timestamp (Chia `connect`).
    pub fn connect(&self, addr: &PeerInfo) {
        let ts = metric_unix_timestamp_secs();
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        g.connect_(addr, ts);
    }

    #[doc(hidden)]
    pub fn connect_at(&self, addr: &PeerInfo, timestamp: u64) {
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        g.connect_(addr, timestamp);
    }

    /// Random peer selection (Chia `select_peer`).
    pub fn select_peer(&self, new_only: bool) -> Option<ExtendedPeerInfo> {
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        let mut rng = rand::thread_rng();
        g.select_peer_(new_only, &mut rng)
    }

    /// Victim row occupying the tried slot a collision wants (Chia `select_tried_collision`).
    pub fn select_tried_collision(&self) -> Option<ExtendedPeerInfo> {
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        g.select_tried_collision_()
    }

    /// Drain / resolve queued tried collisions (Chia `resolve_tried_collisions`).
    pub fn resolve_tried_collisions(&self) {
        let now = metric_unix_timestamp_secs();
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        let mut rng = rand::thread_rng();
        g.resolve_tried_collisions_(now, &mut rng);
    }

    #[doc(hidden)]
    pub fn resolve_tried_collisions_at(&self, now_secs: u64) {
        let mut g = self.inner.lock().expect("address_manager mutex poisoned");
        let mut rng = rand::thread_rng();
        g.resolve_tried_collisions_(now_secs, &mut rng);
    }

    /// CON-001 / CON-002 — last [`Self::add_to_new_table`] batch.
    #[doc(hidden)]
    pub fn __last_new_table_batch_for_tests(&self) -> Option<(Vec<TimestampedPeerInfo>, PeerInfo)> {
        self.inner
            .lock()
            .expect("address_manager mutex poisoned")
            .new_table_log
            .last()
            .cloned()
    }

    /// Deterministic buckets for tests: fixed `key` and fixed RNG seed for stochastic add path.
    #[doc(hidden)]
    pub fn __with_key_and_seed_for_tests(key: [u8; 32], _seed: u64) -> Self {
        Self {
            inner: Mutex::new(Inner::new(key, PathBuf::from("__test__"))),
        }
    }

    #[doc(hidden)]
    pub fn __key_for_tests(&self) -> [u8; 32] {
        self.inner.lock().expect("poisoned").key
    }

    #[doc(hidden)]
    pub fn __new_slot_for_tests(&self, peer: &PeerInfo, src: &PeerInfo) -> (usize, usize) {
        let g = self.inner.lock().expect("poisoned");
        let row = ExtendedPeerInfo {
            peer_info: peer.clone(),
            timestamp: 0,
            src: src.clone(),
            random_pos: None,
            is_tried: false,
            ref_count: 0,
            last_success: 0,
            last_try: 0,
            num_attempts: 0,
            last_count_attempt: 0,
        };
        let b = row.new_bucket_index(&g.key, src);
        let p = row.bucket_position(&g.key, true, b);
        (b, p)
    }

    #[doc(hidden)]
    pub fn __tried_slot_for_tests(&self, peer: &PeerInfo) -> (usize, usize) {
        let g = self.inner.lock().expect("poisoned");
        let row = ExtendedPeerInfo {
            peer_info: peer.clone(),
            timestamp: 1,
            src: peer.clone(),
            random_pos: None,
            is_tried: false,
            ref_count: 0,
            last_success: 0,
            last_try: 0,
            num_attempts: 0,
            last_count_attempt: 0,
        };
        let b = row.tried_bucket_index(&g.key);
        let p = row.bucket_position(&g.key, false, b);
        (b, p)
    }

    #[doc(hidden)]
    pub fn __set_last_good_for_tests(&self, v: u64) {
        let mut g = self.inner.lock().expect("poisoned");
        g.last_good = v;
    }

    /// DSC-002 / tests — bincode snapshot of the live [`Inner`].
    #[doc(hidden)]
    pub fn __snapshot_for_tests(&self) -> AddressManagerState {
        self.inner
            .lock()
            .expect("poisoned")
            .to_address_manager_state()
    }

    /// Snapshot row by **host** key (Chia `map_addr` is host-only).
    #[doc(hidden)]
    pub fn __row_by_host_for_tests(&self, host: &str) -> Option<ExtendedPeerInfo> {
        let g = self.inner.lock().expect("poisoned");
        let id = g.map_addr.get(host).copied()?;
        g.map_info.get(&id).cloned()
    }
}
