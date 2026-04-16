//! **DSC-002 — Address manager persistence (peers file)**
//!
//! Normative: [`docs/requirements/domains/discovery/specs/DSC-002.md`](../docs/requirements/domains/discovery/specs/DSC-002.md),
//! [`NORMATIVE.md`](../docs/requirements/domains/discovery/NORMATIVE.md).
//!
//! ## What this file proves
//!
//! The acceptance matrix in DSC-002 requires bincode snapshots, a `version == 1` header,
//! atomic replace writes, `load` semantics (`None` vs `Err`), and [`AddressManager::create`]
//! restoring state when a non-empty peers file already exists on disk.
//!
//! ## Causal chain (examples)
//!
//! - `test_save_creates_file` → [`AddressManagerStore::save_blocking`] materializes bytes on disk;
//!   if save were a no-op, discovery restarts would lose all peer knowledge (violates SPEC §6.3 intent).
//! - `test_load_corrupted` → garbage bytes must surface [`dig_gossip::GossipError::AddressManagerStore`]
//!   so operators/tests can distinguish “missing file” from “damaged file”.
//! - `test_create_loads_existing` → [`AddressManager::create`] must hydrate [`AddressManager`] from disk
//!   before any gossip traffic; otherwise `peers_file_path` in [`dig_gossip::GossipConfig`] would be meaningless.

use dig_gossip::{
    AddressManager, AddressManagerState, AddressManagerStore, GossipError, PeerInfo,
    TimestampedPeerInfo, ADDRESS_MANAGER_STATE_VERSION, BUCKET_SIZE, NEW_BUCKET_COUNT,
    TRIED_BUCKET_COUNT,
};

fn empty_snapshot(key: [u8; 32]) -> AddressManagerState {
    AddressManagerState {
        version: ADDRESS_MANAGER_STATE_VERSION,
        key,
        node_ids: vec![],
        entries: vec![],
        tried_table: vec![vec![None; BUCKET_SIZE]; TRIED_BUCKET_COUNT],
        new_table: vec![vec![None; BUCKET_SIZE]; NEW_BUCKET_COUNT],
        random_pos: vec![],
        last_good: 1,
        tried_collision_indices: vec![],
        allow_private_subnets: false,
        id_count: 0,
        tried_count: 0,
        new_count: 0,
    }
}

/// **Row:** `test_save_creates_file` — save writes a real file at the target path.
#[test]
fn test_save_creates_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("peers_save.bin");
    let key = [3u8; 32];
    let state = empty_snapshot(key);
    AddressManagerStore::save_blocking(&state, &path).expect("save");
    assert!(path.exists(), "save must create the destination file");
    assert!(path.metadata().expect("meta").len() > 0);
}

/// **Row:** `test_load_nonexistent` — missing path yields `Ok(None)`.
#[tokio::test]
async fn test_load_nonexistent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nope_does_not_exist.bin");
    let got = AddressManagerStore::load(&path).await.expect("load");
    assert!(got.is_none());
}

/// **Row:** `test_load_corrupted` — invalid bincode returns `Err`.
#[tokio::test]
async fn test_load_corrupted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("corrupt.bin");
    std::fs::write(&path, b"not-bincode").expect("write garbage");
    let err = AddressManagerStore::load(&path)
        .await
        .expect_err("corrupt file must error");
    match err {
        GossipError::AddressManagerStore(msg) => {
            assert!(
                msg.contains("bincode") || msg.contains("deserialize"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected AddressManagerStore error, got {other:?}"),
    }
}

/// **Row:** `test_round_trip_empty` — serialize/deserialize empty snapshot.
#[test]
fn test_round_trip_empty() {
    let key = [5u8; 32];
    let a = empty_snapshot(key);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("empty_rt.bin");
    AddressManagerStore::save_blocking(&a, &path).expect("save");
    let b = AddressManagerStore::load_blocking(&path)
        .expect("load result")
        .expect("some");
    assert_eq!(a, b);
}

/// **Row:** `test_round_trip_populated` — manager round-trips through store snapshot.
#[test]
fn test_round_trip_populated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("populated.bin");
    let am = AddressManager::create(&path).expect("create");
    let src = PeerInfo {
        host: "198.51.100.55".into(),
        port: 9444,
    };
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(
            "198.51.100.66".into(),
            9555,
            1_800_000_000,
        )][..],
        &src,
        0,
    );
    am.save_blocking().expect("save");
    let s1 = am.__snapshot_for_tests();
    let loaded = AddressManagerStore::load_blocking(&path)
        .expect("load")
        .expect("some");
    assert_eq!(s1, loaded);
    let am2 = AddressManager::create(&path).expect("reload manager");
    assert_eq!(am2.__key_for_tests(), s1.key);
    assert_eq!(am2.size(), am.size());
}

/// **Row:** `test_atomic_write` — final path exists and no `.tmp` sibling remains after successful save.
#[test]
fn test_atomic_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("atomic.peers");
    let state = empty_snapshot([8u8; 32]);
    AddressManagerStore::save_blocking(&state, &path).expect("save");
    let tmp = path.with_extension("tmp");
    assert!(
        !tmp.exists(),
        "temp file {tmp:?} should be renamed away after successful save"
    );
}

/// **Row:** `test_version_field` — persisted blob carries `version == 1`.
#[test]
fn test_version_field() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("version.bin");
    let state = empty_snapshot([1u8; 32]);
    AddressManagerStore::save_blocking(&state, &path).expect("save");
    let round = AddressManagerStore::load_blocking(&path)
        .expect("load")
        .expect("some");
    assert_eq!(round.version, 1);
}

/// **Row:** `test_version_mismatch` — unsupported future version fails validation after deserialize.
#[test]
fn test_version_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("future.bin");
    let mut bad = empty_snapshot([2u8; 32]);
    bad.version = 99;
    let bytes = bincode::serialize(&bad).expect("serialize");
    std::fs::write(&path, bytes).expect("write");
    let err = AddressManagerStore::load_blocking(&path).expect_err("must reject");
    assert!(matches!(err, GossipError::AddressManagerStore(_)));
}

/// **Row:** `test_create_loads_existing` — second `create` on same path sees prior snapshot.
#[test]
fn test_create_loads_existing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reuse.peers");
    let am1 = AddressManager::create(&path).expect("create");
    let k = am1.__key_for_tests();
    let src = PeerInfo {
        host: "198.51.100.1".into(),
        port: 9444,
    };
    am1.add_to_new_table(
        &[TimestampedPeerInfo::new(
            "198.51.100.2".into(),
            9445,
            1_700_000_000,
        )][..],
        &src,
        0,
    );
    am1.save_blocking().expect("persist");
    let am2 = AddressManager::create(&path).expect("second create");
    assert_eq!(am2.__key_for_tests(), k, "secret key must round-trip");
    assert_eq!(am2.size(), 1);
}

/// **Row:** `test_create_fresh_no_file` — absent file yields empty manager (size 0).
#[test]
fn test_create_fresh_no_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fresh_missing.peers");
    assert!(!path.exists());
    let am = AddressManager::create(&path).expect("create");
    assert_eq!(am.size(), 0);
}

/// **Row:** `test_save_async_round_trip` — async API mirrors blocking semantics.
#[tokio::test]
async fn test_save_async_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("async.peers");
    let am = AddressManager::create(&path).expect("create");
    let src = PeerInfo {
        host: "198.51.100.3".into(),
        port: 9444,
    };
    am.add_to_new_table(
        &[TimestampedPeerInfo::new(
            "198.51.100.4".into(),
            9445,
            1_700_000_001,
        )][..],
        &src,
        0,
    );
    am.save().await.expect("async save");
    let got = AddressManagerStore::load(&path).await.expect("async load");
    assert!(got.is_some());
}
