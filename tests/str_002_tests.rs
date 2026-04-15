//! Integration tests for **STR-002: Module hierarchy** (crate layout under `src/`).
//!
//! ## Traceability
//!
//! - **Normative:** [`docs/requirements/domains/crate_structure/NORMATIVE.md`](../../docs/requirements/domains/crate_structure/NORMATIVE.md) — STR-002
//! - **Detailed spec + acceptance + test plan:**
//!   [`docs/requirements/domains/crate_structure/specs/STR-002.md`](../../docs/requirements/domains/crate_structure/specs/STR-002.md)
//! - **Architectural diagram (authoritative tree, includes `privacy/` not in STR-002 checklist):**
//!   [`docs/resources/SPEC.md`](../../docs/resources/SPEC.md) — Section 10.1 (Module Structure)
//!
//! ## What this proves
//!
//! STR-002 requires a **stable, reviewable file layout** so contributors know where
//! discovery, gossip, relay, and shared types live before behavior lands in later
//! requirements (API-*, CON-*, DSC-*, etc.). These tests:
//!
//! 1. **Filesystem contract** — every path listed in STR-002 acceptance exists. That
//!    directly maps to the checklist bullets (“`src/types/peer.rs` exists”, …).
//! 2. **`mod.rs` wiring contract** — each directory’s `mod.rs` declares the expected
//!    `pub mod …` children. That proves the tree is not only a pile of files but a
//!    valid Rust module hierarchy matching the spec’s responsibility split.
//! 3. **`lib.rs` contract** — the crate root exposes the top-level modules STR-002
//!    calls for (`types`, `service`, `discovery`, …), with **feature gates** exactly
//!    where STR-002 implementation notes demand (`relay`, `compact-blocks`, `erlay`).
//! 4. **Compilation contract** — `cargo check` succeeds for **default features**
//!    (full tree compiled) and for **TLS-only minimal graphs** (`--no-default-features
//!    --features rustls`) so cfg-split modules do not leave dangling references.
//!
//! ## How failures should be interpreted
//!
//! A missing file means the repo no longer matches the agreed architecture — fix the
//! path or update requirements **intentionally** with tracking docs, not silently.
//! A missing `pub mod` usually means `cargo check` would fail or submodules would be
//! unreachable from their parent.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Package root (`dig-gossip/`), where `Cargo.toml` and `src/` live.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Fail fast with a clear message if a required path is missing.
fn assert_path_exists(rel: &str) {
    let p = workspace_root().join(rel);
    assert!(
        p.exists(),
        "STR-002 requires this path to exist: {} (resolved to {})",
        rel,
        p.display()
    );
}

/// Read a UTF-8 source file relative to the workspace root.
fn read_source(rel: &str) -> String {
    let p = workspace_root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// `mod.rs` must expose each listed submodule with a `pub mod name;` declaration.
///
/// We match on lines (after trimming) so inline attributes like
/// `#[cfg(feature = "erlay")]` on the previous line still allow the following
/// `pub mod erlay;` to satisfy the contract.
fn assert_mod_rs_declares_pub_children(mod_rs_rel: &str, children: &[&str]) {
    let src = read_source(mod_rs_rel);
    let lines: Vec<String> = src.lines().map(|l| l.trim().to_string()).collect();
    for child in children {
        let needle = format!("pub mod {child};");
        let ok = lines.iter().any(|line| line == &needle);
        assert!(
            ok,
            "{mod_rs_rel} must declare `{needle}` (STR-002 submodule wiring).\nFile:\n{src}"
        );
    }
}

/// `lib.rs` should contain this exact module declaration line (feature gates may
/// appear immediately above — we only require the `pub mod` line to be present).
fn assert_lib_rs_contains_pub_mod(name: &str) {
    let lib = read_source("src/lib.rs");
    let needle = format!("pub mod {name};");
    assert!(
        lib.lines().any(|l| l.trim() == needle),
        "src/lib.rs must declare `{needle}`.\n---\n{lib}\n---"
    );
}

fn assert_cargo_check(extra: &[&str]) {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root());
    cmd.arg("check");
    cmd.args(extra);
    let out = cmd.output().expect("spawn cargo check");
    assert!(
        out.status.success(),
        "cargo check {:?} failed\nstdout:\n{}\nstderr:\n{}",
        extra,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// **Acceptance:** `src/lib.rs` exists -- the crate root is the first file STR-002 mandates.
///
/// Without it, nothing else in the module hierarchy can compile.
#[test]
fn test_lib_rs_exists() {
    assert_path_exists("src/lib.rs");
}

/// **Acceptance:** `src/types/` contains all STR-002 required files AND `mod.rs` declares
/// each as `pub mod`.
///
/// Types module holds shared data structures (peer, config, stats, reputation, dig_messages)
/// that are re-exported via STR-003 at the crate root. Missing files here mean broken
/// re-exports downstream.
#[test]
fn test_types_module_structure() {
    for f in [
        "src/types/mod.rs",
        "src/types/peer.rs",
        "src/types/config.rs",
        "src/types/stats.rs",
        "src/types/reputation.rs",
        "src/types/dig_messages.rs",
    ] {
        assert_path_exists(f);
    }
    assert_mod_rs_declares_pub_children(
        "src/types/mod.rs",
        &["peer", "config", "stats", "reputation", "dig_messages"],
    );
}

/// **Acceptance:** `src/constants.rs` exists -- holds crate-wide numeric constants
/// (ports, thresholds, timeouts) referenced by API-003, API-006, CON-004, etc.
#[test]
fn test_constants_module_exists() {
    assert_path_exists("src/constants.rs");
}

/// **Acceptance:** `src/error.rs` exists -- the `GossipError` enum (API-004) lives here.
#[test]
fn test_error_module_exists() {
    assert_path_exists("src/error.rs");
}

/// **Acceptance:** `src/service/` contains `gossip_service.rs` and `gossip_handle.rs`,
/// wired via `mod.rs`. This is where API-001 (constructor/lifecycle) and API-002
/// (runtime handle) implementations live.
#[test]
fn test_service_module_structure() {
    for f in [
        "src/service/mod.rs",
        "src/service/gossip_service.rs",
        "src/service/gossip_handle.rs",
    ] {
        assert_path_exists(f);
    }
    assert_mod_rs_declares_pub_children("src/service/mod.rs", &["gossip_service", "gossip_handle"]);
}

/// **Acceptance:** `src/connection/` contains handshake, keepalive, inbound limits, outbound,
/// and listener submodules (CON-001..CON-005 surface area).
#[test]
fn test_connection_module_structure() {
    for f in [
        "src/connection/mod.rs",
        "src/connection/handshake.rs",
        "src/connection/inbound_limits.rs",
        "src/connection/keepalive.rs",
        "src/connection/outbound.rs",
        "src/connection/listener.rs",
    ] {
        assert_path_exists(f);
    }
    assert_mod_rs_declares_pub_children(
        "src/connection/mod.rs",
        &["handshake", "inbound_limits", "keepalive", "listener", "outbound"],
    );
}

/// **Acceptance:** `src/discovery/` contains the address manager, its persistent store,
/// node discovery logic, introducer client, and introducer peers. These implement DSC-*
/// requirements for peer discovery and address book management.
#[test]
fn test_discovery_module_structure() {
    for f in [
        "src/discovery/mod.rs",
        "src/discovery/address_manager.rs",
        "src/discovery/address_manager_store.rs",
        "src/discovery/node_discovery.rs",
        "src/discovery/introducer_client.rs",
        "src/discovery/introducer_peers.rs",
    ] {
        assert_path_exists(f);
    }
    assert_mod_rs_declares_pub_children(
        "src/discovery/mod.rs",
        &[
            "address_manager",
            "address_manager_store",
            "node_discovery",
            "introducer_client",
            "introducer_peers",
        ],
    );
}

/// **Acceptance:** `src/relay/` contains relay client, service, and types -- all behind
/// the `relay` feature gate (STR-004). These handle relay-assisted connectivity for
/// NAT-traversal scenarios.
#[test]
fn test_relay_module_structure() {
    for f in [
        "src/relay/mod.rs",
        "src/relay/relay_client.rs",
        "src/relay/relay_service.rs",
        "src/relay/relay_types.rs",
    ] {
        assert_path_exists(f);
    }
    assert_mod_rs_declares_pub_children(
        "src/relay/mod.rs",
        &["relay_client", "relay_service", "relay_types"],
    );
}

/// **Acceptance:** `src/gossip/` contains all gossip-layer submodules: plumtree epidemic
/// broadcast, compact block relay, erlay set reconciliation, priority scheduling,
/// backpressure control, broadcaster, seen-set deduplication, and message cache.
/// Feature-gated submodules (`compact_block`, `erlay`) are verified separately in
/// `test_gossip_mod_rs_feature_gates_optional_subsystems`.
#[test]
fn test_gossip_module_structure() {
    for f in [
        "src/gossip/mod.rs",
        "src/gossip/plumtree.rs",
        "src/gossip/compact_block.rs",
        "src/gossip/erlay.rs",
        "src/gossip/priority.rs",
        "src/gossip/backpressure.rs",
        "src/gossip/broadcaster.rs",
        "src/gossip/seen_set.rs",
        "src/gossip/message_cache.rs",
    ] {
        assert_path_exists(f);
    }
    assert_mod_rs_declares_pub_children(
        "src/gossip/mod.rs",
        &[
            "plumtree",
            "compact_block",
            "erlay",
            "priority",
            "backpressure",
            "broadcaster",
            "seen_set",
            "message_cache",
        ],
    );
}

/// **Acceptance:** `src/util/` contains IP address helpers, AS-number lookup, and latency
/// measurement utilities used across the crate for peer scoring and grouping.
#[test]
fn test_util_module_structure() {
    for f in [
        "src/util/mod.rs",
        "src/util/ip_address.rs",
        "src/util/as_lookup.rs",
        "src/util/latency.rs",
    ] {
        assert_path_exists(f);
    }
    assert_mod_rs_declares_pub_children("src/util/mod.rs", &["ip_address", "as_lookup", "latency"]);
}

/// Proves `lib.rs` is the integration point STR-002 describes: it mounts each
/// top-level subsystem for the rest of the crate to use.
#[test]
fn test_lib_rs_mounts_top_level_modules() {
    for m in [
        "types",
        "constants",
        "error",
        "service",
        "connection",
        "discovery",
        "relay",
        "gossip",
        "util",
    ] {
        assert_lib_rs_contains_pub_mod(m);
    }

    let lib = read_source("src/lib.rs");
    assert!(
        lib.contains("#[cfg(feature = \"relay\")]"),
        "STR-002 notes: relay subtree should be behind `#[cfg(feature = \"relay\")]` in lib.rs"
    );
}

/// Compact blocks / ERLAY files exist on disk; `gossip/mod.rs` must gate them with
/// the same features STR-002 calls out so default-off builds skip optional code.
#[test]
fn test_gossip_mod_rs_feature_gates_optional_subsystems() {
    let m = read_source("src/gossip/mod.rs");
    assert!(
        m.contains("#[cfg(feature = \"compact-blocks\")]") && m.contains("pub mod compact_block;"),
        "gossip/mod.rs must cfg-gate `compact_block` behind feature compact-blocks"
    );
    assert!(
        m.contains("#[cfg(feature = \"erlay\")]") && m.contains("pub mod erlay;"),
        "gossip/mod.rs must cfg-gate `erlay` behind feature erlay"
    );
}

/// **Acceptance:** `cargo check` with default features compiles the full STR-002 tree.
///
/// Default features include relay + erlay + compact-blocks + dandelion, so this exercises
/// every module in the hierarchy. Failure means the layout is broken for production builds.
#[test]
fn test_module_compilation_default_features() {
    assert_cargo_check(&[]);
}

/// **Acceptance:** `cargo check` with only `rustls` (no relay/erlay/compact-blocks/dandelion).
///
/// Ensures cfg-split modules never assume optional features are always on. A failure here
/// means some module has an unconditional `use` of a feature-gated type.
#[test]
fn test_module_compilation_tls_only_minimal_features() {
    assert_cargo_check(&["--no-default-features", "--features", "rustls"]);
}
