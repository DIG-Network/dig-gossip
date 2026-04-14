//! Integration tests for **STR-004: Feature flags** (`Cargo.toml` + `#[cfg(feature = …)]` wiring).
//!
//! ## Traceability
//!
//! - **Normative:** [`NORMATIVE.md`](../docs/requirements/domains/crate_structure/NORMATIVE.md) — STR-004
//! - **Detailed spec + test plan:** [`specs/STR-004.md`](../docs/requirements/domains/crate_structure/specs/STR-004.md)
//! - **Master spec:** [`SPEC.md`](../docs/resources/SPEC.md) Section 10.3
//!
//! ## What this proves
//!
//! 1. **Manifest contract** — Parsed `Cargo.toml` lists every STR-004 / NORMATIVE feature with the
//!    expected dependency forwarding (`native-tls` → `chia-sdk-client`, `tor` → optional crates).
//!    Default features match production shape: TLS + relay + erlay + compact-blocks + dandelion
//!    (Tor stays opt-in per NORMATIVE).
//! 2. **Deviation documentation** — `erlay` does not list `minisketch-rs` because that crate cannot
//!    coexist in the resolver graph with `chia-sdk-client`’s optional rustls/bindgen chain (STR-001).
//!    The **feature name** still gates `gossip/erlay.rs`; this test encodes that policy.
//! 3. **`compact-blocks` wiring** — Uses Cargo 2.x style `dep:siphasher` (equivalent to legacy
//!    optional-dep activation).
//! 4. **Compile-matrix contract** — Shell `cargo check` invocations prove minimal TLS-only graphs,
//!    rustls-only, per-feature toggles, `tor`, and `--all-features` all resolve on CI.
//! 5. **Source-level cfg anchors** — `src/lib.rs`, `src/gossip/mod.rs`, and `src/privacy/mod.rs`
//!    contain the `#[cfg(feature = …)]` patterns STR-004 calls out so optional code is not pulled
//!    into unrelated builds.
//!
//! ## `start.md` tooling notes
//!
//! **GitNexus** / **SocratiCode** may be unavailable in some environments; this file uses only
//! `cargo` + filesystem inspection so verification stays reproducible.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use toml::Value;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_cargo_toml() -> Value {
    let path = workspace_root().join("Cargo.toml");
    let raw = fs::read_to_string(&path).expect("read Cargo.toml");
    raw.parse().expect("parse Cargo.toml")
}

fn features_table(manifest: &Value) -> &toml::value::Table {
    manifest
        .get("features")
        .and_then(Value::as_table)
        .expect("[features]")
}

fn dependencies_table(manifest: &Value) -> &toml::value::Table {
    manifest
        .get("dependencies")
        .and_then(Value::as_table)
        .expect("[dependencies]")
}

fn assert_cargo_check(args: &[&str]) {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root());
    cmd.arg("check");
    cmd.args(args);
    let out = cmd.output().expect("spawn cargo check");
    assert!(
        out.status.success(),
        "cargo check {:?} failed:\n{}\n{}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn read_source(rel: &str) -> String {
    fs::read_to_string(workspace_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

// ---- Manifest-driven tests (STR-004 acceptance) ----

#[test]
fn test_feature_native_tls_forwards_to_chia_sdk_client() {
    let m = load_cargo_toml();
    let feats = features_table(&m);
    let v = feats
        .get("native-tls")
        .and_then(Value::as_array)
        .expect("native-tls feature");
    let e: Vec<&str> = v.iter().filter_map(Value::as_str).collect();
    assert!(
        e.contains(&"chia-sdk-client/native-tls"),
        "native-tls must forward, got {e:?}"
    );
}

#[test]
fn test_feature_rustls_forwards_to_chia_sdk_client() {
    let m = load_cargo_toml();
    let feats = features_table(&m);
    let v = feats
        .get("rustls")
        .and_then(Value::as_array)
        .expect("rustls feature");
    let e: Vec<&str> = v.iter().filter_map(Value::as_str).collect();
    assert!(
        e.contains(&"chia-sdk-client/rustls"),
        "rustls must forward, got {e:?}"
    );
}

#[test]
fn test_feature_relay_has_no_extra_deps() {
    let m = load_cargo_toml();
    let feats = features_table(&m);
    let v = feats.get("relay").and_then(Value::as_array).expect("relay");
    assert!(v.is_empty(), "relay must be empty feature list, got {v:?}");
}

#[test]
fn test_feature_dandelion_has_no_extra_deps() {
    let m = load_cargo_toml();
    let feats = features_table(&m);
    let v = feats
        .get("dandelion")
        .and_then(Value::as_array)
        .expect("dandelion");
    assert!(
        v.is_empty(),
        "dandelion must add no deps at manifest level, got {v:?}"
    );
}

#[test]
fn test_feature_erlay_is_cfg_gate_without_minisketch() {
    let m = load_cargo_toml();
    let feats = features_table(&m);
    let v = feats.get("erlay").and_then(Value::as_array).expect("erlay");
    assert!(
        v.is_empty(),
        "erlay must not pull minisketch-rs (Cargo links clash); use empty feature, got {v:?}"
    );
    let deps = dependencies_table(&m);
    assert!(
        !deps.contains_key("minisketch-rs"),
        "minisketch-rs must stay absent from [dependencies]"
    );
}

#[test]
fn test_feature_compact_blocks_enables_siphasher() {
    let m = load_cargo_toml();
    let feats = features_table(&m);
    let v = feats
        .get("compact-blocks")
        .and_then(Value::as_array)
        .expect("compact-blocks");
    let e: Vec<&str> = v.iter().filter_map(Value::as_str).collect();
    assert!(
        e.contains(&"dep:siphasher") || e.contains(&"siphasher"),
        "compact-blocks must enable siphasher, got {e:?}"
    );
    let deps = dependencies_table(&m);
    let sip = deps.get("siphasher").expect("siphasher dep");
    let opt = sip
        .as_table()
        .and_then(|t| t.get("optional").and_then(Value::as_bool));
    assert_eq!(opt, Some(true));
}

#[test]
fn test_feature_tor_enables_arti_and_tokio_socks() {
    let m = load_cargo_toml();
    let feats = features_table(&m);
    let v = feats.get("tor").and_then(Value::as_array).expect("tor");
    let e: Vec<&str> = v.iter().filter_map(Value::as_str).collect();
    assert!(
        e.contains(&"dep:arti-client") && e.contains(&"dep:tokio-socks"),
        "tor must enable both deps, got {e:?}"
    );
    let deps = dependencies_table(&m);
    for name in ["arti-client", "tokio-socks"] {
        let d = deps.get(name).expect(name);
        let t = d.as_table().expect("inline dep");
        assert_eq!(
            t.get("optional").and_then(Value::as_bool),
            Some(true),
            "{name} must be optional"
        );
    }
}

#[test]
fn test_default_features_match_normative() {
    let m = load_cargo_toml();
    let feats = features_table(&m);
    let def = feats
        .get("default")
        .and_then(Value::as_array)
        .expect("default");
    let e: Vec<&str> = def.iter().filter_map(Value::as_str).collect();
    for req in [
        "native-tls",
        "relay",
        "erlay",
        "compact-blocks",
        "dandelion",
    ] {
        assert!(e.contains(&req), "default must include {req}, got {e:?}");
    }
    assert!(
        !e.contains(&"tor"),
        "tor must NOT be in default (opt-in only), got {e:?}"
    );
}

// ---- Source cfg anchors ----

#[test]
fn test_lib_rs_cfg_gates_relay_privacy() {
    let lib = read_source("src/lib.rs");
    assert!(
        lib.contains("#[cfg(feature = \"relay\")]") && lib.contains("pub mod relay;"),
        "lib.rs must cfg-gate relay"
    );
    assert!(
        lib.contains("#[cfg(any(feature = \"dandelion\", feature = \"tor\"))]")
            && lib.contains("pub mod privacy;"),
        "lib.rs must cfg-gate privacy on dandelion OR tor"
    );
}

#[test]
fn test_gossip_mod_rs_cfg_gates_submodules() {
    let g = read_source("src/gossip/mod.rs");
    assert!(
        g.contains("#[cfg(feature = \"compact-blocks\")]") && g.contains("pub mod compact_block;")
    );
    assert!(g.contains("#[cfg(feature = \"erlay\")]") && g.contains("pub mod erlay;"));
}

#[test]
fn test_privacy_mod_rs_cfg_gates_submodules() {
    let p = read_source("src/privacy/mod.rs");
    assert!(
        p.contains("#[cfg(feature = \"dandelion\")]") && p.contains("pub mod dandelion;"),
        "privacy/mod.rs must gate dandelion"
    );
    assert!(
        p.contains("#[cfg(feature = \"tor\")]") && p.contains("pub mod tor;"),
        "privacy/mod.rs must gate tor"
    );
}

// ---- Cargo check matrix (integration) ----

#[test]
fn test_check_default_features() {
    assert_cargo_check(&[]);
}

#[test]
fn test_check_native_tls_only_minimal_graph() {
    assert_cargo_check(&["--no-default-features", "--features", "native-tls"]);
}

#[test]
fn test_check_rustls_only_minimal_graph() {
    assert_cargo_check(&["--no-default-features", "--features", "rustls"]);
}

/// TLS + relay without relying on `default` (explicit subgraph).
#[test]
fn test_check_native_tls_and_relay() {
    assert_cargo_check(&["--no-default-features", "--features", "native-tls,relay"]);
}

#[test]
fn test_check_native_tls_erlay() {
    assert_cargo_check(&["--no-default-features", "--features", "native-tls,erlay"]);
}

#[test]
fn test_check_native_tls_compact_blocks() {
    assert_cargo_check(&[
        "--no-default-features",
        "--features",
        "native-tls,compact-blocks",
    ]);
}

#[test]
fn test_check_native_tls_dandelion() {
    assert_cargo_check(&[
        "--no-default-features",
        "--features",
        "native-tls,dandelion",
    ]);
}

#[test]
fn test_check_native_tls_tor() {
    assert_cargo_check(&["--no-default-features", "--features", "native-tls,tor"]);
}

#[test]
fn test_check_all_features() {
    assert_cargo_check(&["--all-features"]);
}

// ---- Optional symbol smoke (proves gated re-exports resolve when features on) ----

#[cfg(feature = "relay")]
#[test]
fn smoke_relay_types_at_root_when_feature_on() {
    let _ = std::marker::PhantomData::<dig_gossip::RelayMessage>;
}

#[cfg(feature = "tor")]
#[test]
fn smoke_tor_transport_config_at_root() {
    let _ = std::marker::PhantomData::<dig_gossip::TorTransportConfig>;
}

#[cfg(all(feature = "dandelion", not(feature = "tor")))]
#[test]
fn smoke_dandelion_without_tor_module_still_compiles() {
    let _ = std::marker::PhantomData::<dig_gossip::StemTransaction>;
}
