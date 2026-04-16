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

/// Returns the crate root directory (where `Cargo.toml` lives).
///
/// Used by all helpers in this file to resolve relative paths against the workspace.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Parse `Cargo.toml` into a TOML [`Value`] tree for manifest-level assertions.
///
/// Used by: every `test_feature_*` and `test_default_*` test to inspect `[features]` and
/// `[dependencies]` tables without running `cargo metadata` (simpler, faster).
fn load_cargo_toml() -> Value {
    let path = workspace_root().join("Cargo.toml");
    let raw = fs::read_to_string(&path).expect("read Cargo.toml");
    raw.parse().expect("parse Cargo.toml")
}

/// Extract the `[features]` table from a parsed manifest.
///
/// Panics if the table is absent, which would itself be a STR-004 failure.
fn features_table(manifest: &Value) -> &toml::value::Table {
    manifest
        .get("features")
        .and_then(Value::as_table)
        .expect("[features]")
}

/// Extract the `[dependencies]` table from a parsed manifest.
///
/// Used to verify optional dependency declarations (e.g. `siphasher`, `arti-client`).
fn dependencies_table(manifest: &Value) -> &toml::value::Table {
    manifest
        .get("dependencies")
        .and_then(Value::as_table)
        .expect("[dependencies]")
}

/// Run `cargo check` with the given extra arguments and assert it succeeds.
///
/// Used by the compile-matrix tests to prove each feature combination resolves without errors.
/// Failure output includes both stdout and stderr for CI diagnostics.
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

/// Read a UTF-8 source file relative to the workspace root.
///
/// Used by cfg-anchor tests (`test_lib_rs_cfg_gates_*`, `test_gossip_mod_rs_*`,
/// `test_privacy_mod_rs_*`) to grep for `#[cfg(feature = …)]` patterns.
fn read_source(rel: &str) -> String {
    fs::read_to_string(workspace_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

// ---- Manifest-driven tests (STR-004 acceptance) ----

/// **Row:** `test_feature_native_tls_forwards_to_chia_sdk_client`
///
/// Verifies the `native-tls` feature forwards through `dig-protocol/native-tls`,
/// which in turn activates `chia-sdk-client/native-tls`. dig-protocol is the
/// single protocol dependency that wraps all chia-* crates.
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
        e.contains(&"dig-protocol/native-tls"),
        "native-tls must forward through dig-protocol, got {e:?}"
    );
}

/// **Row:** `test_feature_rustls_forwards_to_chia_sdk_client`
///
/// Verifies the `rustls` feature forwards through `dig-protocol/rustls`,
/// which in turn activates `chia-sdk-client/rustls`.
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
        e.contains(&"dig-protocol/rustls"),
        "rustls must forward through dig-protocol, got {e:?}"
    );
}

/// **Row:** `test_feature_relay_has_no_extra_deps`
///
/// The `relay` feature is a pure cfg gate with no additional dependency activations.
/// Relay logic lives entirely in `src/relay/` and only needs types already in the
/// base dependency set. An empty feature array proves no accidental dep leakage.
#[test]
fn test_feature_relay_has_no_extra_deps() {
    let m = load_cargo_toml();
    let feats = features_table(&m);
    let v = feats.get("relay").and_then(Value::as_array).expect("relay");
    assert!(v.is_empty(), "relay must be empty feature list, got {v:?}");
}

/// **Row:** `test_feature_dandelion_has_no_extra_deps`
///
/// Like `relay`, the `dandelion` feature is a pure cfg gate. Dandelion++ stem/fluff
/// logic uses only core types already present in the dependency graph. An empty
/// feature array confirms no transitive crates are pulled in.
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

/// **Row:** `test_feature_erlay_is_cfg_gate_without_minisketch`
///
/// Erlay reconciliation would ideally use `minisketch-rs`, but that crate's C
/// bindgen chain conflicts with `chia-sdk-client`'s resolver graph (STR-001
/// deviation). This test encodes the policy: the `erlay` feature MUST be empty
/// (no deps) AND `minisketch-rs` MUST NOT appear in `[dependencies]` at all.
/// The feature name still gates `src/gossip/erlay.rs` via `#[cfg]`.
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

/// **Row:** `test_feature_compact_blocks_enables_siphasher`
///
/// Compact block relay (BIP-152 style) uses SipHash for short transaction IDs.
/// The `compact-blocks` feature MUST activate `dep:siphasher` (Cargo 2.x syntax),
/// and `siphasher` itself MUST be declared as `optional = true` so it stays out
/// of the default dependency graph when compact blocks are not needed.
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

/// **Row:** `test_feature_tor_enables_arti_and_tokio_socks`
///
/// The `tor` feature MUST activate both `dep:arti-client` (Tor circuit manager)
/// and `dep:tokio-socks` (SOCKS5 proxy for outbound connections). Both crates
/// MUST be `optional = true` so they are excluded from non-Tor builds. Tor stays
/// opt-in per NORMATIVE (not in `default` features).
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

/// **Row:** `test_default_features_match_normative`
///
/// The `default` feature set MUST include `native-tls`, `relay`, `erlay`,
/// `compact-blocks`, and `dandelion` -- matching the production shape described
/// in NORMATIVE. Critically, `tor` MUST NOT be in defaults (opt-in only) because
/// it pulls heavy dependencies and has network-policy implications.
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
// These tests verify that actual `#[cfg(feature = …)]` attributes exist in source files,
// ensuring optional code is not compiled into unrelated builds.

/// **Row:** `test_lib_rs_cfg_gates_relay_privacy`
///
/// `src/lib.rs` MUST contain `#[cfg(feature = "relay")] pub mod relay;` so the entire
/// relay subtree is excluded from non-relay builds. Similarly, `privacy` MUST be gated
/// on `dandelion OR tor` since both stem routing and Tor transport live there.
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

/// **Row:** `test_gossip_mod_rs_cfg_gates_submodules`
///
/// `src/gossip/mod.rs` MUST gate `compact_block` behind `compact-blocks` and
/// `erlay` behind `erlay`. Without these gates, optional code would be compiled
/// unconditionally, defeating the purpose of feature flags.
#[test]
fn test_gossip_mod_rs_cfg_gates_submodules() {
    let g = read_source("src/gossip/mod.rs");
    assert!(
        g.contains("#[cfg(feature = \"compact-blocks\")]") && g.contains("pub mod compact_block;")
    );
    assert!(g.contains("#[cfg(feature = \"erlay\")]") && g.contains("pub mod erlay;"));
}

/// **Row:** `test_privacy_mod_rs_cfg_gates_submodules`
///
/// `src/privacy/mod.rs` MUST gate `dandelion` and `tor` submodules behind their
/// respective features. This prevents Dandelion stem/fluff code from compiling
/// when only Tor is enabled and vice versa.
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
// Each test invokes `cargo check` with a specific feature combination to prove the
// dependency graph resolves cleanly. These are slow (spawns a subprocess) but catch
// cfg-conditional compilation errors that unit tests cannot.

/// **Row:** `test_check_default_features` -- the production default feature set compiles.
///
/// This is the baseline: `native-tls + relay + erlay + compact-blocks + dandelion`.
/// If this fails, the crate is broken for all default consumers.
#[test]
fn test_check_default_features() {
    assert_cargo_check(&[]);
}

/// **Row:** `test_check_native_tls_only_minimal_graph`
///
/// Minimal build: only `native-tls`, no relay/erlay/compact-blocks/dandelion.
/// Proves that cfg-gated modules do not introduce unconditional references to
/// optional types that would break a stripped-down build.
#[test]
fn test_check_native_tls_only_minimal_graph() {
    assert_cargo_check(&["--no-default-features", "--features", "native-tls"]);
}

/// **Row:** `test_check_rustls_only_minimal_graph`
///
/// Minimal build with pure-Rust TLS backend. Ensures `rustls` feature forwarding
/// to `chia-sdk-client/rustls` compiles without `native-tls` present, proving the
/// two TLS backends are genuinely independent alternatives.
#[test]
fn test_check_rustls_only_minimal_graph() {
    assert_cargo_check(&["--no-default-features", "--features", "rustls"]);
}

/// TLS + relay without relying on `default` (explicit subgraph).
#[test]
fn test_check_native_tls_and_relay() {
    assert_cargo_check(&["--no-default-features", "--features", "native-tls,relay"]);
}

/// **Row:** `test_check_native_tls_erlay` -- TLS + erlay without relay/compact-blocks/dandelion.
///
/// Proves erlay's cfg gate compiles independently of the other optional subsystems.
#[test]
fn test_check_native_tls_erlay() {
    assert_cargo_check(&["--no-default-features", "--features", "native-tls,erlay"]);
}

/// **Row:** `test_check_native_tls_compact_blocks` -- TLS + compact-blocks (siphasher activated).
///
/// Proves the `dep:siphasher` activation in `compact-blocks` resolves and the
/// compact block module compiles when it is the only optional subsystem enabled.
#[test]
fn test_check_native_tls_compact_blocks() {
    assert_cargo_check(&[
        "--no-default-features",
        "--features",
        "native-tls,compact-blocks",
    ]);
}

/// **Row:** `test_check_native_tls_dandelion` -- TLS + dandelion only.
///
/// Proves the `privacy` module compiles with just `dandelion` (no `tor`), verifying
/// the `#[cfg(any(feature = "dandelion", feature = "tor"))]` gate in `lib.rs`.
#[test]
fn test_check_native_tls_dandelion() {
    assert_cargo_check(&[
        "--no-default-features",
        "--features",
        "native-tls,dandelion",
    ]);
}

/// **Row:** `test_check_native_tls_tor` -- TLS + tor (arti-client + tokio-socks activated).
///
/// Proves the heaviest optional dependency set resolves. `tor` pulls `arti-client`
/// and `tokio-socks` as optional deps; this check catches link/bindgen issues early.
#[test]
fn test_check_native_tls_tor() {
    assert_cargo_check(&["--no-default-features", "--features", "native-tls,tor"]);
}

/// **Row:** `test_check_all_features` -- every feature enabled simultaneously.
///
/// The superset build MUST compile without conflicts. This catches any mutual
/// exclusion bugs between features (e.g. `native-tls` + `rustls` coexistence,
/// `tor` + `dandelion` both enabling `privacy` module).
#[test]
fn test_check_all_features() {
    assert_cargo_check(&["--all-features"]);
}

// ---- Optional symbol smoke (proves gated re-exports resolve when features on) ----
// These tests use `PhantomData::<T>` to verify that feature-gated types are
// accessible at the crate root when their feature is active, without needing
// to construct real instances (which may require runtime state).

/// **Row:** `smoke_relay_types_at_root_when_feature_on`
///
/// When `relay` is enabled, `dig_gossip::RelayMessage` MUST be a valid type at
/// the crate root. `PhantomData` usage proves the type resolves at compile time
/// without requiring construction of the actual relay message.
#[cfg(feature = "relay")]
#[test]
fn smoke_relay_types_at_root_when_feature_on() {
    let _ = std::marker::PhantomData::<dig_gossip::RelayMessage>;
}

/// **Row:** `smoke_tor_transport_config_at_root`
///
/// When `tor` is enabled, `dig_gossip::TorTransportConfig` MUST be re-exported
/// at the crate root. This is the Tor-specific counterpart to the relay smoke test.
#[cfg(feature = "tor")]
#[test]
fn smoke_tor_transport_config_at_root() {
    let _ = std::marker::PhantomData::<dig_gossip::TorTransportConfig>;
}

/// **Row:** `smoke_dandelion_without_tor_module_still_compiles`
///
/// When `dandelion` is on but `tor` is off, `dig_gossip::StemTransaction` MUST
/// still be available. This proves the `privacy` module's `any(dandelion, tor)`
/// gate works correctly for the dandelion-only case without pulling Tor deps.
#[cfg(all(feature = "dandelion", not(feature = "tor")))]
#[test]
fn smoke_dandelion_without_tor_module_still_compiles() {
    let _ = std::marker::PhantomData::<dig_gossip::StemTransaction>;
}
