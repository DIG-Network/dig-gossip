//! Integration + unit tests for **STR-001: Cargo.toml dependencies and feature gates**.
//!
//! ## Requirement traceability
//!
//! - **Normative:** `docs/requirements/domains/crate_structure/NORMATIVE.md` (STR-001)
//! - **Detailed spec + test plan:** `docs/requirements/domains/crate_structure/specs/STR-001.md`
//!
//! ## What this file proves
//!
//! STR-001 is satisfied when:
//!
//! 1. The workspace `Cargo.toml` declares every required dependency at the pinned
//!    minor versions from the spec (Chia crates, async stack, serialization, utilities,
//!    and the optional `siphasher` / `minisketch-rs` pair).
//!
//!    **Ecosystem note (`minisketch-rs`):** STR-001’s sample manifest lists
//!    `minisketch-rs`, but adding that crate makes Cargo fail dependency resolution
//!    because `minisketch-rs`’s build pulls `bindgen` (`links = "clang"`), which
//!    collides with `chia-sdk-client`’s *optional* `rustls → aws-lc-rs (bindgen)`
//!    edge — Cargo resolves optional dependencies globally, so the clash happens even
//!    when we only enable `native-tls`. The dependency is therefore omitted **for now**;
//!    the `erlay` feature remains for `cfg` gates. See `TRACKING.yaml` for STR-001.
//! 2. Feature flags `native-tls`, `rustls`, `relay`, `erlay`, and `compact-blocks`
//!    exist and wire up TLS forwarding / optional dependencies exactly as required.
//! 3. Default features include the four STR-001 defaults.
//! 4. The crate **compiles** under the default feature set and under an alternate
//!    TLS backend (`rustls`) with default features disabled — mirroring the spec’s
//!    integration checks.
//!
//! ## How to read the tests
//!
//! - **Parsing tests** use the `toml` crate to treat the manifest as data. That
//!   keeps assertions stable and avoids hand-maintaining a second copy of versions.
//! - **Compilation tests** shell out to `cargo check` so we validate the *actual*
//!   resolver output, not just string matching in TOML.

use std::path::PathBuf;
use std::process::Command;
use toml::Value;

/// Locate the package manifest for this integration test crate.
///
/// Cargo sets `CARGO_MANIFEST_DIR` to the package root (`dig-gossip/`), which is
/// where `Cargo.toml` lives.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Load and parse the root `Cargo.toml` as a generic `toml::Value`.
///
/// # Panics
///
/// Panics if the file is missing or not valid TOML — those are hard failures for
/// STR-001 because the requirement *is* the manifest.
fn load_cargo_toml() -> Value {
    let path = workspace_root().join("Cargo.toml");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("failed to read {}: {e}", path.display());
    });
    raw.parse::<Value>()
        .unwrap_or_else(|e| panic!("failed to parse {} as TOML: {e}", path.display()))
}

/// Return the `[dependencies]` table if present.
fn dependencies_table(manifest: &Value) -> &toml::value::Table {
    manifest
        .get("dependencies")
        .and_then(Value::as_table)
        .expect("[dependencies] table must exist for STR-001")
}

/// Return the `[features]` table if present.
fn features_table(manifest: &Value) -> &toml::value::Table {
    manifest
        .get("features")
        .and_then(Value::as_table)
        .expect("[features] table must exist for STR-001")
}

/// Extract a simple version string like `"0.26"` from either:
/// - `dep = "0.26"`
/// - `dep = { version = "0.26", ... }`
fn dep_version(dep: &Value) -> String {
    if let Some(s) = dep.as_str() {
        return s.to_string();
    }
    let table = dep
        .as_table()
        .expect("dependency must be a string or inline table");
    table
        .get("version")
        .and_then(Value::as_str)
        .expect("inline dependency must declare version")
        .to_string()
}

/// Whether an inline dependency enables default features from its crate.
fn dep_default_features(dep: &Value) -> bool {
    let Some(table) = dep.as_table() else {
        return true;
    };
    table
        .get("default-features")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

/// `cargo check` from the package root with the given feature arguments.
///
/// This proves the manifest resolves for real toolchains, not only that the TOML
/// *looks* correct.
fn assert_cargo_check_succeeds(extra_args: &[&str]) {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root());
    cmd.arg("check");
    cmd.args(extra_args);

    let output = cmd.output().unwrap_or_else(|e| {
        panic!("failed to spawn `cargo check` ({extra_args:?}): {e}");
    });

    assert!(
        output.status.success(),
        "`cargo check {:?}` failed.\nstdout:\n{}\nstderr:\n{}",
        extra_args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn test_cargo_toml_has_chia_protocol() {
    let manifest = load_cargo_toml();
    let deps = dependencies_table(&manifest);
    let dep = deps
        .get("chia-protocol")
        .expect("chia-protocol must be declared");
    assert_eq!(dep_version(dep), "0.26");
}

#[test]
fn test_cargo_toml_has_chia_sdk_client() {
    let manifest = load_cargo_toml();
    let deps = dependencies_table(&manifest);
    let dep = deps
        .get("chia-sdk-client")
        .expect("chia-sdk-client must be declared");
    assert_eq!(dep_version(dep), "0.28");
    // STR-001 requires TLS selection via our feature flags, not a hard-coded
    // `features = ["native-tls"]` on the dependency that would block rustls builds.
    assert!(
        !dep_default_features(dep),
        "chia-sdk-client must use default-features = false so native-tls/rustls are exclusive"
    );
}

#[test]
fn test_cargo_toml_has_chia_ssl() {
    let manifest = load_cargo_toml();
    let deps = dependencies_table(&manifest);
    let dep = deps.get("chia-ssl").expect("chia-ssl must be declared");
    assert_eq!(dep_version(dep), "0.26");
}

#[test]
fn test_cargo_toml_has_chia_traits() {
    let manifest = load_cargo_toml();
    let deps = dependencies_table(&manifest);
    let dep = deps
        .get("chia-traits")
        .expect("chia-traits must be declared");
    assert_eq!(dep_version(dep), "0.26");
}

#[test]
fn test_cargo_toml_has_tokio() {
    let manifest = load_cargo_toml();
    let deps = dependencies_table(&manifest);
    let dep = deps.get("tokio").expect("tokio must be declared");
    let table = dep
        .as_table()
        .expect("tokio must use an inline table for features");
    assert_eq!(
        table.get("version").and_then(Value::as_str),
        Some("1"),
        "tokio minor pin"
    );
    let features = table
        .get("features")
        .and_then(Value::as_array)
        .expect("tokio must declare features");
    let flags: Vec<&str> = features.iter().filter_map(Value::as_str).collect();
    assert!(
        flags.contains(&"full"),
        "tokio must include the `full` feature per STR-001, got {flags:?}"
    );
}

#[test]
fn test_cargo_toml_has_serde_deps() {
    let manifest = load_cargo_toml();
    let deps = dependencies_table(&manifest);

    let serde = deps.get("serde").expect("serde must be declared");
    let serde_table = serde
        .as_table()
        .expect("serde must use an inline table for derive feature");
    assert_eq!(
        serde_table.get("version").and_then(Value::as_str),
        Some("1")
    );
    let serde_features = serde_table
        .get("features")
        .and_then(Value::as_array)
        .expect("serde must declare features");
    let serde_flags: Vec<&str> = serde_features.iter().filter_map(Value::as_str).collect();
    assert!(
        serde_flags.contains(&"derive"),
        "serde must enable derive, got {serde_flags:?}"
    );

    let bincode = deps.get("bincode").expect("bincode must be declared");
    assert_eq!(dep_version(bincode), "1");

    let serde_json = deps.get("serde_json").expect("serde_json must be declared");
    assert_eq!(dep_version(serde_json), "1");
}

#[test]
fn test_cargo_toml_has_utility_deps() {
    let manifest = load_cargo_toml();
    let deps = dependencies_table(&manifest);
    for name in ["tracing", "thiserror", "rand", "lru"] {
        assert!(
            deps.contains_key(name),
            "{name} must be declared in [dependencies]"
        );
    }
    assert_eq!(dep_version(deps.get("tracing").unwrap()), "0.1");
    assert_eq!(dep_version(deps.get("thiserror").unwrap()), "2");
    assert_eq!(dep_version(deps.get("rand").unwrap()), "0.8");
    assert_eq!(dep_version(deps.get("lru").unwrap()), "0.12");
}

#[test]
fn test_cargo_toml_has_optional_deps() {
    let manifest = load_cargo_toml();
    let deps = dependencies_table(&manifest);

    let sip = deps.get("siphasher").expect("siphasher must be declared");
    let sip_table = sip
        .as_table()
        .expect("siphasher should be optional (inline table)");
    assert_eq!(sip_table.get("version").and_then(Value::as_str), Some("1"));
    assert_eq!(
        sip_table.get("optional").and_then(Value::as_bool),
        Some(true),
        "siphasher should be optional and activated by `compact-blocks`"
    );

    assert!(
        !deps.contains_key("minisketch-rs"),
        "`minisketch-rs` is intentionally absent — see module-level ecosystem note + TRACKING.yaml"
    );
}

#[test]
fn test_feature_native_tls() {
    let manifest = load_cargo_toml();
    let feats = features_table(&manifest);
    let flag = feats
        .get("native-tls")
        .and_then(Value::as_array)
        .expect("native-tls feature must exist");
    let entries: Vec<&str> = flag.iter().filter_map(Value::as_str).collect();
    assert!(
        entries.contains(&"chia-sdk-client/native-tls"),
        "native-tls must forward to chia-sdk-client, got {entries:?}"
    );
}

#[test]
fn test_feature_rustls() {
    let manifest = load_cargo_toml();
    let feats = features_table(&manifest);
    let flag = feats
        .get("rustls")
        .and_then(Value::as_array)
        .expect("rustls feature must exist");
    let entries: Vec<&str> = flag.iter().filter_map(Value::as_str).collect();
    assert!(
        entries.contains(&"chia-sdk-client/rustls"),
        "rustls must forward to chia-sdk-client, got {entries:?}"
    );
}

#[test]
fn test_feature_relay() {
    let manifest = load_cargo_toml();
    let feats = features_table(&manifest);
    let flag = feats
        .get("relay")
        .and_then(Value::as_array)
        .expect("relay feature must exist");
    assert!(
        flag.is_empty(),
        "relay must not pull extra deps at STR-001 stage, got {flag:?}"
    );
}

#[test]
fn test_feature_erlay() {
    let manifest = load_cargo_toml();
    let feats = features_table(&manifest);
    let flag = feats
        .get("erlay")
        .and_then(Value::as_array)
        .expect("erlay feature must exist");
    assert!(
        flag.is_empty(),
        "erlay is currently a pure cfg gate (no `minisketch-rs` dep — Cargo links collision); got {flag:?}"
    );
}

#[test]
fn test_feature_compact_blocks() {
    let manifest = load_cargo_toml();
    let feats = features_table(&manifest);
    let flag = feats
        .get("compact-blocks")
        .and_then(Value::as_array)
        .expect("compact-blocks feature must exist");
    let entries: Vec<&str> = flag.iter().filter_map(Value::as_str).collect();
    assert!(
        entries.contains(&"siphasher"),
        "compact-blocks must enable siphasher (optional dep), got {entries:?}"
    );
}

#[test]
fn test_default_features() {
    let manifest = load_cargo_toml();
    let feats = features_table(&manifest);
    let default = feats
        .get("default")
        .and_then(Value::as_array)
        .expect("default feature set must exist");
    let entries: Vec<&str> = default.iter().filter_map(Value::as_str).collect();
    for required in ["native-tls", "relay", "erlay", "compact-blocks"] {
        assert!(
            entries.contains(&required),
            "default features must include {required}, got {entries:?}"
        );
    }
}

#[test]
fn test_cargo_check_default() {
    // Proves default feature resolution succeeds end-to-end on the developer/CI machine.
    assert_cargo_check_succeeds(&[]);
}

#[test]
fn test_cargo_check_rustls() {
    // Proves the alternate TLS backend resolves when default features (incl. native-tls)
    // are disabled — matches STR-001 acceptance criteria.
    assert_cargo_check_succeeds(&["--no-default-features", "--features", "rustls"]);
}
