//! Primary service type: the entry point for the DIG gossip layer.
//!
//! [`GossipService`] owns configuration, TLS identity, and the shared [`ServiceState`]
//! that backs every subsystem. Its two-phase lifecycle separates construction (config
//! validation, TLS certificate loading, internal state allocation) from network activation
//! (binding the TCP listener, spawning the inbound accept loop, returning a
//! [`GossipHandle`](super::gossip_handle::GossipHandle) for messaging).
//!
//! # Requirements satisfied
//!
//! | Req | Role |
//! |-----|------|
//! | **API-001** | Constructor + `start()` / `stop()` lifecycle ([`docs/requirements/domains/crate_api/specs/API-001.md`]) |
//! | **CON-002** | `start()` binds a [`TcpListener`](tokio::net::TcpListener) and spawns [`crate::connection::listener::accept_loop`] for inbound mTLS connections ([`docs/requirements/domains/connection/specs/CON-002.md`]) |
//! | **CON-004** | `stop()` tears down keepalive tasks and closes live peers ([`docs/requirements/domains/connection/specs/CON-004.md`]) |
//! | **CNC-003** | Shared state is guarded by `Mutex` / `AtomicU64` (see [`ServiceState`](super::state::ServiceState)) |
//!
//! # SPEC cross-references
//!
//! * **§3.1 — Construction:** `GossipService::new(config)` validates, loads TLS, and returns
//!   without spawning tasks or performing network I/O.
//! * **§3.2 — Lifecycle:** `start()` transitions to running; `stop()` drains and cleans up.
//! * **§5.3 — Mutual TLS:** certificate material comes from `chia-ssl` via
//!   [`chia_sdk_client::load_ssl_cert`]; both outbound and inbound paths use the same
//!   [`ChiaCertificate`](chia_ssl::ChiaCertificate).
//!
//! # Design decisions
//!
//! * **Two-phase init (SPEC §3.1):** `new()` is synchronous (`fn`, not `async fn`) because
//!   TLS cert loading is file I/O only. Network I/O is deferred to `start()`.
//! * **Chia TLS delegation:** We delegate the “load or generate PEM” policy to
//!   [`chia_sdk_client::load_ssl_cert`] (see upstream `tls.rs`): missing files trigger
//!   generation and persistence. API-001 additionally ensures parent directories exist so
//!   writes succeed in fresh temp-dir test harnesses.
//! * **No restart:** Once `stop()` is called the service cannot be started again. This
//!   avoids subtle state leaks from reusing partially-cleaned structures (API-001
//!   acceptance criterion).
//! * **Chia equivalent:** There is no direct Chia Python equivalent; the closest analog is
//!   `chia.server.server.ChiaServer.__init__` + `start_server()` in
//!   [`server.py`](https://github.com/Chia-Network/chia-blockchain/blob/main/chia/server/server.py),
//!   but DIG splits responsibilities more granularly between `GossipService` (owner) and
//!   `GossipHandle` (operator).

use std::path::Path;
use std::sync::Arc;

use chia_protocol::Bytes32;
use chia_sdk_client::load_ssl_cert;
use chia_sdk_client::{ClientError, ClientState};

use crate::error::GossipError;
use crate::types::config::GossipConfig;

use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::sync::Notify;

use super::gossip_handle::GossipHandle;
use super::state::{PeerSlot, ServiceState, LC_CONSTRUCTED, LC_RUNNING, LC_STOPPED};

/// Owns configuration, TLS identity, and the [`ServiceState`] that backs every subsystem.
///
/// # Ownership model
///
/// The heavy state lives in `Arc<ServiceState>` so both `GossipService` (lifecycle owner)
/// and [`GossipHandle`](super::gossip_handle::GossipHandle) (messaging surface) can share
/// it cheaply. `GossipService` is the *sole* creator and destroyer of the state; handles
/// are borrowers.
///
/// # Thread safety
///
/// `GossipService` is `Send + Sync` (via inner `Arc`). `start()` and `stop()` are `async`
/// because they perform network I/O (TCP bind, task join), but the constructor is
/// synchronous.
///
/// # Invariants
///
/// * Exactly one `start()` call succeeds; a second returns [`GossipError::AlreadyStarted`].
/// * After `stop()`, re-starting is permanently forbidden (lifecycle is one-way:
///   constructed -> running -> stopped).
///
/// # Requirement traceability
///
/// **API-001** -- [`docs/requirements/domains/crate_api/specs/API-001.md`]
#[derive(Debug)]
pub struct GossipService {
    /// Shared runtime state: configuration, TLS material, peer map, counters, channels.
    /// Cloned into [`GossipHandle`](super::gossip_handle::GossipHandle) on `start()`.
    pub(crate) inner: Arc<ServiceState>,
}

impl GossipService {
    /// Build a new gossip service from the supplied configuration.
    ///
    /// # What happens (SPEC §3.1 — Construction Behavior)
    ///
    /// 1. **Config validation** -- rejects zero `network_id`, inconsistent connection
    ///    limits, and empty cert/key paths (API-001 §Construction).
    /// 2. **Parent-dir creation** -- ensures the directories for `cert_path` / `key_path`
    ///    exist so that `chia-ssl` can write generated PEM files (critical for temp-dir
    ///    test harnesses).
    /// 3. **TLS loading** -- delegates to [`chia_sdk_client::load_ssl_cert`], which loads
    ///    existing PEM files or generates a fresh `ChiaCertificate` pair if they are
    ///    missing (SPEC §5.3).
    /// 4. **State allocation** -- creates the shared [`ServiceState`] with empty peer map,
    ///    address manager, dedup LRU, and zeroed counters. *No tasks are spawned and no
    ///    network I/O is performed.*
    ///
    /// # Errors
    ///
    /// * [`GossipError::InvalidConfig`] -- validation failed (step 1).
    /// * [`GossipError::IoError`] -- directory creation or file I/O failed (steps 2-3).
    /// * [`GossipError::ClientError`] -- TLS creation failed inside `chia-sdk-client`.
    ///
    /// # Postconditions
    ///
    /// On success the service is in the *constructed* state (`LC_CONSTRUCTED`). Call
    /// [`start()`](Self::start) to transition to *running*.
    ///
    /// # Spec cross-links
    ///
    /// [`API-001`](../../../docs/requirements/domains/crate_api/specs/API-001.md#construction-behavior)
    pub fn new(config: GossipConfig) -> Result<Self, GossipError> {
        validate_gossip_config(&config)?;
        ensure_parent_dirs(&config.cert_path, &config.key_path)?;
        let tls = load_tls_material(&config)?;
        let inner = Arc::new(ServiceState::new(config, tls));
        Ok(Self { inner })
    }

    /// Transition the service from *constructed* to *running* and return a [`GossipHandle`].
    ///
    /// # What happens (SPEC §3.2 — Lifecycle)
    ///
    /// 1. **CAS lifecycle guard** -- atomically swaps `LC_CONSTRUCTED` -> `LC_RUNNING`.
    ///    Returns [`GossipError::AlreadyStarted`] or [`GossipError::InvalidConfig`] if the
    ///    service is already running or has been stopped.
    /// 2. **TCP bind** -- binds a [`TcpListener`] on
    ///    [`GossipConfig::listen_addr`](GossipConfig::listen_addr). Port `0` is resolved to
    ///    an OS-assigned port and stored in `listen_bound_addr` for self-dial checks and
    ///    the outbound `Handshake::server_port`.
    /// 3. **Inbound broadcast channel** -- creates a `broadcast::channel(256)` used to
    ///    fan inbound wire messages out to every [`GossipHandle`] subscriber (SPEC §3.3).
    /// 4. **Accept-loop spawn (CON-002)** -- when a TLS feature (`native-tls` or `rustls`)
    ///    is enabled, spawns [`crate::connection::listener::accept_loop`] on a new Tokio
    ///    task. Without a TLS feature the task is a no-op placeholder so the rest of the
    ///    API surface can still be exercised in unit tests.
    /// 5. **Handle creation** -- clones the inner `Arc<ServiceState>` into a new
    ///    [`GossipHandle`] and returns it.
    ///
    /// # Rollback on failure
    ///
    /// If TCP bind or `local_addr()` fails, the lifecycle is restored to `LC_CONSTRUCTED`
    /// so the caller may retry (e.g. with a different port).
    ///
    /// # Errors
    ///
    /// * [`GossipError::IoError`] -- TCP bind or address resolution failed.
    /// * [`GossipError::AlreadyStarted`] -- `start()` was already called successfully.
    /// * [`GossipError::InvalidConfig`] -- the service has been stopped and cannot restart.
    ///
    /// # Postconditions
    ///
    /// On success the service is in the *running* state and the returned handle is
    /// immediately usable for broadcasting, peer management, and stats queries.
    ///
    /// # Spec cross-links
    ///
    /// * **CON-002** -- [`docs/requirements/domains/connection/specs/CON-002.md`]
    /// * **CNC-002** -- task spawning ([`docs/requirements/domains/concurrency/specs/CNC-002.md`])
    pub async fn start(&self) -> Result<GossipHandle, GossipError> {
        // Atomic CAS ensures only one `start()` ever succeeds. SeqCst is used
        // (rather than Acquire/Release) for simplicity -- this is a rare, one-time
        // operation so the stricter ordering has no measurable cost.
        match self.inner.lifecycle.compare_exchange(
            LC_CONSTRUCTED,
            LC_RUNNING,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        ) {
            Ok(_) => {
                // Step 2: Bind TCP listener. Port 0 triggers OS-assigned ephemeral port,
                // used heavily in tests to avoid port conflicts (API-001 test plan).
                let listener = match TcpListener::bind(self.inner.config.listen_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.inner
                            .lifecycle
                            .store(LC_CONSTRUCTED, std::sync::atomic::Ordering::SeqCst);
                        return Err(GossipError::IoError(e.to_string()));
                    }
                };
                let bound = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        self.inner
                            .lifecycle
                            .store(LC_CONSTRUCTED, std::sync::atomic::Ordering::SeqCst);
                        return Err(GossipError::IoError(e.to_string()));
                    }
                };
                *self
                    .inner
                    .listen_bound_addr
                    .lock()
                    .expect("listen_bound_addr mutex poisoned") = Some(bound);

                // Step 3: Create the inbound fan-out channel. SPEC §3.3 says
                // `mpsc::Receiver`, but we use `broadcast` so multiple GossipHandle
                // clones can each subscribe independently (Rust-idiomatic fan-out).
                // Capacity 256 is a balance between memory and backpressure.
                let (tx, _rx) = broadcast::channel(256);
                *self
                    .inner
                    .inbound_tx
                    .lock()
                    .expect("inbound_tx mutex poisoned") = Some(tx);

                let stop = Arc::new(Notify::new());
                *self
                    .inner
                    .listener_stop
                    .lock()
                    .expect("listener_stop mutex poisoned") = Some(stop.clone());

                // Step 4: Spawn the CON-002 inbound accept loop.
                //
                // WHY conditional compilation: TLS is mandatory for real P2P
                // (SPEC §5.3), but unit tests that only exercise the API surface
                // (API-001, API-002) run without a TLS feature to keep CI fast.
                // The no-TLS branch immediately drops the listener so that the
                // port is freed.
                let inner = self.inner.clone();
                let stop_loop = stop.clone();
                #[cfg(any(feature = "native-tls", feature = "rustls"))]
                let jh = tokio::spawn(async move {
                    crate::connection::listener::accept_loop(inner, listener, stop_loop).await;
                });
                #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
                let jh = tokio::spawn(async move {
                    // No-op: drop the listener so the OS reclaims the port.
                    let _ = (inner, listener, stop_loop);
                });

                *self
                    .inner
                    .listener_task
                    .lock()
                    .expect("listener_task mutex poisoned") = Some(jh);

                Ok(GossipHandle {
                    inner: self.inner.clone(),
                })
            }
            // Already running -- API-001 acceptance criterion: "Calling `start()` twice
            // returns `GossipError`."
            Err(LC_RUNNING) => Err(GossipError::AlreadyStarted),
            // Already stopped -- one-way lifecycle; restart is forbidden to avoid stale-state bugs.
            Err(LC_STOPPED) => Err(GossipError::InvalidConfig(
                "gossip service cannot be restarted after stop() (API-001)".to_string(),
            )),
            // Defensive: should never happen with the three-state model.
            Err(_) => Err(GossipError::InvalidConfig(
                "unexpected lifecycle state in GossipService::start".to_string(),
            )),
        }
    }

    /// Gracefully shut down the gossip service (SPEC §3.2, CON-004).
    ///
    /// # Teardown sequence
    ///
    /// 1. **Lifecycle swap** -- unconditionally sets `LC_STOPPED` so all future API calls
    ///    on any [`GossipHandle`](super::gossip_handle::GossipHandle) return
    ///    [`GossipError::ServiceNotStarted`].
    /// 2. **Signal accept loop** -- notifies the [`Notify`](tokio::sync::Notify) watched
    ///    by [`crate::connection::listener::accept_loop`], then aborts+joins the task.
    /// 3. **Clear listen address** -- frees the OS port.
    /// 4. **Drop inbound channel** -- dropping the `broadcast::Sender` causes every
    ///    subscriber's `recv()` to return `RecvError::Closed`, which is the signal
    ///    downstream consumers use to stop.
    /// 5. **Close live peers** -- drains the peer map and calls `Peer::close()` on each
    ///    live TLS connection (CON-004 keepalive tasks observe the close and exit).
    /// 6. **Clear ban / penalty maps** -- resets reputation state so a fresh `GossipService`
    ///    on the same process starts clean.
    ///
    /// # Errors
    ///
    /// Currently infallible (`Ok(())` always). The return type is `Result` for forward
    /// compatibility with async drain that may need to propagate join errors.
    ///
    /// # Postconditions
    ///
    /// After return, no background tasks from this service are running and all network
    /// resources have been released.
    ///
    /// # Spec cross-links
    ///
    /// * **API-001** -- lifecycle: "Gracefully stop: disconnect all peers, stop discovery, close relay."
    /// * **CON-004** -- keepalive tasks terminate when their `Peer` handle is closed.
    pub async fn stop(&self) -> Result<(), GossipError> {
        // Step 1: Unconditional swap -- even if already stopped, this is idempotent.
        let _prev = self
            .inner
            .lifecycle
            .swap(LC_STOPPED, std::sync::atomic::Ordering::SeqCst);

        // Step 2a: Signal the accept loop to stop gracefully.
        if let Ok(mut g) = self.inner.listener_stop.lock() {
            if let Some(n) = g.take() {
                n.notify_waiters();
            }
        }
        // Step 2b: Abort the task (belt-and-suspenders) and await completion.
        let listener_join = self
            .inner
            .listener_task
            .lock()
            .ok()
            .and_then(|mut g| g.take());
        if let Some(jh) = listener_join {
            jh.abort();
            let _ = jh.await;
        }

        // Step 3: Clear the bound address so the OS can reclaim the port.
        *self
            .inner
            .listen_bound_addr
            .lock()
            .expect("listen_bound_addr mutex poisoned") = None;

        // Step 4: Drop the inbound broadcast sender; subscribers see `RecvError::Closed`.
        *self
            .inner
            .inbound_tx
            .lock()
            .expect("inbound_tx mutex poisoned") = None;

        // Step 5: Drain peer map, close every live TLS connection (CON-004).
        // Stubs are simply dropped; they have no network resource.
        let old_peers = {
            let mut guard = self.inner.peers.lock().expect("peers mutex poisoned");
            std::mem::take(&mut *guard)
        };
        for (_, slot) in old_peers {
            if let PeerSlot::Live(l) = slot {
                let _ = l.peer.close().await;
            }
        }

        // Step 6: Reset reputation state for process cleanliness.
        self.inner
            .banned
            .lock()
            .expect("banned mutex poisoned")
            .clear();
        self.inner
            .penalties
            .lock()
            .expect("penalties mutex poisoned")
            .clear();
        // CON-007 — drop Chia-side IP bans so the next `start()` in a fresh process/test run
        // does not inherit stale `ClientState::banned_peers` rows.
        *self.inner.chia_ip_bans.lock().await = ClientState::default();
        Ok(())
    }

    /// Test-only introspection: `true` after a successful [`Self::start`].
    #[doc(hidden)]
    pub fn __is_running_for_tests(&self) -> bool {
        self.inner.is_running()
    }
}

/// Validate configuration invariants required by API-001 §Construction *before* any
/// filesystem or network I/O.
///
/// # Checks
///
/// * `network_id` is non-zero -- a zero genesis ID would cause every handshake to be
///   rejected by the Chia wire protocol validation inside `connect_peer()`.
/// * `target_outbound_count <= max_connections` -- prevents the discovery loop from
///   attempting more connections than the connection manager will accept.
/// * `cert_path` / `key_path` are non-empty -- downstream `load_ssl_cert` would panic
///   on empty strings; we surface a clear config error instead.
fn validate_gossip_config(config: &GossipConfig) -> Result<(), GossipError> {
    if config.network_id == Bytes32::default() {
        return Err(GossipError::InvalidConfig(
            "network_id must be non-zero (set a DIG network genesis id)".to_string(),
        ));
    }
    if config.target_outbound_count > config.max_connections {
        return Err(GossipError::InvalidConfig(format!(
            "target_outbound_count ({}) must be <= max_connections ({})",
            config.target_outbound_count, config.max_connections
        )));
    }
    if config.cert_path.is_empty() || config.key_path.is_empty() {
        return Err(GossipError::InvalidConfig(
            "cert_path and key_path must be non-empty PEM locations".to_string(),
        ));
    }
    Ok(())
}

/// Create parent directories for cert/key paths so that `chia-ssl` can write freshly
/// generated PEM files.
///
/// This is necessary in test harnesses that use `tempdir()` where the subdirectory tree
/// does not yet exist. Without this step, `load_ssl_cert` would fail with a "No such
/// file or directory" error when attempting to generate a new certificate.
fn ensure_parent_dirs(cert_path: &str, key_path: &str) -> Result<(), GossipError> {
    let c = Path::new(cert_path);
    let k = Path::new(key_path);
    if let Some(p) = c.parent() {
        std::fs::create_dir_all(p).map_err(|e| GossipError::IoError(e.to_string()))?;
    }
    if let Some(p) = k.parent() {
        std::fs::create_dir_all(p).map_err(|e| GossipError::IoError(e.to_string()))?;
    }
    Ok(())
}

/// Load (or generate) a TLS certificate pair via [`chia_sdk_client::load_ssl_cert`]
/// (SPEC section 5.3 — mandatory mutual TLS; **CON-009**).
///
/// The returned [`ChiaCertificate`](chia_ssl::ChiaCertificate) is stored in
/// [`ServiceState::tls`] and used for both outbound `connect_peer()` calls and the
/// inbound TLS acceptor in the CON-002 accept loop (see `vendor/native-tls/README.dig-gossip.md`
/// for inbound OpenSSL `CERT_REQUIRED` behavior).
fn load_tls_material(config: &GossipConfig) -> Result<chia_ssl::ChiaCertificate, GossipError> {
    load_ssl_cert(&config.cert_path, &config.key_path).map_err(map_sdk_tls_err)
}

/// Map [`chia_sdk_client::ClientError`] to [`GossipError`], special-casing the `Io`
/// variant so callers see [`GossipError::IoError`] (a `String`) rather than the
/// `Arc`-wrapped `ClientError` path. This keeps file-system errors easy to pattern-match
/// in tests.
fn map_sdk_tls_err(e: ClientError) -> GossipError {
    match e {
        ClientError::Io(io) => GossipError::IoError(io.to_string()),
        other => other.into(),
    }
}
