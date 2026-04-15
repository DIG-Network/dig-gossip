//! Primary service type: binds listeners, runs discovery, owns subsystem handles.
//!
//! **Requirement:** API-001 /
//! [`docs/requirements/domains/crate_api/specs/API-001.md`](../../../docs/requirements/domains/crate_api/specs/API-001.md)
//! and [`SPEC.md`](../../../docs/resources/SPEC.md) §3.1.
//!
//! ## TLS
//!
//! We delegate the “load or generate PEM” policy to [`chia_sdk_client::load_ssl_cert`] (see
//! upstream `tls.rs`): missing files trigger generation and persistence. API-001 additionally
//! ensures parent directories exist so writes succeed in fresh temp harnesses.

use std::path::Path;
use std::sync::Arc;

use chia_protocol::Bytes32;
use chia_sdk_client::load_ssl_cert;
use chia_sdk_client::ClientError;

use crate::error::GossipError;
use crate::types::config::GossipConfig;

use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::sync::Notify;

use super::gossip_handle::GossipHandle;
use super::state::{PeerSlot, ServiceState, LC_CONSTRUCTED, LC_RUNNING, LC_STOPPED};

/// Owns configuration, TLS identity, and placeholder subsystems created in `new()`.
///
/// **Threading:** cheap to move across threads (`Arc`); `start`/`stop` are `async` for parity
/// with future task joins even though API-001 does not spawn Tokio tasks yet.
#[derive(Debug)]
pub struct GossipService {
    pub(crate) inner: Arc<ServiceState>,
}

impl GossipService {
    /// Build a service: validate config, load/generate TLS, allocate maps — **no** network I/O.
    ///
    /// **Spec cross-links:** [`API-001`](../../../docs/requirements/domains/crate_api/specs/API-001.md#construction-behavior).
    pub fn new(config: GossipConfig) -> Result<Self, GossipError> {
        validate_gossip_config(&config)?;
        ensure_parent_dirs(&config.cert_path, &config.key_path)?;
        let tls = load_tls_material(&config)?;
        let inner = Arc::new(ServiceState::new(config, tls));
        Ok(Self { inner })
    }

    /// Transition to running and hand back a [`GossipHandle`] sharing the same [`ServiceState`].
    ///
    /// Binds [`TcpListener`] on [`GossipConfig::listen_addr`](GossipConfig::listen_addr), spawns
    /// CON-002 inbound accept loop when a TLS feature is enabled (STR-004), and returns the handle.
    ///
    /// **Rollback:** if binding fails, lifecycle returns to constructed so callers may retry.
    pub async fn start(&self) -> Result<GossipHandle, GossipError> {
        match self.inner.lifecycle.compare_exchange(
            LC_CONSTRUCTED,
            LC_RUNNING,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        ) {
            Ok(_) => {
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

                let inner = self.inner.clone();
                let stop_loop = stop.clone();
                #[cfg(any(feature = "native-tls", feature = "rustls"))]
                let jh = tokio::spawn(async move {
                    crate::connection::listener::accept_loop(inner, listener, stop_loop).await;
                });
                #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
                let jh = tokio::spawn(async move {
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
            Err(LC_RUNNING) => Err(GossipError::AlreadyStarted),
            Err(LC_STOPPED) => Err(GossipError::InvalidConfig(
                "gossip service cannot be restarted after stop() (API-001)".to_string(),
            )),
            Err(_) => Err(GossipError::InvalidConfig(
                "unexpected lifecycle state in GossipService::start".to_string(),
            )),
        }
    }

    /// Tear down: stops CON-002 accept loop, clears inbound fan-out, closes live peers.
    pub async fn stop(&self) -> Result<(), GossipError> {
        let _prev = self
            .inner
            .lifecycle
            .swap(LC_STOPPED, std::sync::atomic::Ordering::SeqCst);

        if let Ok(mut g) = self.inner.listener_stop.lock() {
            if let Some(n) = g.take() {
                n.notify_waiters();
            }
        }
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
        *self
            .inner
            .listen_bound_addr
            .lock()
            .expect("listen_bound_addr mutex poisoned") = None;

        *self
            .inner
            .inbound_tx
            .lock()
            .expect("inbound_tx mutex poisoned") = None;
        let old_peers = {
            let mut guard = self.inner.peers.lock().expect("peers mutex poisoned");
            std::mem::take(&mut *guard)
        };
        for (_, slot) in old_peers {
            if let PeerSlot::Live(l) = slot {
                let _ = l.peer.close().await;
            }
        }
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
        Ok(())
    }

    /// Test-only introspection: `true` after a successful [`Self::start`].
    #[doc(hidden)]
    pub fn __is_running_for_tests(&self) -> bool {
        self.inner.is_running()
    }
}

/// Configuration checks required before touching the filesystem (API-001 §Construction).
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

fn load_tls_material(config: &GossipConfig) -> Result<chia_ssl::ChiaCertificate, GossipError> {
    load_ssl_cert(&config.cert_path, &config.key_path).map_err(map_sdk_tls_err)
}

fn map_sdk_tls_err(e: ClientError) -> GossipError {
    match e {
        ClientError::Io(io) => GossipError::IoError(io.to_string()),
        other => other.into(),
    }
}
