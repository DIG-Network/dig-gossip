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

use super::gossip_handle::GossipHandle;
use super::state::{ServiceState, LC_CONSTRUCTED, LC_RUNNING, LC_STOPPED};

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
    /// Networking (listener, discovery tasks) will attach here in CON-* / CNC-*; API-001 only
    /// flips the lifecycle flag and returns the handle.
    pub async fn start(&self) -> Result<GossipHandle, GossipError> {
        match self.inner.lifecycle.compare_exchange(
            LC_CONSTRUCTED,
            LC_RUNNING,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        ) {
            Ok(_) => Ok(GossipHandle {
                inner: self.inner.clone(),
            }),
            Err(LC_RUNNING) => Err(GossipError::AlreadyStarted),
            Err(LC_STOPPED) => Err(GossipError::InvalidConfig(
                "gossip service cannot be restarted after stop() (API-001)".to_string(),
            )),
            Err(_) => Err(GossipError::InvalidConfig(
                "unexpected lifecycle state in GossipService::start".to_string(),
            )),
        }
    }

    /// Tear down: marks lifecycle stopped so [`GossipHandle`] calls fail with [`GossipError::ServiceNotStarted`].
    ///
    /// With no peers yet (CON-*), this is a state transition only; later it joins tasks and
    /// closes sockets.
    pub async fn stop(&self) -> Result<(), GossipError> {
        let prev = self
            .inner
            .lifecycle
            .swap(LC_STOPPED, std::sync::atomic::Ordering::SeqCst);
        match prev {
            LC_CONSTRUCTED => Ok(()),
            LC_RUNNING | LC_STOPPED => Ok(()),
            _ => Ok(()),
        }
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
        other => GossipError::ClientError(Box::new(other)),
    }
}
