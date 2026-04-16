//! Tor/SOCKS5 transport (**PRV-009**, **PRV-010**).
//!
//! # Requirements
//!
//! - **PRV-009** — TorConfig (enabled, socks5_proxy, onion_address, prefer_tor)
//! - **PRV-010** — Tor transport: SOCKS5 outbound, .onion inbound, hybrid, selection
//! - **Master SPEC:** §1.9.3 (Tor/SOCKS5 Proxy Transport)
//!
//! # Feature gate
//!
//! `tor` feature enables `arti-client` + `tokio-socks`.
//! SPEC §1.8#12: "node's physical location and ISP hidden from all peers."

/// Tor/SOCKS5 configuration (**PRV-009**).
///
/// SPEC §1.9.3: "TorConfig with enabled, socks5_proxy, onion_address, prefer_tor."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorConfig {
    /// Enable Tor transport. Default: false.
    pub enabled: bool,
    /// SOCKS5 proxy address (Tor daemon). Default: "127.0.0.1:9050".
    pub socks5_proxy: String,
    /// Hidden service .onion address for inbound. None = outbound only.
    pub onion_address: Option<String>,
    /// Prefer Tor over direct. Default: false.
    /// If true, all outbound via Tor.
    pub prefer_tor: bool,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socks5_proxy: "127.0.0.1:9050".to_string(),
            onion_address: None,
            prefer_tor: false,
        }
    }
}

impl TorConfig {
    /// Whether Tor is configured and enabled.
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    /// Whether this node has a .onion address for inbound.
    pub fn has_onion_address(&self) -> bool {
        self.onion_address.is_some()
    }

    /// Whether running in hybrid mode (direct + Tor).
    ///
    /// SPEC §1.9.3: "accept both direct P2P and Tor connections simultaneously."
    pub fn is_hybrid(&self) -> bool {
        self.enabled && self.has_onion_address() && !self.prefer_tor
    }
}

/// Historical name alias.
pub type TorTransportConfig = TorConfig;

/// Transport selection with Tor (**PRV-010**).
///
/// SPEC §1.9.3 transport selection:
/// - prefer_tor=true → Tor
/// - prefer_tor=false → direct first → relay → Tor
/// - .onion addresses always via Tor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorTransportChoice {
    /// Direct P2P (no Tor).
    Direct,
    /// Via Tor SOCKS5 proxy.
    Tor,
}

/// Select transport considering Tor option (**PRV-010**).
///
/// SPEC §1.9.3: "prefer_tor=true → all outbound via Tor;
/// prefer_tor=false → direct first → Tor as last resort."
pub fn select_with_tor(
    prefer_tor: bool,
    is_onion_address: bool,
    has_direct: bool,
) -> TorTransportChoice {
    // .onion addresses always via Tor
    if is_onion_address {
        return TorTransportChoice::Tor;
    }
    if prefer_tor {
        return TorTransportChoice::Tor;
    }
    if has_direct {
        return TorTransportChoice::Direct;
    }
    // Last resort: Tor
    TorTransportChoice::Tor
}
