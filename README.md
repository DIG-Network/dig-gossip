# dig-gossip

Peer-to-peer networking and gossip for the DIG Network L2 blockchain. Handles peer
discovery, connection management, and message routing between DIG full nodes. Accepts
application-level payloads (blocks, transactions, attestations) as opaque `Message` bytes
and delivers them to connected peers via a Chia-compatible protocol extended with
Plumtree structured gossip, ERLAY transaction relay, priority lanes, compact block relay,
Dandelion++ privacy, and relay fallback for NAT traversal.

---

## What this crate does / does NOT do

| Does | Does NOT |
|------|----------|
| Peer discovery (DNS seeds, introducer, peer exchange) | Block validation |
| TLS-authenticated P2P connections (mTLS via chia-ssl) | CLVM execution |
| Message broadcast + relay + receive | Mempool management |
| Plumtree structured gossip (eager + lazy push) | Consensus / fork choice |
| ERLAY-style transaction reconciliation | Validator key management |
| Priority lanes + backpressure (Critical > Normal > Bulk) | RPC or HTTP endpoints |
| Compact block relay (BIP-152 style) | State storage |
| Dandelion++ transaction origin privacy | |
| Relay fallback for NAT-traversed peers | |

---

## Lifecycle

```rust
use dig_gossip::{GossipConfig, GossipService, GossipError};

// 1. Configure — all fields have sane defaults
let config = GossipConfig {
    listen_addr: "0.0.0.0:9444".parse()?,
    ..GossipConfig::default()
};

// 2. Construct — loads TLS certificates, creates address manager
let service = GossipService::new(config)?;

// 3. Start — binds listener, spawns background tasks, returns handle
let handle = service.start().await?;

// 4. Use the handle — Send + Sync + Clone, share across tasks freely
handle.broadcast(message, None).await?;              // fan-out to peers
let rx = handle.inbound_receiver()?;                 // recv (PeerId, Message)
let stats = handle.stats().await;                    // observe metrics
let peer_id = handle.connect_to(addr).await?;        // manual connect
handle.ban_peer(peer_id, PenaltyReason::InvalidBlock).await?;

// 5. Stop — disconnects all peers, saves address manager, cancels tasks
service.stop().await?;
```

---

## Public API

### `GossipService` — owns the service lifecycle

```rust
pub struct GossipService { ... }

impl GossipService {
    /// Construct. Loads TLS cert, creates address manager, validates config.
    /// Returns Err if certs are missing or config is invalid.
    pub fn new(config: GossipConfig) -> Result<Self, GossipError>;

    /// Bind listener, spawn background tasks (discovery, feeler, cleanup, relay).
    /// Returns a GossipHandle for interacting with the live service.
    pub async fn start(&self) -> Result<GossipHandle, GossipError>;

    /// Graceful shutdown: disconnect all peers, flush address manager, cancel tasks.
    pub async fn stop(&self) -> Result<(), GossipError>;
}
```

### `GossipHandle` — interact with the running service

`GossipHandle` is `Send + Sync + Clone` (cheaply cloneable Arc wrapper). All methods
require the service to be started; they return `GossipError::ServiceNotStarted` otherwise.

```rust
pub struct GossipHandle { ... }

impl GossipHandle {
    // --- Health & stats ---

    /// Returns Ok(()) if the service is running and accepting connections.
    pub async fn health_check(&self) -> Result<(), GossipError>;

    /// Aggregate network metrics across all live connections.
    pub async fn stats(&self) -> GossipStats;

    /// Relay-specific stats (None if relay feature not compiled or not connected).
    pub async fn relay_stats(&self) -> Option<RelayStats>;

    // --- Inbound messages ---

    /// Subscribe to inbound messages from all peers.
    /// Returns (PeerId, Message) pairs as they arrive.
    /// Multiple callers get independent broadcast::Receiver instances.
    pub fn inbound_receiver(&self) -> Result<broadcast::Receiver<(PeerId, Message)>, GossipError>;

    // --- Outbound messages ---

    /// Broadcast a raw Chia Message to all connected peers.
    ///
    /// Routing: Plumtree eager/lazy push (INT-001). Priority: assigned by
    /// MessagePriority::from_chia_type() or from_dig_type() (PRI-001).
    /// Backpressure: bulk dropped, normal delayed, tx deduped under load (PRI-005..008).
    ///
    /// exclude_peer: if Some(id), that peer is skipped (origin exclusion for gossip).
    /// Returns the number of peers the message was sent to.
    pub async fn broadcast(
        &self,
        msg: Message,
        exclude_peer: Option<PeerId>,
    ) -> Result<usize, GossipError>;

    /// Broadcast a typed Streamable message (serialized to Message internally).
    pub async fn broadcast_typed<T: Streamable + ChiaProtocolMessage + Send>(
        &self,
        body: T,
        exclude_peer: Option<PeerId>,
    ) -> Result<usize, GossipError>;

    /// Send a typed message to one specific peer.
    pub async fn send_to<T: Streamable + ChiaProtocolMessage + Send>(
        &self,
        peer_id: PeerId,
        body: T,
    ) -> Result<(), GossipError>;

    /// Send a request and await a typed response from one peer.
    pub async fn request<T, B>(&self, peer_id: PeerId, body: B) -> Result<T, GossipError>
    where
        T: Streamable + ChiaProtocolMessage,
        B: Streamable + ChiaProtocolMessage + Send;

    // --- Connection management ---

    /// Open an outbound TLS connection to addr (port 9444 default).
    /// Performs mTLS handshake, network_id check, RequestPeers peer exchange.
    /// Returns the PeerId (SHA256 of peer's TLS cert public key).
    pub async fn connect_to(&self, addr: std::net::SocketAddr) -> Result<PeerId, GossipError>;

    /// Disconnect a peer (closes the WebSocket, removes from active set).
    pub async fn disconnect(&self, peer_id: &PeerId) -> Result<(), GossipError>;

    /// Apply penalty points and ban if threshold is reached.
    /// Ban duration: BAN_DURATION_SECS (3600s default).
    pub async fn ban_peer(
        &self,
        peer_id: PeerId,
        reason: PenaltyReason,
    ) -> Result<(), GossipError>;

    /// Apply penalty points without necessarily triggering a ban.
    pub async fn penalize_peer(
        &self,
        peer_id: PeerId,
        reason: PenaltyReason,
    ) -> Result<(), GossipError>;

    // --- Peer queries ---

    /// All currently live connections with metadata.
    pub async fn connected_peers(&self) -> Vec<PeerConnection>;

    /// Number of live connections.
    pub async fn peer_count(&self) -> usize;

    // --- Discovery helpers ---

    /// Manually query the configured introducer for peers.
    pub async fn discover_from_introducer(&self) -> Result<Vec<TimestampedPeerInfo>, GossipError>;

    /// Register this node with the configured introducer.
    pub async fn register_with_introducer(&self) -> Result<RegisterAck, GossipError>;

    /// Send RequestPeers to a specific peer and return the response.
    pub async fn request_peers_from(
        &self,
        peer_id: &PeerId,
    ) -> Result<RespondPeers, GossipError>;
}
```

---

## Configuration — `GossipConfig`

All fields have defaults. Minimal working config:

```rust
let config = GossipConfig::default(); // binds 0.0.0.0:9444, generates ephemeral cert
```

Full config reference:

```rust
pub struct GossipConfig {
    /// TCP listen address. Default: 0.0.0.0:9444.
    pub listen_addr: SocketAddr,

    /// This node's PeerId (Bytes32 = SHA256 of TLS cert public key).
    /// Default: derived from loaded cert at start().
    pub peer_id: PeerId,

    /// Chia network_id for handshake validation. Default: mainnet.
    pub network_id: Bytes32,

    /// Chia Network for DNS seed resolution (mainnet/testnet/etc.).
    pub network: Network,

    /// DNS seed resolution timeout. Default: 30s.
    pub dns_seed_timeout: Duration,

    /// Number of DNS seeds to query per discovery round. Default: 2.
    pub dns_seed_batch_size: usize,

    /// Target number of outbound connections. Default: 8.
    pub target_outbound_count: usize,

    /// Hard cap on total connections (inbound + outbound). Default: 50.
    pub max_connections: usize,

    /// Static bootstrap peers (bypasses DNS seeding). Default: empty.
    pub bootstrap_peers: Vec<SocketAddr>,

    /// Introducer config for DIG-specific peer discovery. Default: None.
    pub introducer: Option<IntroducerConfig>,

    /// Relay fallback config for NAT traversal. Default: None.
    pub relay: Option<RelayConfig>,

    /// Path to TLS certificate PEM. Default: "" (auto-generate ephemeral).
    pub cert_path: String,

    /// Path to TLS private key PEM. Default: "" (auto-generate ephemeral).
    pub key_path: String,

    /// Seconds between outbound connection attempts. Default: 30.
    pub peer_connect_interval: u64,

    /// Plumtree eager-push fanout (peers per broadcast). Default: 8.
    pub gossip_fanout: usize,

    /// Seen-message dedup set capacity. Default: 100_000.
    pub max_seen_messages: usize,

    /// Path to persist the address manager state. Default: "peers.dat".
    pub peers_file_path: PathBuf,

    /// Per-connection options (rate limit factor, etc.).
    pub peer_options: PeerOptions,

    /// Dandelion++ privacy config. None = disabled. Feature gate: dandelion.
    pub dandelion: Option<DandelionConfig>,

    /// PeerId rotation config. None = disabled.
    pub peer_id_rotation: Option<PeerIdRotationConfig>,

    /// Tor SOCKS5 proxy config. None = disabled. Feature gate: tor.
    #[cfg(feature = "tor")]
    pub tor: Option<TorConfig>,

    /// ERLAY set-reconciliation config. None = disabled. Feature gate: erlay.
    #[cfg(feature = "erlay")]
    pub erlay: Option<ErlayConfig>,

    /// Adaptive backpressure thresholds. None = backpressure disabled.
    pub backpressure: Option<BackpressureConfig>,

    /// Override PING_INTERVAL_SECS for tests. None = use constant.
    pub keepalive_ping_interval_secs: Option<u64>,

    /// Override PEER_TIMEOUT_SECS for tests. None = use constant.
    pub keepalive_peer_timeout_secs: Option<u64>,
}
```

### Sub-configs

```rust
// Introducer — DIG-specific peer discovery server
pub struct IntroducerConfig {
    pub endpoint: String,              // ws://host:9448
    pub connection_timeout_secs: u64,  // default: 10
    pub request_timeout_secs: u64,     // default: 30
    pub network_id: String,            // default: "DIG_MAINNET"
}

// Relay — WebSocket relay server for NAT traversal
pub struct RelayConfig {
    pub endpoint: String,  // ws://host:9450
    pub enabled: bool,
    // + reconnect_delay, max_reconnect_attempts, etc.
}

// Dandelion++ transaction origin privacy (feature: dandelion)
pub struct DandelionConfig {
    pub enabled: bool,
    pub fluff_probability: f64,    // default: 0.1 (10% per hop)
    pub stem_timeout_secs: u64,    // default: 30 (force fluff after)
    pub epoch_secs: u64,           // default: 600 (re-randomize stem relay)
}

// PeerId rotation — fresh TLS cert on interval (PRV-006..008)
pub struct PeerIdRotationConfig {
    pub enabled: bool,                  // default: true
    pub rotation_interval_secs: u64,    // default: 86400 (24h)
    pub reconnect_on_rotation: bool,    // default: true
}

// ERLAY transaction reconciliation (feature: erlay)
pub struct ErlayConfig {
    pub flood_peer_count: usize,                // default: 1
    pub reconciliation_interval_ms: u64,        // default: 2000
    pub sketch_capacity: usize,                 // default: 8
}

// Adaptive backpressure (PRI-005..008)
pub struct BackpressureConfig {
    pub tx_dedup_threshold: usize,    // queue depth above which duplicate txns are dropped
    pub bulk_drop_threshold: usize,   // queue depth above which bulk messages are dropped
    pub normal_delay_threshold: usize,// queue depth above which normal messages are delayed
}
```

---

## Key Types

### Peer identification

```rust
// PeerId = SHA256(remote TLS certificate public key) — stable across reconnects
pub type PeerId = Bytes32;

// Human-readable peer address
pub struct PeerInfo {
    pub host: String,
    pub port: u16,
}

// Full peer metadata for a live connection
pub struct PeerConnection {
    pub peer: Peer,               // chia-sdk-client handle
    pub peer_id: PeerId,
    pub address: SocketAddr,
    pub is_outbound: bool,
    pub node_type: NodeType,
    pub protocol_version: String,
    pub software_version: String,
    pub peer_server_port: u16,
    // + creation_time, messages_sent/received, bytes_sent/received
}
```

### Reputation and banning

```rust
// Applied when a peer misbehaves. Accumulates; ban at 100 pts.
pub enum PenaltyReason {
    InvalidBlock,          // 100 pts — immediate ban
    InvalidAttestation,    // 50 pts
    ConsensusError,        // 100 pts — immediate ban
    Spam,                  // 25 pts
    ConnectionIssue,       // 10 pts
    ProtocolViolation,     // 50 pts
    RateLimitExceeded,     // 15 pts
}

pub struct PeerReputation {
    pub penalty_points: u32,
    pub is_banned: bool,
    pub ban_expiry: Option<u64>,
    pub ban_count: u32,
    pub avg_rtt_ms: Option<u64>,   // rolling RTT average from keepalive probes
    pub score: f64,                 // trust_score × (1 / avg_rtt_ms) — higher = better
    // ...
}
```

### Statistics

```rust
pub struct GossipStats {
    pub total_connections: usize,
    pub connected_peers: usize,
    pub inbound_connections: usize,
    pub outbound_connections: usize,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub known_addresses: usize,   // address manager size
    pub seen_messages: usize,     // dedup set occupancy
    pub relay_connected: bool,
    pub relay_peer_count: usize,
}

pub struct RelayStats {
    pub connected: bool,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub reconnect_attempts: u32,
    pub last_connected_at: Option<u64>,
    pub relay_peer_count: usize,
    pub latency_ms: Option<u64>,
}
```

### DIG-specific message types

DIG extends the Chia protocol with message IDs 200–219:

```rust
pub enum DigMessageType {
    NewAttestation             = 200,  // Critical priority
    NewCheckpointProposal      = 201,  // Critical priority
    NewCheckpointSignature     = 202,  // Critical priority
    RequestCheckpointSignatures= 203,  // Normal priority
    RespondCheckpointSignatures= 204,  // Normal priority
    RequestStatus              = 205,  // Normal priority
    RespondStatus              = 206,  // Normal priority
    NewCheckpointSubmission    = 207,
    ValidatorAnnounce          = 208,  // Bulk priority
    RequestBlockTransactions   = 209,  // compact-blocks feature
    RespondBlockTransactions   = 210,  // compact-blocks feature
    ReconciliationSketch       = 211,  // erlay feature
    ReconciliationResponse     = 212,  // erlay feature
    StemTransaction            = 213,  // dandelion feature
    PlumtreeLazyAnnounce       = 214,  // Plumtree protocol
    PlumtreePrune              = 215,  // Plumtree protocol
    PlumtreeGraft              = 216,  // Plumtree protocol
    PlumtreeRequestByHash      = 217,  // Plumtree protocol
    RegisterPeer               = 218,  // introducer registration
    RegisterAck                = 219,  // introducer registration ack
}
```

---

## Message Priority

Every outbound message is classified into one of three priority lanes:

| Priority | Message types | Behavior |
|----------|--------------|----------|
| **Critical** | `NewPeak`, `RespondBlock`, `NewAttestation`, `NewCheckpointProposal/Signature` | Sent first, never dropped |
| **Normal** | `NewTransaction`, `RequestBlock`, `NewUnfinishedBlock`, DIG status/sigs | Sent after critical; delayed under heavy load |
| **Bulk** | `RequestBlocks`, `RespondBlocks`, `RequestPeers`, `RespondPeers`, mempool sync | Sent last; dropped first under backpressure |

Starvation prevention: one bulk message is allowed through per `PRIORITY_STARVATION_RATIO`
(16) critical+normal messages so bulk queues cannot starve indefinitely.

---

## Errors — `GossipError`

```rust
pub enum GossipError {
    ClientError(ClientError),            // chia-sdk-client transport error
    ServiceNotStarted,                   // handle used before start() or after stop()
    AlreadyStarted,                      // start() called twice
    PeerBanned(PeerId),                  // connection rejected — peer is banned
    DuplicateConnection(PeerId),         // already connected to this peer
    MaxConnectionsReached(usize),        // max_connections cap hit
    SelfConnection,                      // tried to connect to own listen addr
    ConnectionFiltered(String),          // /16 or AS-diversity filter rejected
    DiscoveryError(String),              // DNS/introducer lookup failure
    RelayError(String),                  // relay connect/send failure
    ChannelClosed,                       // internal mpsc channel gone (service dead)
    Io(io::Error),
    // ...
}
```

---

## Feature Flags

| Flag | Default | Adds |
|------|---------|------|
| `native-tls` | ✓ | OS-native TLS (OpenSSL / Schannel / SecureTransport) |
| `rustls` | | Pure-Rust TLS alternative |
| `relay` | ✓ | `RelayConfig`, `RelayStats`, relay message forwarding |
| `erlay` | ✓ | `ErlayConfig`, `ErlayState`, `ReconciliationSketch` |
| `compact-blocks` | ✓ | `CompactBlock`, `ShortTxId`, `RequestBlockTransactions` |
| `dandelion` | ✓ | `DandelionConfig`, `StemTransaction` |
| `tor` | | `TorConfig`, SOCKS5 outbound, .onion inbound |

---

## Key Constants

```rust
DEFAULT_P2P_PORT             = 9444    // standard DIG/Chia P2P port
DEFAULT_RELAY_PORT           = 9450    // relay server port
DEFAULT_INTRODUCER_PORT      = 9448    // introducer server port
PENALTY_BAN_THRESHOLD        = 100     // penalty points → ban
BAN_DURATION_SECS            = 3600    // 1-hour ban default
PEER_TIMEOUT_SECS            = 90      // keepalive timeout
PING_INTERVAL_SECS           = 30      // keepalive probe interval
PARALLEL_CONNECT_BATCH_SIZE  = 8       // concurrent outbound connects
FEELER_INTERVAL_SECS         = 240     // average Poisson feeler interval
MAX_PEERS_RECEIVED_PER_REQUEST = 1000  // cap per RespondPeers
```

---

## Background tasks spawned by `start()`

| Task | Purpose |
|------|---------|
| **listener** | Accept inbound TLS+WebSocket connections |
| **discovery loop** | DNS seeds → introducer → bootstrap peers |
| **feeler loop** | Poisson-scheduled feeler probes (Sybil resistance) |
| **cleanup task** | Expire bans, remove stale connections, flush address manager |
| **relay reconnect** | Reconnect relay with exponential backoff |
| **per-connection keepalive** | Ping/pong RTT sampling + timeout enforcement |

---

## Discovery flow

1. `start()` spawns the discovery loop
2. Loop queries DNS seeds (`Network::lookup_all()`)
3. Falls back to configured introducer (`RequestPeersIntroducer`)
4. Filters candidates through `/16 subnet group` and `AS-level diversity` guards
5. Connects in parallel batches (`PARALLEL_CONNECT_BATCH_SIZE = 8`)
6. On connect: sends `RequestPeers`, feeds reply to `AddressManager`
7. Inbound listener relays peer addresses back to any live outbound peer

---

## Address Manager

`AddressManager` (Rust port of Bitcoin/Chia `CAddrMan`) maintains:
- **tried table**: 256 buckets × 64 slots — peers with successful connections
- **new table**: 1024 buckets × 64 slots — gossip-received candidates
- Persisted to `peers_file_path` on shutdown and loaded on start
- Selection uses randomized bucket keys for Sybil resistance

---

## Security notes

- **mTLS required** on all P2P connections — both peers present `ChiaCertificate`.
  `PeerId = SHA256(remote TLS cert public key)`.
- **Rate limiting** per connection: inherits Chia `V2_RATE_LIMITS` plus DIG extension
  message types (ids 200–219).
- **Ban system**: penalty points accumulate; 100 pts = 1-hour IP ban enforced at both
  Chia `ClientState` and DIG `ServiceState` levels.
- `#![forbid(unsafe_code)]` — no unsafe Rust in this crate.

---

## SPEC and requirements

| Document | Path |
|----------|------|
| Master specification | `docs/resources/SPEC.md` |
| Requirements by domain | `docs/requirements/README.md` |
| Implementation order | `docs/requirements/IMPLEMENTATION_ORDER.md` |
| Test files | `tests/{domain}_{nnn}_tests.rs` (flat layout) |
