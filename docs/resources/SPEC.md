# dig-gossip Specification

**Version:** 0.1.0
**Status:** Draft
**Date:** 2026-04-13

## 1. Overview

`dig-gossip` is a self-contained Rust crate that manages **peer-to-peer networking and gossip** for the DIG Network L2 blockchain. It handles peer discovery, connection management, message routing, and protocol-level communication between full nodes. The crate accepts application-level payloads (blocks, transactions, attestations) as opaque typed inputs and delivers them to connected peers via a Chia-compatible gossip protocol.

**This crate maximally reuses the Chia Rust ecosystem** rather than reimplementing functionality. The wire protocol types (`Handshake`, `Message`, `NodeType`, `ProtocolMessageTypes`), peer connection management (`Peer`, `Client`), rate limiting (`RateLimiter`, `RateLimits`), TLS handling, and DNS resolution are all provided by `chia-protocol` and `chia-sdk-client`. `dig-gossip` builds on top of these, adding: relay fallback, introducer registration, address manager persistence, gossip fanout, and message deduplication.

The gossip layer **does** perform:
- **Peer discovery** via introducer registration and querying, DNS seeding (using `chia-sdk-client`'s `Network::lookup_all()`), and peer exchange between connected nodes.
- **Connection management** — establishing connections via `chia-sdk-client`'s `Peer::connect()` and `connect_peer()`, maintaining connections with keepalive, and tearing down on timeout.
- **Relay fallback** — when direct P2P connections cannot be established (NAT, firewall), messages are routed through a relay server as a transparent fallback.
- **Structured gossip (Plumtree)** — eager/lazy push protocol that maintains a spanning tree for full-message push and uses lazy push (hash-only announcements) for redundancy, reducing bandwidth by 60-80% over Chia's naive flood-to-all approach.
- **Compact block relay** — blocks are propagated as header + short transaction IDs; receivers reconstruct from mempool, requesting only missing transactions. Reduces block propagation bandwidth by 90%+.
- **ERLAY-style transaction relay** — low-fanout flooding (announce to ~8 peers) combined with periodic set reconciliation (minisketch/IBLT) with remaining peers, reducing per-transaction bandwidth from O(connections) to O(1).
- **Message priority lanes** — consensus-critical messages (NewPeak, attestations, blocks) are sent ahead of bulk data (mempool sync, peer exchange, historical block requests), preventing head-of-line blocking.
- **Peer sharing** — exchanging known peer lists between connected nodes via `chia-protocol`'s `RequestPeers`/`RespondPeers`.
- **Rate limiting with adaptive backpressure** — using `chia-sdk-client`'s `RateLimiter` with `V2_RATE_LIMITS` for per-connection message rate enforcement, extended with adaptive backpressure that monitors outbound queue depth and selectively throttles non-critical messages under load.
- **Peer reputation with latency-aware scoring** — tracking peer behavior (valid/invalid messages, timeouts, protocol violations) with penalty-based banning, extending `chia-sdk-client`'s `ClientState` ban/trust model. Peers are scored by RTT (from Ping/Pong) and low-latency peers are preferred for outbound connections.
- **Address management with AS-level diversity** — maintaining tried/new peer address tables with bucket-based eviction, matching Chia's `AddressManager` (ported from Bitcoin's `CAddrMan`), enhanced with AS-level diversity (one outbound per autonomous system) for stronger eclipse attack resistance than Chia's /16 grouping.
- **Parallel connection establishment** — bootstrap connects to multiple peers concurrently rather than Chia's sequential one-at-a-time approach.
- **NAT traversal upgrade** — relay connections can be upgraded to direct P2P via STUN-style hole punching coordinated through the relay server.

The gossip layer does **not** perform:
- **Block validation** (CLVM execution, signature verification, consensus checks) — the caller validates payloads before broadcasting and after receiving.
- **Block production** (transaction selection, generator building).
- **Mempool management** (transaction ordering, fee estimation, conflict detection) — handled by `dig-mempool`.
- **Coinstate management** (coin record storage, state root computation) — handled by `dig-coinstore`.
- **Consensus** (fork choice, finality, validator set management, checkpoint aggregation).

The design is derived from Chia's production networking stack, primarily consumed through the **Chia Rust crates** rather than ported from the Python source:

**Chia Rust crates used directly (not reimplemented):**
- **`chia-protocol`** ([crates.io](https://crates.io/crates/chia-protocol)): Wire protocol types — `Handshake`, `Message`, `NodeType`, `ProtocolMessageTypes`, `RequestPeers`, `RespondPeers`, `RequestPeersIntroducer`, `RespondPeersIntroducer`, `NewPeak`, `NewTransaction`, `RequestTransaction`, `RespondTransaction`, `RequestBlock`, `RespondBlock`, `RequestBlocks`, `RespondBlocks`, `NewUnfinishedBlock`, `RequestUnfinishedBlock`, `RespondUnfinishedBlock`, `RequestMempoolTransactions`, `SpendBundle`, `FullBlock`, `Bytes32`, `ChiaProtocolMessage` trait.
- **`chia-sdk-client`** ([crates.io](https://crates.io/crates/chia-sdk-client)): Peer connection — `Peer` (WebSocket connection wrapper with `send()`, `request_raw()`, `request_infallible()`, `request_fallible()`), `Client`/`ClientState` (peer manager with ban/trust), `PeerOptions`, `Network` (DNS introducer lookup), `RateLimiter` (per-connection rate enforcement), `RateLimits`/`RateLimit` (rate limit tables), `V1_RATE_LIMITS`/`V2_RATE_LIMITS` (pre-configured Chia rate limits), `connect_peer()` (full handshake flow), `load_ssl_cert()`, `create_native_tls_connector()`/`create_rustls_connector()` (TLS setup), `ClientError`.
- **`chia-ssl`** ([crates.io](https://crates.io/crates/chia-ssl)): TLS certificates — `ChiaCertificate` (generate/load), `CHIA_CA_CRT` (Chia CA certificate).
- **`chia-traits`** ([crates.io](https://crates.io/crates/chia-traits)): Serialization — `Streamable` trait for wire format encoding/decoding.

**Chia Python source (reference for address manager and discovery loop logic):**
- **Peer discovery**: [`chia/server/node_discovery.py`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py)
- **Address manager**: [`chia/server/address_manager.py`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/address_manager.py) (Bitcoin `CAddrMan` port — no Rust equivalent exists)
- **Introducer peers**: [`chia/server/introducer_peers.py`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/introducer_peers.py)

**DIG-specific extensions (from `l2_driver_state_channel`):**
- **Relay client**: `l2_driver_state_channel/src/services/relay/client.rs`, `l2_driver_state_channel/src/services/relay/types.rs`
- **Introducer client**: `l2_driver_state_channel/src/services/network/introducer_client.rs`

**Hard boundary:** Inputs = application payloads (`Vec<u8>` or typed via `chia-protocol`'s `Streamable + ChiaProtocolMessage`) to broadcast/send. Outputs = received payloads delivered to the caller via async channels as `chia-protocol::Message`. Block validation, CLVM execution, mempool management, coinstate, and consensus are outside this crate. The gossip crate is **payload-agnostic** — it transports `Message`s between peers. The caller defines what those bytes mean.

### 1.1 Design Principles

- **Chia crate reuse over reimplementation**: Every type and behavior that exists in the Chia Rust crates (`chia-protocol`, `chia-sdk-client`, `chia-ssl`, `chia-traits`) is used directly. We do NOT redefine `Handshake`, `NodeType`, `Message`, `ProtocolMessageTypes`, `Peer`, `RateLimiter`, or TLS handling. We only implement what doesn't exist in the Chia ecosystem: address manager, discovery loop, relay fallback, introducer registration, gossip fanout, and message deduplication.
- **Chia protocol parity**: The handshake, message framing, peer exchange, and discovery protocols match Chia's networking protocol. `chia-protocol`'s `Handshake` struct is used directly with DIG-specific `network_id` and `capabilities` values.
- **Relay as transparent fallback**: When direct P2P fails (NAT, firewall), the relay server acts as a message proxy. The caller sees no difference — messages arrive through the same channel regardless of transport. Matches `l2_driver_state_channel/src/services/relay/service.rs`.
- **Introducer for bootstrap**: New nodes register with an introducer and query it for initial peers, matching Chia's `FullNodeDiscovery._introducer_client()` ([`node_discovery.py:173-184`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L173)) and `l2_driver_state_channel/src/services/network/introducer_client.rs`.
- **Payload-agnostic transport**: The gossip layer does not inspect or validate message payloads. It transports `chia-protocol::Message` envelopes between peers. The caller registers handlers for specific `ProtocolMessageTypes`.
- **Peer sharing via gossip**: Connected peers exchange peer lists periodically via `chia-protocol`'s `RequestPeers`/`RespondPeers` ([`full_node_protocol.py:207-216`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/protocols/full_node_protocol.py#L207)).
- **Address manager with tried/new tables**: Peer addresses are managed using the Bitcoin/Chia bucket-based address manager ([`address_manager.py`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/address_manager.py)), providing resistance to eclipse attacks. This is the one major component that must be ported to Rust — no Chia Rust crate provides it.

### 1.2 Crate Dependencies

| Crate | Purpose | Reuse vs New |
|-------|---------|-------------|
| `chia-protocol` | Wire protocol types: `Handshake`, `Message`, `NodeType`, `ProtocolMessageTypes`, `Bytes32`, `RequestPeers`, `RespondPeers`, `NewPeak`, `NewTransaction`, `SpendBundle`, `FullBlock`, all request/respond/reject types. `ChiaProtocolMessage` trait. | **Direct reuse** |
| `chia-sdk-client` | `Peer` (WebSocket connection), `Client`/`ClientState` (peer manager), `PeerOptions`, `Network` (DNS lookup), `RateLimiter`/`RateLimits` (rate limiting), `V2_RATE_LIMITS`, `connect_peer()` (handshake), TLS utilities. | **Direct reuse** |
| `chia-ssl` | `ChiaCertificate`, `CHIA_CA_CRT`. TLS certificate generation and loading. | **Direct reuse** |
| `chia-traits` | `Streamable` trait for wire serialization/deserialization. | **Direct reuse** |
| `tokio` | Async runtime. Timers, tasks, channels, TCP listeners. | Dependency |
| `tokio-tungstenite` | WebSocket (already a dependency of `chia-sdk-client`). | Transitive |
| `serde` / `bincode` | Serialization for relay protocol and address manager persistence. | Dependency |
| `serde_json` | JSON serialization for relay and introducer messages. | Dependency |
| `tracing` | Structured logging. | Dependency |
| `thiserror` | Error type derivation. | Dependency |
| `rand` | Randomized peer selection for gossip fanout and address manager bucket computation. | Dependency |
| `lru` | LRU set for message deduplication and message cache. | Dependency |
| `minisketch-rs` | Minisketch library for ERLAY set reconciliation. | Dependency |
| `siphasher` | SipHash for compact block short transaction IDs. | Dependency |

### 1.3 Design Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Reuse `chia-sdk-client::Peer` for connections | `Peer` already handles WebSocket TLS connections, message framing (4-byte length prefix), `Streamable` serialization, request/response correlation via message IDs, and outbound rate limiting. No reason to reimplement. |
| 2 | Reuse `chia-sdk-client::RateLimiter` + `V2_RATE_LIMITS` | Complete Chia-compatible rate limiting with V1/V2 limit tables. We extend with DIG-specific message types only. |
| 3 | Reuse `chia-protocol::Handshake` for connection setup | The handshake struct has `network_id`, `protocol_version`, `software_version`, `server_port`, `node_type`, `capabilities`. We pass DIG-specific values, not a new struct. `connect_peer()` handles the full handshake flow. |
| 4 | Reuse `chia-ssl` for TLS | `ChiaCertificate::generate()`, `load_ssl_cert()`, and `create_native_tls_connector()` / `create_rustls_connector()` already exist. |
| 5 | Reuse `chia-sdk-client::Network` for DNS seeding | `Network::lookup_all()` handles DNS resolution with timeout and batching. We configure with DIG DNS servers. |
| 6 | Port `AddressManager` from Python (no Rust crate exists) | Chia's `address_manager.py` is a Python port of Bitcoin's `CAddrMan`. No Rust equivalent exists in the Chia crate ecosystem. This must be ported. |
| 7 | Port discovery loop from Python (no Rust crate exists) | Chia's `node_discovery.py` discovery loop (introducer backoff, feeler connections, peer connect logic) has no Rust equivalent. This must be ported. |
| 8 | Relay as fallback, not primary | Direct P2P via `chia-sdk-client::Peer` is attempted first. Relay is used only when direct connection fails. Matches `l2_driver_state_channel/src/services/relay/types.rs` `RelayConfig::prefer_relay` default `false`. |
| 9 | DIG-specific `ProtocolMessageTypes` for extensions | Chia's `ProtocolMessageTypes` enum doesn't include DIG L2 messages (attestations, checkpoints). We define DIG extension types in a separate enum and map them to unused Chia message type IDs (200+). |
| 10 | `chia-sdk-client::ClientState` extended for reputation | `ClientState` provides basic ban/trust per IP. We extend with penalty-based reputation tracking per `PeerId`. |
| 11 | `std` only | Full-node networking infrastructure. No `no_std` support needed. |
| 12 | Plumtree structured gossip over naive flooding | Chia broadcasts to ALL connected peers. This is O(peers × messages). Plumtree maintains a spanning tree for eager push and uses lazy push (hash-only) for redundancy. Reduces bandwidth 60-80%. Critical for DIG L2's faster block times and higher attestation volume. |
| 13 | Compact block relay (BIP 152 equivalent) | Chia sends full `RespondBlock` (up to 2MB+). Most transactions are already in the receiver's mempool. Compact blocks send header + 6-byte short tx IDs; receiver reconstructs from mempool. Reduces block propagation bandwidth 90%+ and latency significantly. |
| 14 | ERLAY-style transaction relay | Chia announces `NewTransaction` to every peer. ERLAY uses low-fanout flooding (~8 peers) + periodic set reconciliation (minisketch/IBLT) with remaining peers. Per-transaction bandwidth drops from O(connections) to O(1). |
| 15 | Message priority lanes | Chia multiplexes all messages on one WebSocket. A 50MB `RespondBlocks` blocks a time-critical `NewPeak`. Priority lanes ensure consensus-critical messages (NewPeak, attestations, blocks) are sent before bulk data. |
| 16 | Parallel outbound connection establishment | Chia's `_connect_to_peers()` connects one at a time with `asyncio.sleep()` between attempts ([`node_discovery.py:244-349`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L244)). Batch parallel connects dramatically reduce bootstrap time. |
| 17 | Latency-aware peer scoring | Chia selects peers by address manager recency, not quality. Tracking RTT from Ping/Pong timestamps and preferring low-latency peers for outbound connections improves block/attestation propagation. |
| 18 | AS-level diversity over /16 grouping | Chia limits one outbound per IPv4 /16 ([`node_discovery.py:296-306`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L296)). An attacker controlling many /16s in one AS bypasses this. AS-level grouping provides stronger eclipse resistance. |
| 19 | Adaptive backpressure | Chia's rate limiter has fixed per-connection limits. Under mempool floods, no mechanism to throttle low-priority messages. Adaptive backpressure monitors outbound queue depth and selectively drops/delays non-critical traffic. |
| 20 | NAT traversal upgrade from relay | Relay connections are static in `l2_driver_state_channel`. STUN-style hole punching coordinated through the relay can upgrade relay connections to direct P2P, reducing relay load and latency. |

### 1.4 Chia Crate Type Mapping

Types used **directly** from Chia crates (NOT redefined in dig-gossip):

| Type | Source Crate | Usage in dig-gossip |
|------|-------------|-------------------|
| `Bytes32` | `chia-protocol` | Peer IDs, network IDs, message hashes |
| `Handshake` | `chia-protocol` | Connection handshake (populated with DIG values) |
| `Message` | `chia-protocol` | Wire-level message envelope (`msg_type`, `id`, `data`) |
| `NodeType` | `chia-protocol` | Node type discrimination (FullNode, Wallet, Introducer) |
| `ProtocolMessageTypes` | `chia-protocol` | Message type discriminant |
| `RequestPeers` / `RespondPeers` | `chia-protocol` | Peer exchange between full nodes |
| `RequestPeersIntroducer` / `RespondPeersIntroducer` | `chia-protocol` | Introducer peer queries |
| `NewPeak` | `chia-protocol` | Chain tip announcement |
| `NewTransaction` / `RequestTransaction` / `RespondTransaction` | `chia-protocol` | Transaction gossip |
| `RequestBlock` / `RespondBlock` / `RejectBlock` | `chia-protocol` | Block requests |
| `RequestBlocks` / `RespondBlocks` / `RejectBlocks` | `chia-protocol` | Bulk block requests |
| `NewUnfinishedBlock` / `RequestUnfinishedBlock` / `RespondUnfinishedBlock` | `chia-protocol` | Unfinished block gossip |
| `RequestMempoolTransactions` | `chia-protocol` | Mempool sync |
| `SpendBundle` | `chia-protocol` | Transaction payload |
| `FullBlock` | `chia-protocol` | Block payload |
| `TimestampedPeerInfo` | `chia-protocol` | Peer info in `RespondPeers` |
| `Peer` | `chia-sdk-client` | WebSocket connection wrapper |
| `PeerOptions` | `chia-sdk-client` | Connection options (rate_limit_factor) |
| `Client` / `ClientState` | `chia-sdk-client` | Peer connection manager with ban/trust |
| `Network` | `chia-sdk-client` | DNS introducer lookup |
| `RateLimiter` | `chia-sdk-client` | Per-connection rate limiting |
| `RateLimits` / `RateLimit` | `chia-sdk-client` | Rate limit configuration |
| `V2_RATE_LIMITS` | `chia-sdk-client` | Pre-configured Chia V2 rate limits |
| `connect_peer()` | `chia-sdk-client` | Full handshake + connect flow |
| `load_ssl_cert()` | `chia-sdk-client` | TLS certificate loading |
| `create_native_tls_connector()` | `chia-sdk-client` | TLS connector creation |
| `ClientError` | `chia-sdk-client` | Connection error types |
| `ChiaCertificate` | `chia-ssl` | TLS certificate generation |
| `Streamable` | `chia-traits` | Wire serialization trait |

### 1.5 Chia Behaviors Adopted (via crate reuse)

| # | Behavior | How Adopted | Reference |
|---|----------|-------------|-----------|
| 1 | Handshake with capabilities | `connect_peer()` sends `chia-protocol::Handshake` with capabilities list. | [`chia-sdk-client/src/connect.rs:20-32`](https://github.com/Chia-Network/chia-wallet-sdk) |
| 2 | V2 rate limiting | `chia-sdk-client::RateLimiter` with `V2_RATE_LIMITS` handles per-message-type frequency and size limits. | [`chia-sdk-client/src/rate_limits.rs`](https://github.com/Chia-Network/chia-wallet-sdk) |
| 3 | TLS mutual authentication | `chia-ssl::ChiaCertificate::generate()` + `create_native_tls_connector()` or `create_rustls_connector()`. | [`chia-sdk-client/src/tls.rs`](https://github.com/Chia-Network/chia-wallet-sdk) |
| 4 | Message framing | `chia-protocol::Message` uses `Streamable` for binary encoding. `Peer` handles WebSocket binary frames. | [`chia-protocol`](https://crates.io/crates/chia-protocol) |
| 5 | Request/response correlation | `Peer::request_raw()` assigns message IDs and waits for correlated responses via `RequestMap`. | [`chia-sdk-client/src/peer.rs:302-316`](https://github.com/Chia-Network/chia-wallet-sdk) |
| 6 | DNS seeding | `Network::lookup_all()` with timeout and batching. | [`chia-sdk-client/src/network.rs:40-68`](https://github.com/Chia-Network/chia-wallet-sdk) |
| 7 | Network ID validation | `connect_peer()` rejects peers with mismatched `network_id`. | [`chia-sdk-client/src/connect.rs:54-58`](https://github.com/Chia-Network/chia-wallet-sdk) |
| 8 | Peer ban/trust | `ClientState::ban()`, `ClientState::unban()`, `ClientState::trust()`, `ClientState::is_banned()`. | [`chia-sdk-client/src/client.rs:93-133`](https://github.com/Chia-Network/chia-wallet-sdk) |

### 1.6 Chia Behaviors Ported from Python (no Rust crate)

| # | Behavior | Description | Python Reference |
|---|----------|-------------|------------------|
| 1 | Peer exchange on outbound connect | After connecting, send `RequestPeers` to discover more peers. | [`node_discovery.py:135-136`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L135) |
| 2 | Inbound peer relay | When an inbound connection arrives, add peer to address manager and relay to other peers. | [`node_discovery.py:112-127`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L112) |
| 3 | Introducer client with exponential backoff | When address manager is empty, contact introducer. Backoff doubles up to 300s. | [`node_discovery.py:256-293`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L256) |
| 4 | DNS before introducer | DNS servers tried first (round-robin). Introducer as fallback. | [`node_discovery.py:270-277`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L270) |
| 5 | One outbound per /16 group | Eclipse attack resistance. | [`node_discovery.py:296-306`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L296) |
| 6 | Feeler connections (Poisson) | Periodic connections to vet "new" table addresses. 240s average interval. | [`node_discovery.py:167-171`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L167) |
| 7 | Timestamp update on message | Outbound peer timestamps updated in address manager on message receipt. | [`node_discovery.py:139-154`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L139) |
| 8 | AddressManager (tried/new tables) | Bitcoin `CAddrMan` port. Bucket-based eviction with collision resolution. | [`address_manager.py`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/address_manager.py) |
| 9 | VettedPeer tracking | Introducer tracks peers with vetting state. | [`introducer_peers.py:12-28`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/introducer_peers.py#L12) |
| 10 | MAX_PEERS_RECEIVED_PER_REQUEST (1000) | Caps peers accepted from a single `RespondPeers`. | [`node_discovery.py:34`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L34) |
| 11 | MAX_TOTAL_PEERS_RECEIVED (3000) | Caps total peers received across all requests. | [`node_discovery.py:35`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L35) |

### 1.7 DIG-Specific Extensions (not in Chia)

| # | Extension | Description |
|---|-----------|-------------|
| 1 | Relay server fallback | Nodes behind NAT/firewall can participate in gossip through a relay server. Chia has no relay. From `l2_driver_state_channel/src/services/relay/`. |
| 2 | Introducer registration | Nodes actively register with the introducer (IP, port, node_type), not just query it. Chia's introducer is query-only. From `l2_driver_state_channel/src/services/network/introducer_client.rs`. |
| 3 | DIG protocol message types | Attestation, checkpoint, and status messages (types 200+). |
| 4 | Inbound connection listener | `chia-sdk-client`'s `Peer` only does outbound connections. We add a `TcpListener` accepting inbound. |

### 1.8 Improvements Over Chia L1

| # | Improvement | Description | Impact |
|---|-------------|-------------|--------|
| 1 | **Plumtree structured gossip** | Chia floods every message to all connected peers. Plumtree maintains a spanning tree for eager push (full messages to tree neighbors) and lazy push (hash-only announcements to non-tree peers). Non-tree peers that don't receive the message within a timeout pull it via the hash. The tree self-heals: if a tree link fails, a lazy link is promoted. Based on the Plumtree protocol (Leitão et al., 2007). | **60-80% bandwidth reduction** vs naive flooding. Critical for DIG L2 with faster block times generating higher message volume. |
| 2 | **Compact block relay** | Chia sends full `RespondBlock` (up to 2MB+). Compact block relay sends: (a) block header, (b) short transaction IDs (6 bytes each, truncated SHA256), (c) prefilled transactions the sender predicts the receiver doesn't have. The receiver reconstructs the full block from its mempool using short IDs, and requests only missing transactions individually. Inspired by Bitcoin BIP 152. | **90%+ block propagation bandwidth reduction**. Latency drops from "full block transfer time" to "header + short IDs + missing tx round-trip." With DIG L2's faster block times, this prevents blocks from being the bandwidth bottleneck. |
| 3 | **ERLAY-style transaction relay** | Chia announces `NewTransaction` to every connected peer — each peer receives the announcement N times (once from each neighbor who has it). ERLAY (Naumenko et al., 2019) splits peers into: (a) **flood set** (~8 peers): receive immediate `NewTransaction` announcements, (b) **reconciliation set** (remaining peers): periodically reconcile transaction sets using minisketch (a compact sketch of set differences). On each reconciliation round, both peers compute a sketch of their transaction IDs, exchange sketches, and derive the symmetric difference to discover missing transactions. | **Per-transaction bandwidth drops from O(connections) to ~O(1)**. At 50 connections, this is a ~6x bandwidth reduction for transaction relay alone. Also reduces the rate of `NewTransaction` messages competing with block propagation. |
| 4 | **Message priority lanes** | Chia sends all messages through a single WebSocket with no prioritization. A 50MB `RespondBlocks` (bulk sync) blocks a 512-byte `NewPeak` (consensus-critical). Priority lanes assign each `ProtocolMessageType` to one of three priority levels, with separate outbound queues drained in priority order. | **Prevents consensus-critical latency spikes** during bulk sync or mempool floods. Block and attestation propagation latency becomes independent of bulk data transfer. |
| 5 | **Parallel connection establishment** | Chia's `_connect_to_peers()` connects to one peer at a time with `asyncio.sleep(select_peer_interval)` between attempts ([`node_discovery.py:244-349`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L244)). During bootstrap with an empty address manager, this means peers are connected one-by-one with multi-second gaps. Parallel establishment batches N connection attempts concurrently using `FuturesUnordered`. | **Bootstrap time reduced by Nx** (where N is the batch size). A node that needs 8 outbound connections goes from ~80 seconds (8 × 10s interval) to ~10 seconds. |
| 6 | **Latency-aware peer scoring** | Chia selects peers from the address manager based on bucket position and recency, not connection quality. Latency-aware scoring tracks RTT (measured from Ping/Pong timestamps already in the protocol) and computes a composite peer score: `score = trust_score × (1 / avg_rtt_ms)`. Outbound peer selection prefers higher-scored peers. The Plumtree spanning tree is also optimized to prefer low-latency links for eager push. | **Block and attestation propagation latency reduced** by routing through lower-latency paths. Particularly important for DIG L2 where attestation latency affects finality timing. |
| 7 | **AS-level diversity** | Chia limits one outbound connection per IPv4 /16 subnet ([`node_discovery.py:296-306`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L296)). An attacker controlling many /16 blocks within a single autonomous system can bypass this. AS-level grouping (one outbound per AS number) provides stronger eclipse attack resistance. AS numbers are resolved via a cached BGP prefix table (e.g., from routeviews or a compact local database). | **Stronger eclipse attack resistance** than /16 grouping. The /16 check is kept as a fast first-pass filter; AS-level check is the authoritative grouping. |
| 8 | **Adaptive backpressure** | Chia's `RateLimiter` enforces fixed per-message-type limits per connection. Under network-wide load (mempool flood, many new blocks), all messages compete equally for outbound bandwidth. Adaptive backpressure monitors the depth of the per-connection outbound queue and, when it exceeds a threshold: (a) drops duplicate transaction announcements, (b) delays non-critical messages (peer exchange, mempool sync), (c) preserves full throughput for priority-lane messages. | **Prevents cascading slowdowns** under peak load. Consensus-critical messages maintain target latency even when the network is flooded with transactions. |
| 9 | **NAT traversal upgrade** | Relay connections in `l2_driver_state_channel` are static — once on relay, always on relay. NAT traversal upgrade uses the relay as a signaling channel for STUN-style UDP hole punching. Procedure: (a) both peers register their observed external IP:port with the relay, (b) relay coordinates a simultaneous connection attempt, (c) if hole punching succeeds, traffic migrates to the direct connection and the relay path is dropped. Falls back to relay if hole punching fails. | **Reduces relay server load** by migrating successful hole-punches to direct P2P. Reduces latency for upgraded connections (relay adds 1 RTT). |
| 10 | **Dandelion++ transaction origin privacy** | Chia broadcasts transactions via gossip immediately, revealing the originator to all neighbors. Dandelion++ (Fanti et al., 2018) adds a **stem phase** before gossip: the transaction is forwarded along a single random path, each hop probabilistically deciding to continue stem or transition to fluff (normal gossip). This makes the originator indistinguishable from any node on the stem path. | **Transaction origin privacy**. An adversary observing the network cannot determine which node created a transaction, even if connected to many nodes. Critical for DIG L2 where transaction patterns may reveal validator strategies. |
| 11 | **Ephemeral PeerId rotation** | Chia's PeerId is permanent (derived from a static TLS certificate). An observer connecting to a node over time can track it across IP changes, sessions, and restarts. Ephemeral rotation generates a fresh `chia-ssl` certificate periodically, giving the node a new PeerId. The gossip layer doesn't need persistent identity — that's the consensus layer's job. | **Prevents long-term tracking** of nodes across sessions. A surveillance node connecting today and next month cannot link the two observations to the same physical node. |
| 12 | **Tor/SOCKS5 proxy transport** | Chia exposes node IP addresses to all connected peers. Tor transport routes connections through the Tor network, hiding the node's real IP entirely. Nodes can publish `.onion` addresses via the introducer and accept connections through Tor hidden services. | **IP address privacy**. The node's physical location and ISP are hidden from all peers. Feature-gated and opt-in — adds latency but provides strong anonymity for nodes that need it. |

### 1.9 Privacy Features

DIG gossip includes privacy-preserving features not present in Chia. These protect peer identity, transaction origin, and network topology from surveillance.

#### 1.9.1 Dandelion++ Transaction Origin Privacy

Chia broadcasts transactions immediately to all gossip peers, making the originator trivially identifiable — it's the first node to announce the transaction. Dandelion++ (Fanti et al., 2018) mitigates this by splitting transaction propagation into two phases:

**Stem phase (anonymous forwarding):**
- When a node creates or receives a stem-phase transaction, it forwards to **exactly one** randomly selected peer (the "stem relay").
- Each stem relay flips a weighted coin: with probability `DANDELION_FLUFF_PROBABILITY` (default 10%), transition to fluff phase. Otherwise, continue stem to the next random peer.
- Stem transactions are NOT added to the local mempool until fluff phase begins. This prevents the node from responding to `RequestTransaction` for a transaction it's only stemming — which would reveal it as being on the stem path.
- **Stem timeout**: If a stemmed transaction is not seen via fluff within `DANDELION_STEM_TIMEOUT_SECS` (default 30s), the holding node transitions it to fluff itself. This ensures liveness even if the stem path is broken.

**Fluff phase (normal gossip):**
- Once a node decides to fluff, the transaction enters normal Plumtree gossip (or ERLAY, depending on configuration).
- From this point, propagation is identical to a non-Dandelion transaction.

**Stem relay selection:**
- Each node maintains a single "stem relay" peer, re-randomized every `DANDELION_EPOCH_SECS` (default 600s / 10 minutes).
- Using a consistent relay per epoch (rather than per-transaction) creates a predictable routing topology that is harder to fingerprint than per-transaction random selection.

```rust
/// Dandelion++ configuration.
pub struct DandelionConfig {
    /// Enable Dandelion++ stem phase for outgoing transactions.
    /// Default: true.
    pub enabled: bool,
    /// Probability of transitioning from stem to fluff at each hop.
    /// Default: 0.10 (10%). Higher values = shorter stems = less privacy.
    pub fluff_probability: f64,
    /// Timeout before a stem transaction is force-fluffed (seconds).
    /// Default: 30.
    pub stem_timeout_secs: u64,
    /// Duration of a stem relay epoch (seconds).
    /// The stem relay peer is re-randomized at each epoch boundary.
    /// Default: 600 (10 minutes).
    pub epoch_secs: u64,
}
```

```
Transaction propagation with Dandelion++:

Node originates tx:
   │
   ├─ stem_relay = current epoch's random peer
   ├─ Send StemTransaction { tx, ttl: STEM_TIMEOUT } to stem_relay
   │
   stem_relay receives:
   │
   ├─ flip coin (10% fluff, 90% continue stem)
   ├─ if fluff:
   │      add tx to mempool
   │      broadcast via Plumtree/ERLAY (normal fluff)
   └─ if stem:
          forward StemTransaction to own stem_relay
          start stem_timeout timer
          if timeout expires without seeing fluff → force fluff
```

#### 1.9.2 Ephemeral PeerId Rotation

Chia's `PeerId` is derived from a permanent TLS certificate — the same node has the same identity forever. This enables long-term tracking: a surveillance node connecting to you today and next month knows it's the same physical node, even if your IP changed.

`dig-gossip` rotates certificates periodically to break this linkability:

- **On startup**: Generate a fresh `ChiaCertificate` via `chia-ssl` (or load existing if within the rotation window).
- **On rotation**: Every `PEER_ID_ROTATION_SECS` (default 86400 / 24 hours), generate a new certificate, disconnect all peers, and reconnect with the new identity.
- **Separation of concerns**: Network-layer identity (`PeerId` from TLS cert) is independent of consensus-layer identity (validator BLS keys). Rotating the network identity does not affect staking, attestation signing, or checkpoint participation.
- **Address manager**: Peers are tracked by `IP:port` in the address manager, not by `PeerId`. Certificate rotation does not cause address manager churn.
- **Opt-out**: Nodes that prefer a stable identity (e.g., well-known bootstrap nodes) can set `PEER_ID_ROTATION_SECS = 0` to disable rotation.

```rust
/// Ephemeral PeerId rotation configuration.
pub struct PeerIdRotationConfig {
    /// Enable periodic PeerId rotation.
    /// Default: true.
    pub enabled: bool,
    /// Rotation interval in seconds.
    /// Default: 86400 (24 hours). Set to 0 to disable.
    pub rotation_interval_secs: u64,
    /// Whether to reconnect to all peers after rotation.
    /// Default: true. If false, only new connections use the new identity.
    pub reconnect_on_rotation: bool,
}
```

#### 1.9.3 Tor/SOCKS5 Proxy Transport

For nodes requiring strong IP privacy, `dig-gossip` supports routing connections through the Tor network:

- **Outbound via Tor**: Connections are routed through a local SOCKS5 proxy (Tor daemon at `127.0.0.1:9050`). The destination peer sees only the Tor exit node's IP, not the connecting node's real IP.
- **Inbound via Tor hidden service**: The node publishes a `.onion` address via the introducer. Peers connect to the `.onion` address through Tor, reaching the node without knowing its IP.
- **Hybrid mode**: A node can accept both direct P2P connections and Tor connections simultaneously. Direct connections are faster; Tor connections are more private.
- **Feature-gated**: `tor` feature flag. Requires a running Tor daemon.
- **Latency tradeoff**: Tor adds 200-1000ms RTT. Nodes using Tor will have lower peer scores (RTT-based) and may not be selected as Plumtree eager peers.

```rust
/// Tor/SOCKS5 proxy configuration.
pub struct TorConfig {
    /// Enable Tor transport.
    /// Default: false.
    pub enabled: bool,
    /// SOCKS5 proxy address (Tor daemon).
    /// Default: "127.0.0.1:9050".
    pub socks5_proxy: String,
    /// Hidden service address (.onion) for inbound connections.
    /// If None, Tor is outbound-only.
    pub onion_address: Option<String>,
    /// Prefer Tor over direct connections.
    /// Default: false. If true, all outbound connections go through Tor.
    pub prefer_tor: bool,
}
```

**Transport selection with Tor:**
1. If `prefer_tor = true` → use Tor for all outbound connections.
2. If `prefer_tor = false` → try direct P2P first, then relay, then Tor.
3. For peers only reachable at `.onion` addresses → always use Tor.
4. Inbound `.onion` connections are accepted alongside direct inbound.

---

## 2. Data Model

### 2.1 Types Reused from Chia Crates

The following types are **re-exported** from Chia crates, not redefined:

```rust
// From chia-protocol
pub use chia_protocol::{
    Bytes32,
    Handshake,
    Message,
    NodeType,
    ProtocolMessageTypes,
    // Full node protocol messages
    NewPeak, NewTransaction, RequestTransaction, RespondTransaction,
    RequestBlock, RespondBlock, RejectBlock,
    RequestBlocks, RespondBlocks, RejectBlocks,
    NewUnfinishedBlock, RequestUnfinishedBlock, RespondUnfinishedBlock,
    RequestMempoolTransactions,
    RequestPeers, RespondPeers,
    RequestPeersIntroducer, RespondPeersIntroducer,
    // Payload types
    SpendBundle, FullBlock,
    // Peer info
    TimestampedPeerInfo,
};

// From chia-sdk-client
pub use chia_sdk_client::{
    Peer, PeerOptions,
    Client, ClientState,
    Network,
    RateLimiter, RateLimits, RateLimit,
    V2_RATE_LIMITS,
    ClientError,
    load_ssl_cert,
};

// From chia-ssl
pub use chia_ssl::ChiaCertificate;

// From chia-traits
pub use chia_traits::Streamable;
```

### 2.2 PeerId (type alias)

```rust
/// A unique identifier for a peer, derived from SHA256(TLS public key).
/// Uses `Bytes32` from `chia-protocol`.
pub type PeerId = Bytes32;
```

### 2.3 DIG Extension Message Types

For DIG L2-specific messages not in Chia's `ProtocolMessageTypes`:

```rust
/// DIG-specific protocol message type extensions.
/// These use message type IDs in the 200+ range to avoid collision
/// with Chia's ProtocolMessageTypes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DigMessageType {
    /// Attestation gossip (validator attestation for a block).
    NewAttestation = 200,
    /// Checkpoint proposal from epoch proposer.
    NewCheckpointProposal = 201,
    /// BLS signature for checkpoint aggregation.
    NewCheckpointSignature = 202,
    /// Checkpoint signature request.
    RequestCheckpointSignatures = 203,
    /// Checkpoint signature response.
    RespondCheckpointSignatures = 204,
    /// Status request.
    RequestStatus = 205,
    /// Status response.
    RespondStatus = 206,
    /// Checkpoint submission (after BLS aggregation).
    NewCheckpointSubmission = 207,
    /// Validator directory announcement.
    ValidatorAnnounce = 208,
}
```

### 2.4 PeerConnection (DIG extension of `chia-sdk-client::Peer`)

`chia-sdk-client::Peer` handles the WebSocket connection and message I/O. `PeerConnection` wraps it with additional metadata for the gossip layer.

```rust
/// Extended peer connection state for the gossip layer.
/// Wraps `chia-sdk-client::Peer` with gossip-specific metadata.
pub struct PeerConnection {
    /// The underlying chia-sdk-client Peer connection.
    pub peer: Peer,
    /// Unique peer identifier (SHA256 of TLS public key).
    pub peer_id: PeerId,
    /// Remote socket address.
    pub address: SocketAddr,
    /// Whether we initiated this connection (outbound) or they connected to us (inbound).
    pub is_outbound: bool,
    /// The peer's node type (from handshake).
    pub node_type: NodeType,
    /// The peer's protocol version (from handshake).
    pub protocol_version: String,
    /// The peer's software version (from handshake).
    pub software_version: String,
    /// The peer's advertised server port (from handshake).
    pub peer_server_port: u16,
    /// Negotiated capabilities.
    pub capabilities: Vec<(u16, String)>,
    /// Timestamp when connection was established (Unix seconds).
    pub creation_time: u64,
    /// Bytes read from this peer.
    pub bytes_read: u64,
    /// Bytes written to this peer.
    pub bytes_written: u64,
    /// Timestamp of last message received.
    pub last_message_time: u64,
    /// Peer reputation tracker (DIG extension).
    pub reputation: PeerReputation,
    /// Inbound message receiver for this connection.
    pub inbound_rx: mpsc::Receiver<Message>,
}
```

### 2.5 PeerReputation (DIG extension)

Extends `chia-sdk-client::ClientState`'s binary ban/trust with numeric penalties.

```rust
/// Reasons a peer can be penalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyReason {
    InvalidBlock,
    InvalidAttestation,
    MalformedMessage,
    Spam,
    ConnectionIssue,
    ProtocolViolation,
    RateLimitExceeded,
    ConsensusError,
}

/// Reputation tracking for a peer.
#[derive(Debug, Clone, Default)]
pub struct PeerReputation {
    /// Cumulative penalty points (higher = worse).
    pub penalty_points: u32,
    /// Whether this peer is temporarily banned.
    pub is_banned: bool,
    /// Ban expiry timestamp (Unix seconds).
    pub ban_until: Option<u64>,
    /// Last penalty reason.
    pub last_penalty_reason: Option<PenaltyReason>,
    /// Rolling average RTT in milliseconds (from Ping/Pong).
    /// Used for latency-aware peer selection and Plumtree tree optimization.
    pub avg_rtt_ms: Option<u64>,
    /// Recent RTT measurements (circular buffer, last RTT_WINDOW_SIZE pings).
    pub rtt_history: VecDeque<u64>,
    /// Composite peer score: trust_score × (1 / avg_rtt_ms).
    /// Higher = better. Used for outbound peer selection preference.
    pub score: f64,
    /// AS number for this peer's IP (cached from BGP lookup).
    pub as_number: Option<u32>,
}
```

### 2.6 ExtendedPeerInfo (Rust port of `address_manager.py:43`)

No Chia Rust crate provides this. Ported from [`address_manager.py:43-120`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/address_manager.py#L43).

```rust
/// Extended peer info for the address manager.
/// Rust port of Chia's ExtendedPeerInfo (address_manager.py:43).
pub struct ExtendedPeerInfo {
    pub peer_info: PeerInfo,
    pub timestamp: u64,
    pub src: PeerInfo,
    pub random_pos: Option<usize>,
    pub is_tried: bool,
    pub ref_count: u32,
    pub last_success: u64,
    pub last_try: u64,
    pub num_attempts: u32,
    pub last_count_attempt: u64,
}
```

### 2.7 PeerInfo (for address manager)

The address manager needs a `PeerInfo` type with `get_group()` and `get_key()` methods for bucket computation. `chia-protocol`'s `TimestampedPeerInfo` provides the wire format but not the bucket methods. This must be defined.

```rust
/// Resolved peer address with bucket computation methods.
/// Provides get_group() and get_key() for address manager bucketing.
/// Chia: peer_info.py:20-57.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    pub host: String,
    pub port: u16,
}

impl PeerInfo {
    /// Get the network group (/16 for IPv4, /32 for IPv6).
    /// Used for one-connection-per-group policy.
    /// Chia: peer_info.py:51-56.
    pub fn get_group(&self) -> Vec<u8>;

    /// Get a unique key for bucket computation.
    /// Chia: peer_info.py:43-49.
    pub fn get_key(&self) -> Vec<u8>;
}
```

### 2.8 VettedPeer (Rust port of `introducer_peers.py:12`)

No Chia Rust crate provides this. Ported from [`introducer_peers.py:12-28`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/introducer_peers.py#L12).

```rust
/// A peer tracked by the introducer with vetting status.
/// Rust port of Chia's VettedPeer (introducer_peers.py:12-28).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VettedPeer {
    pub host: String,
    pub port: u16,
    /// 0 = not vetted, negative = consecutive failures, positive = consecutive successes.
    pub vetted: i32,
    pub vetted_timestamp: u64,
    pub last_attempt: u64,
    pub time_added: u64,
}
```

### 2.9 RelayPeerInfo

Derived from `l2_driver_state_channel/src/services/relay/types.rs`. DIG-specific; not in Chia.

```rust
/// Peer info as tracked by the relay server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPeerInfo {
    pub peer_id: PeerId,
    pub network_id: Bytes32,
    pub protocol_version: u32,
    pub connected_at: u64,
    pub last_seen: u64,
}
```

### 2.10 GossipConfig

```rust
/// Configuration for the gossip service.
pub struct GossipConfig {
    /// Listen address for inbound P2P connections. Default: 0.0.0.0:9444.
    pub listen_addr: SocketAddr,
    /// Our peer ID.
    pub peer_id: PeerId,
    /// Network ID (e.g., SHA256("dig_mainnet")).
    pub network_id: Bytes32,
    /// Network config for DNS lookup (uses chia-sdk-client::Network).
    pub network: Network,
    /// Target number of outbound connections.
    /// Chia: node_discovery.py:49. Default: 8.
    pub target_outbound_count: usize,
    /// Maximum total connections. Default: 50.
    pub max_connections: usize,
    /// Bootstrap peer addresses.
    pub bootstrap_peers: Vec<SocketAddr>,
    /// Introducer configuration (optional).
    pub introducer: Option<IntroducerConfig>,
    /// Relay configuration (optional).
    pub relay: Option<RelayConfig>,
    /// TLS certificate paths.
    pub cert_path: String,
    pub key_path: String,
    /// Peer connect interval in seconds. Default: 10.
    pub peer_connect_interval: u64,
    /// Gossip fanout. Default: 8.
    pub gossip_fanout: usize,
    /// Max seen message hashes for dedup. Default: 100,000.
    pub max_seen_messages: usize,
    /// Path to persist address manager state.
    pub peers_file_path: PathBuf,
    /// Peer connection options (rate_limit_factor).
    pub peer_options: PeerOptions,
}
```

### 2.11 IntroducerConfig

From `l2_driver_state_channel/src/services/network/introducer_client.rs`. DIG-specific extension.

```rust
/// Introducer client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroducerConfig {
    /// Introducer endpoint (e.g., "ws://introducer.example.com:9448").
    pub endpoint: String,
    /// Connection timeout in seconds. Default: 10.
    pub connection_timeout_secs: u64,
    /// Request timeout in seconds. Default: 10.
    pub request_timeout_secs: u64,
    /// Network ID string. Default: "DIG_MAINNET".
    pub network_id: String,
}
```

### 2.12 RelayConfig

From `l2_driver_state_channel/src/services/relay/types.rs`. DIG-specific extension.

```rust
/// Relay client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Relay server endpoint (e.g., "wss://relay.example.com:9450").
    pub endpoint: String,
    /// Enable relay. Default: true (when endpoint set).
    pub enabled: bool,
    /// Connection timeout in seconds. Default: 10.
    pub connection_timeout_secs: u64,
    /// Reconnect delay in seconds. Default: 5.
    pub reconnect_delay_secs: u64,
    /// Max reconnect attempts. Default: 10.
    pub max_reconnect_attempts: u32,
    /// Ping interval in seconds. Default: 30.
    pub ping_interval_secs: u64,
    /// Prefer relay over direct. Default: false.
    pub prefer_relay: bool,
}
```

### 2.13 Constants

Only constants NOT already defined in Chia crates:

```rust
// -- Discovery (from Chia Python, no Rust equivalent) --

/// Max peers from a single RespondPeers. Chia: node_discovery.py:34.
pub const MAX_PEERS_RECEIVED_PER_REQUEST: usize = 1000;

/// Max total peers received. Chia: node_discovery.py:35.
pub const MAX_TOTAL_PEERS_RECEIVED: usize = 3000;

/// Max concurrent outbound connections. Chia: node_discovery.py:36.
pub const MAX_CONCURRENT_OUTBOUND_CONNECTIONS: usize = 70;

/// Poisson feeler interval (seconds). Chia: node_discovery.py:245.
pub const FEELER_INTERVAL_SECS: u64 = 240;

/// Parallel connection batch size for bootstrap.
pub const PARALLEL_CONNECT_BATCH_SIZE: usize = 8;

// -- Address Manager (from Chia Python, no Rust equivalent) --

pub const TRIED_BUCKETS_PER_GROUP: usize = 8;   // address_manager.py:24
pub const NEW_BUCKETS_PER_SOURCE_GROUP: usize = 64; // address_manager.py:25
pub const TRIED_BUCKET_COUNT: usize = 256;       // address_manager.py:26
pub const NEW_BUCKET_COUNT: usize = 1024;         // address_manager.py:27
pub const BUCKET_SIZE: usize = 64;                 // address_manager.py:28
pub const NEW_BUCKETS_PER_ADDRESS: usize = 8;     // address_manager.py:30
pub const HORIZON_DAYS: u32 = 30;                  // address_manager.py:33
pub const MAX_RETRIES: u32 = 3;                    // address_manager.py:34
pub const MIN_FAIL_DAYS: u32 = 7;                  // address_manager.py:35
pub const MAX_FAILURES: u32 = 10;                   // address_manager.py:36

// -- DIG-specific --

pub const DEFAULT_P2P_PORT: u16 = 9444;
pub const DEFAULT_RELAY_PORT: u16 = 9450;
pub const DEFAULT_INTRODUCER_PORT: u16 = 9448;
pub const DEFAULT_TARGET_OUTBOUND_COUNT: usize = 8;
pub const DEFAULT_MAX_SEEN_MESSAGES: usize = 100_000;
pub const PENALTY_BAN_THRESHOLD: u32 = 100;
pub const BAN_DURATION_SECS: u64 = 3600;
pub const PEER_TIMEOUT_SECS: u64 = 90;
pub const PING_INTERVAL_SECS: u64 = 30;

// -- Plumtree gossip --

/// Timeout before a lazily-announced message is pulled (ms).
pub const PLUMTREE_LAZY_TIMEOUT_MS: u64 = 500;

/// Message cache capacity for GRAFT responses.
pub const PLUMTREE_MESSAGE_CACHE_SIZE: usize = 1000;

/// Message cache TTL (seconds).
pub const PLUMTREE_MESSAGE_CACHE_TTL_SECS: u64 = 60;

// -- Compact block relay --

/// Short TX ID length in bytes.
pub const SHORT_TX_ID_BYTES: usize = 6;

/// Max missing transactions before falling back to full block request.
pub const COMPACT_BLOCK_MAX_MISSING_TXS: usize = 5;

// -- ERLAY transaction relay --

/// Number of peers to flood NewTransaction to immediately.
pub const ERLAY_FLOOD_PEER_COUNT: usize = 8;

/// Set reconciliation interval per peer (ms).
pub const ERLAY_RECONCILIATION_INTERVAL_MS: u64 = 2000;

/// Minisketch capacity (max decodable symmetric difference).
pub const ERLAY_SKETCH_CAPACITY: usize = 20;

/// Flood set re-randomization interval (seconds).
pub const ERLAY_FLOOD_SET_ROTATION_SECS: u64 = 60;

// -- Priority lanes / backpressure --

/// Queue depth at which duplicate tx announcements are suppressed.
pub const BACKPRESSURE_TX_DEDUP_THRESHOLD: usize = 25;

/// Queue depth at which Bulk messages are dropped.
pub const BACKPRESSURE_BULK_DROP_THRESHOLD: usize = 50;

/// Queue depth at which Normal messages are delayed.
pub const BACKPRESSURE_NORMAL_DELAY_THRESHOLD: usize = 100;

/// Starvation prevention: 1 bulk message per N critical/normal messages.
pub const PRIORITY_STARVATION_RATIO: usize = 10;

// -- Latency-aware scoring --

/// RTT measurement window (number of recent pings to average).
pub const RTT_WINDOW_SIZE: usize = 10;

/// Maximum acceptable RTT before peer score is penalized (ms).
pub const RTT_PENALTY_THRESHOLD_MS: u64 = 5000;

// -- Dandelion++ --

/// Probability of transitioning stem → fluff at each hop.
pub const DANDELION_FLUFF_PROBABILITY: f64 = 0.10;

/// Timeout before a stem transaction is force-fluffed (seconds).
pub const DANDELION_STEM_TIMEOUT_SECS: u64 = 30;

/// Duration of a stem relay epoch (seconds). Relay re-randomized each epoch.
pub const DANDELION_EPOCH_SECS: u64 = 600;

// -- Ephemeral PeerId rotation --

/// Default PeerId rotation interval (seconds). 24 hours.
pub const DEFAULT_PEER_ID_ROTATION_SECS: u64 = 86400;

// -- Tor --

/// Default SOCKS5 proxy address for Tor.
pub const DEFAULT_TOR_SOCKS5_PROXY: &str = "127.0.0.1:9050";
```

---

## 3. Public API

### 3.1 Construction

```rust
impl GossipService {
    /// Create a new gossip service with the given configuration.
    /// TLS is set up via chia-ssl (load_ssl_cert / ChiaCertificate::generate()).
    pub fn new(config: GossipConfig) -> Result<Self, GossipError>;
}
```

### 3.2 Lifecycle

```rust
impl GossipService {
    /// Start the gossip service: bind listener, start discovery, connect to
    /// bootstrap peers, start relay (if configured).
    pub async fn start(&self) -> Result<GossipHandle, GossipError>;

    /// Gracefully stop: disconnect all peers, stop discovery, close relay.
    pub async fn stop(&self) -> Result<(), GossipError>;
}
```

### 3.3 GossipHandle

```rust
/// Handle to a running gossip service. Cheaply cloneable (inner Arc).
#[derive(Clone)]
pub struct GossipHandle { /* ... */ }

impl GossipHandle {
    // -- Message sending --

    /// Broadcast a chia-protocol::Message to connected peers via gossip fanout.
    pub async fn broadcast(
        &self,
        message: Message,
        exclude: Option<PeerId>,
    ) -> Result<usize, GossipError>;

    /// Broadcast a typed Streamable + ChiaProtocolMessage.
    /// Serializes to Message internally using chia-traits::Streamable.
    pub async fn broadcast_typed<T: Streamable + ChiaProtocolMessage>(
        &self,
        body: T,
        exclude: Option<PeerId>,
    ) -> Result<usize, GossipError>;

    /// Send a message to a specific peer (via their chia-sdk-client::Peer).
    pub async fn send_to<T: Streamable + ChiaProtocolMessage>(
        &self,
        peer_id: PeerId,
        body: T,
    ) -> Result<(), GossipError>;

    /// Send a request and await a typed response (uses Peer::request_infallible).
    pub async fn request<T, B>(
        &self,
        peer_id: PeerId,
        body: B,
    ) -> Result<T, GossipError>
    where
        T: Streamable + ChiaProtocolMessage,
        B: Streamable + ChiaProtocolMessage;

    // -- Message receiving --

    /// Inbound message receiver. Each item is (sender_peer_id, chia-protocol::Message).
    pub fn inbound_receiver(&self) -> &mpsc::Receiver<(PeerId, Message)>;

    // -- Peer management --

    /// Get all connected peers with their extended state.
    pub async fn connected_peers(&self) -> Vec<PeerConnection>;

    /// Get number of connected peers.
    pub async fn peer_count(&self) -> usize;

    /// Get connections filtered by node type and direction.
    pub async fn get_connections(
        &self,
        node_type: Option<NodeType>,
        outbound_only: bool,
    ) -> Vec<PeerConnection>;

    /// Connect to a peer (uses chia-sdk-client::connect_peer internally).
    pub async fn connect_to(&self, addr: SocketAddr) -> Result<PeerId, GossipError>;

    /// Disconnect a peer.
    pub async fn disconnect(&self, peer_id: &PeerId) -> Result<(), GossipError>;

    /// Ban a peer (delegates to ClientState::ban + PeerReputation).
    pub async fn ban_peer(&self, peer_id: &PeerId, reason: PenaltyReason) -> Result<(), GossipError>;

    /// Apply a reputation penalty.
    pub async fn penalize_peer(&self, peer_id: &PeerId, reason: PenaltyReason) -> Result<(), GossipError>;

    // -- Discovery --

    /// Discover peers from introducer.
    pub async fn discover_from_introducer(&self) -> Result<Vec<TimestampedPeerInfo>, GossipError>;

    /// Register with introducer.
    pub async fn register_with_introducer(&self) -> Result<(), GossipError>;

    /// Request peers from a connected peer (sends chia-protocol::RequestPeers).
    pub async fn request_peers_from(&self, peer_id: &PeerId) -> Result<RespondPeers, GossipError>;

    // -- Stats --
    pub async fn stats(&self) -> GossipStats;
    pub async fn relay_stats(&self) -> Option<RelayStats>;
}
```

### 3.4 Statistics

```rust
#[derive(Debug, Clone, Default)]
pub struct GossipStats {
    pub total_connections: usize,
    pub connected_peers: usize,
    pub inbound_connections: usize,
    pub outbound_connections: usize,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub known_addresses: usize,
    pub seen_messages: usize,
    pub relay_connected: bool,
    pub relay_peer_count: usize,
}

#[derive(Debug, Clone, Default)]
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

---

## 4. Error Types

```rust
#[derive(Debug, Clone, thiserror::Error)]
pub enum GossipError {
    /// Wraps chia-sdk-client::ClientError for connection-level errors.
    #[error("client error: {0}")]
    ClientError(#[from] ClientError),

    #[error("peer not connected: {0}")]
    PeerNotConnected(PeerId),

    #[error("peer banned: {0}")]
    PeerBanned(PeerId),

    #[error("max connections reached ({0})")]
    MaxConnectionsReached(usize),

    #[error("duplicate connection to peer {0}")]
    DuplicateConnection(PeerId),

    #[error("self connection detected")]
    SelfConnection,

    #[error("request timeout")]
    RequestTimeout,

    #[error("introducer not configured")]
    IntroducerNotConfigured,

    #[error("introducer error: {0}")]
    IntroducerError(String),

    #[error("relay not configured")]
    RelayNotConfigured,

    #[error("relay error: {0}")]
    RelayError(String),

    #[error("service not started")]
    ServiceNotStarted,

    #[error("channel closed")]
    ChannelClosed,

    #[error("I/O error: {0}")]
    IoError(String),
}
```

---

## 5. Connection Lifecycle

### 5.1 Outbound Connection (reuses `chia-sdk-client`)

```
Outbound connection (uses connect_peer() from chia-sdk-client):
   │
   ├─ 1. Load TLS cert via load_ssl_cert() / ChiaCertificate::generate()
   ├─ 2. Create connector via create_native_tls_connector() or create_rustls_connector()
   ├─ 3. Call connect_peer(network_id, connector, socket_addr, options)
   │      → Internally: Peer::connect() → WebSocket TLS connect
   │      → Sends chia-protocol::Handshake with DIG network_id
   │      → Receives and validates Handshake response
   │      → Returns (Peer, mpsc::Receiver<Message>)
   ├─ 4. Wrap in PeerConnection with gossip metadata
   ├─ 5. Add peer to address manager
   ├─ 6. Send RequestPeers for discovery (node_discovery.py:135-136)
   └─ 7. Spawn per-connection message loop task

Relay fallback (when direct P2P fails):
   │
   ├─ 1. Connect to relay via WebSocket
   ├─ 2. Send Register { peer_id, network_id }
   ├─ 3. Relay messages transparently
   └─ 4. Inbound relay messages delivered to same channel
```

### 5.2 Inbound Connection

`chia-sdk-client`'s `Peer` only supports outbound connections. For inbound, we accept TCP/TLS connections and use `Peer::from_websocket()`:

```
Inbound connection:
   │
   ├─ 1. TcpListener::accept()
   ├─ 2. TLS handshake (using chia-ssl certificate)
   ├─ 3. tokio_tungstenite::accept_async()
   ├─ 4. Peer::from_websocket(ws, options)
   │      → Returns (Peer, mpsc::Receiver<Message>)
   ├─ 5. Receive Handshake, validate network_id
   ├─ 6. Send Handshake response
   ├─ 7. Wrap in PeerConnection
   ├─ 8. Add to address manager "new" table (node_discovery.py:120-125)
   └─ 9. Relay peer info (node_discovery.py:126-127)
```

### 5.3 Mandatory Mutual TLS (mTLS) via chia-ssl

**ALL peer-to-peer connections MUST use mutual TLS (mTLS).** Both the client and server present certificates and verify each other. This is a hard security requirement — unencrypted connections and server-only TLS are never permitted for P2P.

- **Mutual authentication**: Both sides of every P2P connection present a `chia-ssl` certificate. The connecting peer presents its certificate to the listener, and the listener presents its certificate to the connecting peer. Both sides extract `PeerId = SHA256(remote_certificate_public_key)` from the peer's presented certificate.
- **Certificate management**: Exclusively via `chia-ssl`. `ChiaCertificate::generate()` creates new node certificates on first run. `load_ssl_cert()` loads existing certificates on subsequent runs.
- **Outbound mTLS**: `create_native_tls_connector()` or `create_rustls_connector()` from `chia-sdk-client` creates a TLS connector that includes the node's own certificate (client cert) for mutual authentication. This connector is passed to `connect_peer()`.
- **Inbound mTLS**: The TLS acceptor is configured with `ssl.CERT_REQUIRED` (matching Chia's [`server.py:67`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/server.py#L67) `ssl_context.verify_mode = ssl.CERT_REQUIRED`). The listener requires the connecting peer to present a valid certificate. If the peer does not present a certificate, or if the TLS handshake fails, the connection is dropped.
- **Peer identity from mTLS**: `PeerId = SHA256(remote_TLS_certificate_public_key)`. Because mTLS guarantees both sides present certificates, each side can derive the other's `PeerId` from the certificate exchanged during the TLS handshake. This binds peer identity to cryptographic key material — impersonation requires possessing the private key. Matches Chia's `peer_node_id` derivation from certificate hash ([`ws_connection.py:95`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/ws_connection.py#L95)).
- **Self-signed certificates**: Expected (Chia model). Both connector and acceptor use `danger_accept_invalid_certs(true)` / skip CA chain validation — peer identity is verified by `PeerId` hash, not by a certificate authority. The Chia CA cert (`CHIA_CA_CRT` from `chia-ssl`) is used as a root but verification is relaxed for self-signed node certs.
- **No fallback**: If mTLS handshake fails for any reason (missing cert, expired cert, corrupt cert), the connection MUST be dropped. There is no fallback to plain WebSocket or server-only TLS.
- **Relay connections are separate**: Relay uses standard `wss://` TLS (server-only, not mTLS). Relay identity is verified by the relay server, not by mutual certificate exchange. The relay server does not participate in the `chia-ssl` mTLS system.

This matches Chia's mTLS design where both client and server present certificates ([`server.py:54-71`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/server.py#L54), [`server.py:67`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/server.py#L67) `verify_mode = ssl.CERT_REQUIRED`).

### 5.4 Rate Limiting

Uses `chia-sdk-client::RateLimiter` directly:

```rust
// Outbound: RateLimiter is built into Peer::send_raw()
// (it loops with 1s sleep until rate limit clears)

// Inbound: create a separate RateLimiter for each connection
let inbound_limiter = RateLimiter::new(
    true,   // incoming
    60,     // reset_seconds
    config.peer_options.rate_limit_factor,
    V2_RATE_LIMITS.clone(),
);

// For DIG extension messages, extend V2_RATE_LIMITS with additional entries
```

---

## 6. Peer Discovery

### 6.1 Overview

Uses `chia-sdk-client::Network::lookup_all()` for DNS resolution. The discovery loop and address manager are ported from Chia Python.

### 6.2 DNS Seeding (reuses `chia-sdk-client::Network`)

```rust
let network = Network {
    default_port: DEFAULT_P2P_PORT,
    genesis_challenge: dig_genesis_challenge,
    dns_introducers: vec!["dns-introducer.dignetwork.org".to_string()],
};

// Lookup peers from DNS (already handles timeout + batching)
let addrs = network.lookup_all(Duration::from_secs(30), 2).await;
```

### 6.3 Address Manager (Rust port, no crate exists)

Ported from [`address_manager.py`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/address_manager.py). This is the single largest piece of new code in the crate.

```rust
impl AddressManager {
    pub async fn create(peers_file_path: &Path) -> Result<Self, GossipError>;
    pub async fn add_to_new_table(&self, addrs: &[TimestampedPeerInfo], source: &PeerInfo, penalty: u64);
    pub async fn mark_good(&self, addr: &PeerInfo);
    pub async fn attempt(&self, addr: &PeerInfo, count_failure: bool);
    pub async fn connect(&self, addr: &PeerInfo);
    pub async fn select_peer(&self, new_only: bool) -> Option<ExtendedPeerInfo>;
    pub async fn select_tried_collision(&self) -> Option<ExtendedPeerInfo>;
    pub async fn resolve_tried_collisions(&self);
    pub async fn size(&self) -> usize;
    pub async fn save(&self);
}
```

### 6.4 Discovery Loop (Rust port, improved)

Ported from [`node_discovery.py:244-349`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L244) with the following improvements over Chia:

1. If address manager empty → DNS first (via `Network::lookup_all()`), then introducer with exponential backoff.
2. **Parallel connection establishment**: Select up to `PARALLEL_CONNECT_BATCH_SIZE` (8) peers from the address manager and connect concurrently using `FuturesUnordered`. Chia connects one at a time with `asyncio.sleep()` between attempts — this is N× faster for bootstrap.
3. **AS-level diversity** (improvement over Chia's /16 grouping): First check /16 group (fast filter), then verify AS number is unique among outbound connections. AS numbers resolved via cached BGP prefix table.
4. Feeler connections on Poisson schedule (240s average).
5. On successful connect → `mark_good()`. On failure → `attempt(count_failure=true)`.
6. **Latency-aware peer selection**: When multiple candidate peers pass the group/AS filter, prefer the one with the lowest average RTT from the peer scorer.

### 6.5 Introducer Client (DIG extension)

From `l2_driver_state_channel/src/services/network/introducer_client.rs`. Adds registration capability not in Chia.

**Query flow:** Connect → Handshake → `get_peers` → receive `peers` → close.
**Register flow:** Connect → Handshake → `register_peer { ip, port, node_type }` → receive `register_ack` → close.

### 6.6 Peer Exchange via Gossip

Uses `chia-protocol::RequestPeers` / `chia-protocol::RespondPeers` directly:

```rust
// Send RequestPeers via Peer::request_infallible
let respond: RespondPeers = peer.request_infallible(RequestPeers::new()).await?;
// respond.peer_list is Vec<TimestampedPeerInfo>
address_manager.add_to_new_table(&respond.peer_list, &peer_info, 0).await;
```

---

## 7. Relay Fallback

DIG-specific; not in Chia. See `l2_driver_state_channel/src/services/relay/`.

Relay messages use JSON over WebSocket (not Chia's binary protocol), matching the existing relay server implementation.

### 7.1 NAT Traversal Upgrade

Relay connections in `l2_driver_state_channel` are static. `dig-gossip` adds a NAT traversal upgrade path that can promote relay connections to direct P2P:

```
NAT traversal upgrade procedure:
   │
   ├─ 1. Both peers A and B are connected via relay
   ├─ 2. A sends HolePunchRequest to relay with its observed external IP:port
   ├─ 3. Relay forwards to B with A's external IP:port
   ├─ 4. B sends HolePunchResponse with its observed external IP:port
   ├─ 5. Relay coordinates simultaneous connection:
   │      A attempts connect to B's external IP:port
   │      B attempts connect to A's external IP:port
   ├─ 6. If either succeeds:
   │      Perform handshake on direct connection
   │      Migrate message traffic to direct connection
   │      Drop relay path for this peer pair
   └─ 7. If both fail:
          Keep relay path (no change)
          Retry after HOLE_PUNCH_RETRY_SECS (default 300)
```

**Relay messages for NAT traversal:**

```rust
/// Additional relay messages for NAT traversal.
pub enum RelayMessage {
    // ... existing variants ...

    /// Request NAT traversal assistance.
    HolePunchRequest {
        peer_id: PeerId,
        target_peer_id: PeerId,
        external_addr: SocketAddr,
    },
    /// NAT traversal coordination from relay.
    HolePunchCoordinate {
        peer_id: PeerId,
        external_addr: SocketAddr,
    },
    /// NAT traversal result.
    HolePunchResult {
        peer_id: PeerId,
        success: bool,
    },
}
```

---

## 8. Message Gossip

### 8.1 Plumtree Structured Gossip

Chia broadcasts every message to all connected peers (naive flooding). `dig-gossip` uses Plumtree (Leitão et al., 2007), a hybrid push/lazy push protocol that maintains a spanning tree over the peer overlay for efficient dissemination.

**Peer classification:**

Each connected peer is classified into one of two sets:

```rust
/// Plumtree peer classification for gossip routing.
pub struct PlumtreeState {
    /// Eager peers: receive full messages immediately (spanning tree neighbors).
    /// Default: all peers start as eager.
    pub eager_peers: HashSet<PeerId>,
    /// Lazy peers: receive hash-only announcements. Pull full message on demand.
    pub lazy_peers: HashSet<PeerId>,
    /// Pending lazy announcements (hash → timestamp) awaiting timeout.
    pub lazy_queue: HashMap<Bytes32, Vec<(PeerId, u64)>>,
    /// Missing message timer: if a lazily-announced hash isn't received
    /// eagerly within this timeout, pull from the lazy announcer.
    pub lazy_timeout_ms: u64,
}
```

**Broadcast algorithm (eager push + lazy push):**

```
broadcast(message: Message, origin: Option<PeerId>):
  1. hash = SHA256(message.msg_type || message.data)
  2. if seen_set.contains(hash) → return 0 (already seen)
  3. seen_set.insert(hash)
  4. Deliver to local inbound channel (application layer)
  5. For each peer in eager_peers (excluding origin):
       peer.send_raw(message)         // Full message via eager push
  6. For each peer in lazy_peers (excluding origin):
       peer.send_raw(LazyAnnounce { hash, msg_type })  // Hash-only
  7. If relay connected: relay.broadcast(message, exclude_list)
  8. Return count sent
```

**On receiving a message via eager push:**

```
on_eager_receive(from: PeerId, message: Message):
  1. hash = SHA256(message.msg_type || message.data)
  2. if seen_set.contains(hash):
       // Duplicate from eager peer → tree has a redundant link
       // Demote sender to lazy (prune tree edge)
       eager_peers.remove(from)
       lazy_peers.insert(from)
       send PRUNE to from
       return
  3. Process as new message (steps 2-7 of broadcast above)
  4. Cancel any pending lazy timer for this hash
```

**On receiving a lazy announcement:**

```
on_lazy_announce(from: PeerId, hash: Bytes32):
  1. if seen_set.contains(hash) → return (already have it)
  2. Start timer: lazy_queue.insert(hash, (from, now()))
  3. After lazy_timeout_ms, if hash still not received eagerly:
       send GRAFT + RequestByHash { hash } to from
       // Promote from to eager (repair tree)
       lazy_peers.remove(from)
       eager_peers.insert(from)
```

**On receiving PRUNE from peer:**

```
on_prune(from: PeerId):
  // Peer is telling us to stop eager-pushing to them
  eager_peers.remove(from)
  lazy_peers.insert(from)
```

**On receiving GRAFT from peer:**

```
on_graft(from: PeerId, hash: Bytes32):
  // Peer wants to be promoted back to eager
  lazy_peers.remove(from)
  eager_peers.insert(from)
  // If we have the message, send it
  if let Some(message) = message_cache.get(hash):
    peer.send_raw(message)
```

**Tree self-healing:** If an eager link fails (peer disconnects), lazy peers that have announced hashes we haven't received will be promoted to eager via GRAFT. The tree reconverges within one `lazy_timeout_ms` cycle.

**Message cache:** Recently broadcast messages are cached (LRU, capacity 1000) so they can be served in response to GRAFT requests. Cache entries expire after 60 seconds.

### 8.2 Compact Block Relay

Instead of sending full `RespondBlock` (up to 2MB+), compact block relay sends a lightweight representation that the receiver reconstructs from its mempool.

```rust
/// Compact block representation for efficient relay.
/// Inspired by Bitcoin BIP 152.
pub struct CompactBlock {
    /// Full block header.
    pub header: BlockHeader,
    /// Short transaction IDs (6 bytes each, truncated SipHash).
    /// Receiver matches against mempool to reconstruct full block.
    pub short_tx_ids: Vec<ShortTxId>,
    /// Prefilled transactions the sender predicts the receiver
    /// doesn't have (e.g., coinbase, very recent transactions).
    pub prefilled_txs: Vec<PrefilledTransaction>,
    /// SipHash key derived from block header hash (for short ID computation).
    pub sip_hash_key: [u8; 16],
}

/// 6-byte truncated SipHash of transaction ID.
pub type ShortTxId = [u8; 6];

/// A transaction included in the compact block directly.
pub struct PrefilledTransaction {
    /// Index in the block's transaction list.
    pub index: u16,
    /// Full serialized transaction.
    pub tx: Vec<u8>,
}
```

**Compact block relay protocol:**

```
Sender (has new block):
  1. Compute CompactBlock from full block
  2. Include coinbase + any txs added in last 2 seconds as prefilled
  3. Send CompactBlock to eager peers

Receiver:
  1. Receive CompactBlock
  2. For each short_tx_id:
     a. Compute SipHash of each mempool transaction with sip_hash_key
     b. Match against short_tx_ids
  3. Reconstruct full block from header + matched mempool txs + prefilled txs
  4. If any short_tx_ids unmatched:
     a. Send RequestBlockTransactions { block_hash, missing_indices }
     b. Receive RespondBlockTransactions { transactions }
     c. Reconstruct complete block
  5. Validate full block (caller responsibility)
```

**Short ID computation:** `short_tx_id = SipHash(sip_hash_key, tx_id)[0..6]`. The SipHash key is derived from the block header hash to prevent precomputed collision attacks. At 6 bytes, collision probability is ~1 in 2^48 per transaction pair.

**Fallback:** If compact block reconstruction fails (>5 missing transactions), fall back to requesting the full block via `RequestBlock`/`RespondBlock`.

### 8.3 ERLAY-Style Transaction Relay

Transaction relay is split into two mechanisms operating in parallel:

**1. Low-fanout flooding (immediate propagation):**
```
on_new_transaction(tx_id, cost, fees):
  1. Select ERLAY_FLOOD_PEERS (default 8) random connected peers
  2. Send NewTransaction { tx_id, cost, fees } to selected peers only
  3. Add tx_id to local reconciliation sketch
```

**2. Periodic set reconciliation (catch-up):**
```
every RECONCILIATION_INTERVAL_MS (default 2000ms) per peer:
  1. if peer not in flood_set:
     a. Compute minisketch of local tx_ids added since last reconciliation
     b. Send ReconciliationSketch { sketch, sketch_capacity }
     c. Receive peer's sketch
     d. Compute symmetric difference (XOR of sketches)
     e. Decode difference → set of tx_ids one side has but not the other
     f. Request missing tx_ids via RequestTransaction
     g. Send tx_ids the peer is missing via NewTransaction
```

```rust
/// Configuration for ERLAY-style transaction relay.
pub struct ErlayConfig {
    /// Number of peers to flood NewTransaction to immediately.
    /// Remaining peers use set reconciliation.
    /// Default: 8 (matching ERLAY paper recommendation).
    pub flood_peer_count: usize,
    /// Interval between reconciliation rounds per peer (ms).
    /// Default: 2000.
    pub reconciliation_interval_ms: u64,
    /// Minisketch capacity (max set difference decodable per round).
    /// Default: 20 (handles up to 20 tx difference per reconciliation).
    pub sketch_capacity: usize,
}
```

**Flood peer selection:** The flood set is re-randomized every 60 seconds. Inbound peers are never in the flood set (they initiate reconciliation with us). This matches ERLAY's design for optimal propagation latency.

### 8.4 Message Priority Lanes

Each `ProtocolMessageType` is assigned to a priority lane. Outbound messages are queued per-lane and drained in priority order.

```rust
/// Message priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    /// Consensus-critical: NewPeak, blocks, attestations.
    /// Always sent first. Never dropped by backpressure.
    Critical = 0,
    /// Normal protocol: transactions, unfinished blocks.
    /// Sent after critical. May be delayed under backpressure.
    Normal = 1,
    /// Bulk/background: mempool sync, peer exchange, historical block requests.
    /// Sent last. Dropped first under backpressure.
    Bulk = 2,
}
```

**Priority assignment:**

| Priority | Message Types |
|----------|--------------|
| **Critical** | `NewPeak`, `RespondBlock`, `RespondUnfinishedBlock`, DIG `NewAttestation`, DIG `NewCheckpointProposal`, DIG `NewCheckpointSignature` |
| **Normal** | `NewTransaction`, `RespondTransaction`, `NewUnfinishedBlock`, `RequestBlock`, `RequestTransaction`, `RequestUnfinishedBlock`, DIG `RequestStatus`/`RespondStatus` |
| **Bulk** | `RequestBlocks`, `RespondBlocks`, `RequestPeers`, `RespondPeers`, `RequestMempoolTransactions`, `RequestPeersIntroducer`, `RespondPeersIntroducer`, DIG `ValidatorAnnounce` |

**Outbound queue structure per connection:**

```rust
struct PriorityOutbound {
    critical: VecDeque<Message>,  // Drained first, always
    normal: VecDeque<Message>,    // Drained when critical is empty
    bulk: VecDeque<Message>,      // Drained when both above are empty
}

// Drain order: exhaust critical → exhaust normal → one bulk message → check critical again
```

**Starvation prevention:** Bulk messages are guaranteed at least 1 message per 10 critical/normal messages to prevent indefinite starvation during sustained high-priority load.

### 8.5 Adaptive Backpressure

When outbound queue depth exceeds thresholds, the gossip layer reduces non-critical traffic:

```rust
pub struct BackpressureConfig {
    /// Queue depth at which Normal messages start being delayed.
    /// Default: 100 messages.
    pub normal_delay_threshold: usize,
    /// Queue depth at which Bulk messages are dropped.
    /// Default: 50 messages.
    pub bulk_drop_threshold: usize,
    /// Queue depth at which duplicate transaction announcements are suppressed.
    /// Default: 25 messages.
    pub tx_dedup_threshold: usize,
}
```

**Behavior under backpressure:**

| Queue Depth | Action |
|-------------|--------|
| 0 - 25 | Normal operation. All messages sent. |
| 25 - 50 | Duplicate `NewTransaction` announcements suppressed (only first announcement per tx_id passes). |
| 50 - 100 | Bulk messages dropped silently. ERLAY reconciliation paused. |
| 100+ | Normal messages delayed (batched, sent every 500ms). Critical messages unaffected. |

### 8.6 Message Types Gossiped

All types are from `chia-protocol` (used directly, not reimplemented):

| Message | Source | Gossip Strategy | Description |
|---------|--------|----------------|-------------|
| `NewPeak` | `chia-protocol` | Plumtree eager/lazy | Chain tip announcement |
| `NewTransaction` | `chia-protocol` | ERLAY (flood 8 + reconcile) | Transaction announcement |
| `RespondTransaction` | `chia-protocol` | Unicast (on request) | Full `SpendBundle` |
| `RespondBlock` / `CompactBlock` | `chia-protocol` / DIG | Plumtree eager (compact) | Block relay |
| `NewUnfinishedBlock` | `chia-protocol` | Plumtree eager/lazy | Unfinished block hash |
| `RequestMempoolTransactions` | `chia-protocol` | Unicast | Mempool sync via bloom filter |
| `RespondPeers` | `chia-protocol` | Unicast (on request) | Peer list response |
| DIG `NewAttestation` | `DigMessageType` | Plumtree eager/lazy | Validator attestation |
| DIG `NewCheckpointProposal` | `DigMessageType` | Plumtree eager/lazy | Checkpoint proposal |
| DIG `NewCheckpointSignature` | `DigMessageType` | Plumtree eager/lazy | Checkpoint BLS signature |

---

## 9. Compatibility Notes

### 9.1 Crate Boundary

`dig-gossip` is a **library crate** (`lib`). It wraps `chia-sdk-client` and `chia-protocol` to provide a gossip layer. It does **not** include block validation, CLVM, mempool, coinstate, or consensus.

**Input**: `chia-protocol::Message` (or typed `T: Streamable + ChiaProtocolMessage`) via `broadcast()` / `send_to()`.
**Output**: `(PeerId, chia-protocol::Message)` via inbound channel receiver.

### 9.2 What dig-gossip Implements vs Reuses

| Component | Source | dig-gossip Role |
|-----------|--------|----------------|
| Wire protocol types | `chia-protocol` | **Reuse** (re-export) |
| Peer connection (WebSocket + TLS) | `chia-sdk-client::Peer` | **Reuse** |
| Handshake flow | `chia-sdk-client::connect_peer()` | **Reuse** |
| Rate limiting | `chia-sdk-client::RateLimiter` | **Reuse** + extend with DIG types |
| TLS certificates | `chia-ssl` + `chia-sdk-client` TLS utils | **Reuse** |
| DNS resolution | `chia-sdk-client::Network` | **Reuse** |
| Ban/trust management | `chia-sdk-client::ClientState` | **Reuse** + extend with reputation |
| Serialization | `chia-traits::Streamable` | **Reuse** |
| Address manager | Chia Python `address_manager.py` | **Port to Rust** (no crate exists) |
| Discovery loop | Chia Python `node_discovery.py` | **Port to Rust** (no crate exists) |
| Introducer peers | Chia Python `introducer_peers.py` | **Port to Rust** (no crate exists) |
| Inbound connection listener | New | **Implement** (`Peer::from_websocket` exists) |
| Relay fallback | `l2_driver_state_channel` | **Port/adapt** |
| Introducer registration | `l2_driver_state_channel` | **Port/adapt** |
| Plumtree structured gossip | New (based on Leitão et al., 2007) | **Implement** |
| Compact block relay | New (inspired by Bitcoin BIP 152) | **Implement** |
| ERLAY transaction relay | New (based on Naumenko et al., 2019) | **Implement** |
| Message priority lanes | New | **Implement** |
| Adaptive backpressure | New | **Implement** |
| Latency-aware peer scoring | New | **Implement** |
| AS-level diversity | New (extends address manager) | **Implement** |
| Parallel connection establishment | New (improves Chia's sequential loop) | **Implement** |
| NAT traversal upgrade | New (extends relay) | **Implement** |
| Message dedup (LRU set) | New | **Implement** |
| Peer reputation | New (extends `ClientState`) | **Implement** |
| Dandelion++ tx origin privacy | New (based on Fanti et al., 2018) | **Implement** |
| Ephemeral PeerId rotation | New | **Implement** |
| Tor/SOCKS5 proxy transport | New (uses `arti-client` / `tokio-socks`) | **Implement** (feature-gated) |

---

## 10. Crate Architecture

### 10.1 Module Structure

```
dig-gossip/
├── Cargo.toml
├── docs/
│   └── resources/
│       └── SPEC.md                    # This specification
├── src/
│   ├── lib.rs                         # Crate root: re-exports from chia crates + DIG types
│   │
│   ├── types/
│   │   ├── mod.rs                     # Re-exports
│   │   ├── peer.rs                    # PeerId (alias), PeerInfo (with get_group/get_key),
│   │   │                              #   PeerConnection (wraps chia-sdk-client::Peer)
│   │   ├── config.rs                  # GossipConfig, IntroducerConfig, RelayConfig
│   │   ├── stats.rs                   # GossipStats, RelayStats
│   │   ├── reputation.rs             # PeerReputation, PenaltyReason
│   │   └── dig_messages.rs           # DigMessageType enum (200+ range)
│   │
│   ├── constants.rs                   # DIG constants + ported Chia Python constants
│   ├── error.rs                       # GossipError (wraps ClientError)
│   │
│   ├── service/
│   │   ├── mod.rs
│   │   ├── gossip_service.rs          # GossipService (construction, start/stop)
│   │   └── gossip_handle.rs           # GossipHandle (broadcast, send_to, request, stats)
│   │
│   ├── connection/
│   │   ├── mod.rs
│   │   └── listener.rs                # TcpListener + TLS accept + Peer::from_websocket()
│   │                                  #   (chia-sdk-client::Peer handles the rest)
│   │
│   ├── discovery/
│   │   ├── mod.rs
│   │   ├── address_manager.rs         # Rust port of address_manager.py (no crate exists)
│   │   ├── address_manager_store.rs   # Persistent serialization for address manager
│   │   ├── node_discovery.rs          # Rust port of node_discovery.py discovery loop
│   │   ├── introducer_client.rs       # Introducer query + registration (DIG extension)
│   │   └── introducer_peers.rs        # VettedPeer, IntroducerPeers (port of introducer_peers.py)
│   │
│   ├── relay/
│   │   ├── mod.rs
│   │   ├── relay_client.rs            # Relay WebSocket client
│   │   ├── relay_service.rs           # Relay lifecycle with auto-reconnect
│   │   └── relay_types.rs             # RelayMessage, RelayPeerInfo, RelayConfig, RelayError
│   │
│   ├── gossip/
│   │   ├── mod.rs
│   │   ├── plumtree.rs                # Plumtree eager/lazy push state machine
│   │   ├── compact_block.rs           # Compact block encoding/decoding/reconstruction
│   │   ├── erlay.rs                   # ERLAY flood set + minisketch reconciliation
│   │   ├── priority.rs                # MessagePriority, PriorityOutbound queue
│   │   ├── backpressure.rs            # Adaptive backpressure monitor
│   │   ├── broadcaster.rs             # Top-level broadcast orchestration (delegates to plumtree/erlay)
│   │   ├── seen_set.rs                # LRU message deduplication
│   │   └── message_cache.rs           # LRU message cache for GRAFT responses
│   │
│   ├── privacy/
│   │   ├── mod.rs
│   │   ├── dandelion.rs               # Dandelion++ stem/fluff state machine
│   │   ├── peer_id_rotation.rs        # Ephemeral PeerId certificate rotation
│   │   └── tor.rs                     # Tor/SOCKS5 proxy transport
│   │
│   └── util/
│       ├── mod.rs
│       ├── ip_address.rs              # get_group(), get_key() for PeerInfo bucketing
│       ├── as_lookup.rs               # AS number lookup from cached BGP prefix table
│       └── latency.rs                 # RTT tracker, peer scoring
│
└── tests/
    ├── connection_tests.rs            # Handshake via connect_peer(), lifecycle
    ├── discovery_tests.rs             # Address manager, AS diversity, introducer, DNS
    ├── plumtree_tests.rs              # Eager/lazy push, tree formation, self-healing
    ├── compact_block_tests.rs         # Encoding, decoding, mempool reconstruction
    ├── erlay_tests.rs                 # Flood set, minisketch reconciliation
    ├── priority_tests.rs              # Priority lanes, drain order, starvation prevention
    ├── backpressure_tests.rs          # Threshold transitions, selective dropping
    ├── relay_tests.rs                 # Relay fallback, NAT traversal upgrade
    ├── rate_limit_tests.rs            # RateLimiter integration
    ├── reputation_tests.rs            # Penalty, ban/unban, latency scoring
    ├── dandelion_tests.rs             # Stem/fluff phases, epoch rotation, timeout fallback
    ├── peer_id_rotation_tests.rs      # Certificate rotation, reconnection, opt-out
    ├── tor_tests.rs                   # SOCKS5 proxy, .onion address, hybrid mode
    └── integration_tests.rs           # Multi-node gossip scenarios, bootstrap, full pipeline
```

### 10.2 Public Re-exports (`lib.rs`)

```rust
// =========================================================================
// Re-exports from Chia crates (NOT reimplemented)
// =========================================================================
pub use chia_protocol::{
    Bytes32, Handshake, Message, NodeType, ProtocolMessageTypes,
    NewPeak, NewTransaction, RequestTransaction, RespondTransaction,
    RequestBlock, RespondBlock, RejectBlock,
    RequestBlocks, RespondBlocks, RejectBlocks,
    NewUnfinishedBlock, RequestUnfinishedBlock, RespondUnfinishedBlock,
    RequestMempoolTransactions,
    RequestPeers, RespondPeers,
    RequestPeersIntroducer, RespondPeersIntroducer,
    SpendBundle, FullBlock, TimestampedPeerInfo,
    ChiaProtocolMessage,
};
pub use chia_sdk_client::{
    Peer, PeerOptions, Client, ClientState, Network,
    RateLimiter, RateLimits, RateLimit, V2_RATE_LIMITS,
    ClientError, load_ssl_cert,
};
pub use chia_ssl::ChiaCertificate;
pub use chia_traits::Streamable;

// =========================================================================
// DIG-specific types (implemented in this crate)
// =========================================================================
pub use types::peer::{PeerId, PeerInfo, PeerConnection};
pub use types::config::{GossipConfig, IntroducerConfig, RelayConfig};
pub use types::stats::{GossipStats, RelayStats};
pub use types::reputation::{PeerReputation, PenaltyReason};
pub use types::dig_messages::DigMessageType;

pub use service::gossip_service::GossipService;
pub use service::gossip_handle::GossipHandle;

pub use discovery::address_manager::AddressManager;
pub use discovery::introducer_client::IntroducerClient;
pub use discovery::introducer_peers::{IntroducerPeers, VettedPeer};

pub use relay::relay_types::{RelayPeerInfo, RelayMessage};

pub use error::GossipError;
pub use constants::*;
```

### 10.3 Feature Flags

```toml
[features]
default = ["native-tls", "relay", "erlay", "compact-blocks", "dandelion"]
native-tls = ["chia-sdk-client/native-tls"]    # Uses chia-sdk-client's native-tls feature
rustls = ["chia-sdk-client/rustls"]              # Uses chia-sdk-client's rustls feature
relay = []                                        # Relay fallback + NAT traversal support
erlay = ["minisketch-rs"]                         # ERLAY-style transaction relay with set reconciliation
compact-blocks = ["siphasher"]                    # Compact block relay (BIP 152 equivalent)
dandelion = []                                    # Dandelion++ transaction origin privacy
tor = ["arti-client", "tokio-socks"]             # Tor/SOCKS5 proxy transport (opt-in)
```

### 10.4 Cargo.toml Dependencies

```toml
[dependencies]
# Chia crates (direct reuse)
chia-protocol = "0.26"
chia-sdk-client = { version = "0.28", features = ["native-tls"] }
chia-ssl = "0.26"
chia-traits = "0.26"

# Async runtime
tokio = { version = "1", features = ["full"] }
tokio-tungstenite = "0.24"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
bincode = "1"

# Utilities
tracing = "0.1"
thiserror = "2"
rand = "0.8"
lru = "0.12"
siphasher = "1"

# ERLAY set reconciliation
minisketch-rs = "0.2"
```

---

## 11. Testing Strategy

### 11.1 Unit Tests

- **Address manager** (ported logic): add to new, promote to tried, bucket computation, eviction, collision, serialization round-trip, AS-level grouping.
- **VettedPeer**: vetting state transitions.
- **PeerInfo**: `get_group()` and `get_key()` correctness.
- **AS lookup**: correct AS number resolution from BGP prefix table, cache behavior, fallback to /16 on lookup failure.
- **PeerReputation**: penalty accumulation, ban threshold, auto-unban.
- **Latency scoring**: RTT tracking, window averaging, composite score computation, peer ranking.
- **Plumtree state machine**: eager→lazy demotion on duplicate, lazy→eager promotion on GRAFT, tree self-healing on peer disconnect, PRUNE handling.
- **Compact block**: encode/decode round-trip, short TX ID computation (SipHash), reconstruction from mempool (full match, partial match, fallback to full request).
- **ERLAY**: flood set selection, minisketch encode/decode round-trip, symmetric difference computation, reconciliation correctness (both peers converge), flood set rotation.
- **Priority lanes**: correct priority assignment per message type, drain order (critical → normal → bulk), starvation prevention (bulk gets 1 per N).
- **Backpressure**: threshold transitions, tx dedup suppression at 25+, bulk drop at 50+, normal delay at 100+, critical messages always pass.
- **Deduplication (LRU set)**: seen dropped, LRU eviction, unknown pass.
- **Message cache**: insert/get round-trip, TTL expiry, LRU eviction at capacity.
- **DigMessageType**: serialization round-trip, correct type IDs.
- **IntroducerConfig / RelayConfig**: defaults, builder patterns.

### 11.2 Integration Tests

- **connect_peer() integration**: connect two nodes using `chia-sdk-client::connect_peer()`, verify handshake with DIG `network_id`.
- **Peer::request_infallible() for RequestPeers**: verify `RespondPeers` round-trip.
- **Plumtree three-node gossip**: broadcast from A, B receives via eager, C receives via lazy→pull. Verify tree forms and self-heals.
- **Plumtree tree optimization**: verify that after initial convergence, eager peers are low-latency and redundant paths are pruned.
- **Compact block relay**: node A produces block, sends compact block to B, B reconstructs from mempool. Test with 0, 1, and 5+ missing transactions.
- **ERLAY reconciliation**: nodes A and B with overlapping mempool. After reconciliation round, both have the union. Verify bandwidth is less than flooding.
- **Priority lanes end-to-end**: during bulk sync (RespondBlocks), inject NewPeak — verify NewPeak arrives before bulk sync completes.
- **Backpressure under load**: flood node with transactions, verify bulk messages are dropped, critical messages still propagate at target latency.
- **Parallel bootstrap**: start node with 8 bootstrap peers, verify all 8 connections established concurrently (not sequentially).
- **Introducer flow**: mock introducer, verify registration and peer discovery.
- **Relay fallback**: mock relay, verify message delivery when direct P2P unavailable.
- **NAT traversal upgrade**: two nodes on relay, simulate successful hole punch, verify traffic migrates to direct connection.
- **Rate limiting**: verify `chia-sdk-client::RateLimiter` enforces limits on DIG message types.
- **Address manager persistence**: save, reload, verify peers restored.
- **AS-level diversity**: verify outbound connections span distinct AS numbers, reject second connection to same AS.

### 11.3 Benchmark Tests

- **Message throughput**: messages/second through `chia-sdk-client::Peer` (baseline from Chia crate).
- **Plumtree vs flood bandwidth**: measure total bytes transferred across 50-node network for 1000 messages. Target: Plumtree < 40% of naive flood.
- **Compact block vs full block**: measure bytes and latency for block propagation across 10 hops. Target: compact block < 10% bandwidth of full block.
- **ERLAY vs flood tx relay**: measure bytes per transaction across 50-connection node. Target: ERLAY < 20% of flood.
- **Priority lane latency**: measure NewPeak delivery latency during concurrent RespondBlocks transfer. Target: < 50ms p99.
- **Broadcast latency**: time for message to reach all peers in 50-node network via Plumtree.
- **Bootstrap time**: time to establish 8 outbound connections (parallel vs sequential). Target: < 15 seconds.
- **Address manager operations**: `select_peer()` latency with 10K addresses.
- **Minisketch encode/decode**: ops/second for sketch operations (target >100K/s).
- **Dedup throughput**: ops/second for seen_set (target >1M/s).

### 11.4 Property Tests

- **Gossip coverage**: every connected peer eventually receives every broadcast message (Plumtree convergence).
- **Plumtree tree invariant**: after stabilization, the eager peer graph forms a connected spanning tree (no partitions, no cycles in eager-only subgraph).
- **ERLAY convergence**: after one reconciliation round, the symmetric difference of both peers' tx sets is empty.
- **Compact block determinism**: same block + same SipHash key always produces identical CompactBlock.
- **Dedup correctness**: no message delivered twice to the same inbound channel.
- **Priority ordering**: no Bulk message is sent while a Critical message is queued.
- **Backpressure monotonicity**: as queue depth increases, restrictions only tighten (never loosen until depth decreases).
- **Address manager invariants**: no address in both tried and new, bucket sizes <= `BUCKET_SIZE`, at most one outbound per AS number.
