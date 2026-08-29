# dig-gossip Specification

**Version:** 0.1.0
**Status:** Draft
**Date:** 2026-04-13

## 1. Overview

`dig-gossip` is a self-contained Rust crate that manages **peer-to-peer networking and gossip** for the DIG Network L2 blockchain. It handles peer discovery, connection management, message routing, and protocol-level communication between full nodes. The crate accepts application-level payloads (blocks, transactions, attestations) as opaque typed inputs and delivers them to connected peers via a Chia-compatible gossip protocol.

**This crate maximally reuses the Chia Rust ecosystem** rather than reimplementing functionality, and it reaches that ecosystem through exactly one dependency: **`dig-peer-protocol`**. That crate re-exports the Chia wire types (`Handshake`, `NodeType`, `ProtocolMessageTypes`, `Streamable`, `ChiaCertificate`), the Chia peer-manager and TLS surface (`Client`/`ClientState`, `Connector`, `load_ssl_cert`, `create_native_tls_connector`/`create_rustls_connector`, `Network`), and supplies the DIG peer link itself — `DigLink`, framing a raw `u8` opcode so DIG's 200-222 extension band is expressible on the wire. `dig-gossip` builds on top of these, adding: relay fallback, introducer registration, address manager persistence, gossip fanout, and message deduplication.

The gossip layer **does** perform:
- **Peer discovery** via introducer registration and querying, DNS seeding (using `dig-peer-protocol`'s re-exported `Network::lookup_all()`), and peer exchange between connected nodes.
- **Connection management** — establishing WebSocket-over-mTLS peer links as `dig_peer_protocol::DigLink`, maintaining connections with keepalive, and tearing down on timeout.
- **Relay fallback** — when direct P2P connections cannot be established (NAT, firewall), messages are routed through a relay server as a transparent fallback.
- **Structured gossip (Plumtree)** — eager/lazy push protocol that maintains a spanning tree for full-message push and uses lazy push (hash-only announcements) for redundancy, reducing bandwidth by 60-80% over Chia's naive flood-to-all approach.
- **Compact block relay** — blocks are propagated as header + short transaction IDs; receivers reconstruct from mempool, requesting only missing transactions. Reduces block propagation bandwidth by 90%+.
- **ERLAY-style transaction relay** — low-fanout flooding (announce to ~8 peers) combined with periodic set reconciliation (minisketch/IBLT) with remaining peers, reducing per-transaction bandwidth from O(connections) to O(1).
- **Message priority lanes** — consensus-critical messages (NewPeak, attestations, blocks) are sent ahead of bulk data (mempool sync, peer exchange, historical block requests), preventing head-of-line blocking.
- **Peer sharing** — exchanging known peer lists between connected nodes via `chia-protocol`'s `RequestPeers`/`RespondPeers`.
- **Rate limiting with adaptive backpressure** — using `dig-peer-protocol`'s `OpcodeRateLimiter`, which enforces Chia's published `V2_RATE_LIMITS` table re-keyed by raw wire opcode, for per-connection message rate enforcement, extended with adaptive backpressure that monitors outbound queue depth and selectively throttles non-critical messages under load.
- **Peer reputation with latency-aware scoring** — tracking peer behavior (valid/invalid messages, timeouts, protocol violations) with penalty-based banning, extending the re-exported `ClientState` ban/trust model. Peers are scored by RTT (from Ping/Pong) and low-latency peers are preferred for outbound connections.
- **Address management with AS-level diversity** — maintaining tried/new peer address tables with bucket-based eviction, matching Chia's `AddressManager` (ported from Bitcoin's `CAddrMan`), enhanced with AS-level diversity (one outbound per autonomous system) for stronger eclipse attack resistance than Chia's /16 grouping.
- **Parallel connection establishment** — bootstrap connects to multiple peers concurrently rather than Chia's sequential one-at-a-time approach.
- **NAT traversal upgrade** — relay connections can be upgraded to direct P2P via STUN-style hole punching coordinated through the relay server.

The gossip layer does **not** perform:
- **Block validation** (CLVM execution, signature verification, consensus checks) — the caller validates payloads before broadcasting and after receiving.
- **Block production** (transaction selection, generator building).
- **Mempool management** (transaction ordering, fee estimation, conflict detection) — handled by `dig-mempool`.
- **Coinstate management** (coin record storage, state root computation) — handled by `dig-coinstore`.
- **Consensus** (fork choice, finality, validator set management, checkpoint aggregation).

The design is derived from Chia's production networking stack, primarily consumed through the **Chia Rust crates** rather than ported from the Python source. Those crates are reached through `dig-peer-protocol`, which re-exports them and adds the DIG extension band:

**`dig-peer-protocol`** ([crates.io](https://crates.io/crates/dig-peer-protocol)) — the sole owner of the peer link, and the path through which the client, TLS and DIG-extension surfaces are consumed:
- **DIG peer link** — `DigLink` (WebSocket peer link with `send_message()`, `send_protocol_message()`, `request_infallible()`, `request_fallible()`, `from_websocket()`, `from_server_websocket()`), `LinkOptions`, `LinkError`.
- **DIG wire envelope** — `DigMessage` (a `msg_type: u8` / `id: Option<u16>` / `data: Bytes` envelope, layout-identical to Chia's `Message` but with the discriminant left as a raw byte), `DigMessageType`, `Bytes`, and the opcode constants (`DIG_BAND_START`, `DIG_MESSAGE`, `HOLDINGS_ANNOUNCE`, `STORE_MELTED`, `PROFILE_ROOT_ANNOUNCE`, `PROFILE_BODY_REQUEST`, `PROFILE_BODY`, `ALL_DIG_OPCODES`, `is_dig_opcode`).
- **Introducer wire types** — `RegisterPeer`, `RegisterAck`, `RequestPeersIntroducer`, `RespondPeersIntroducer`.
- **Opcode-keyed rate limiting** — `OpcodeRateLimiter`, `OpcodeRateLimits`, `Admission`.
- **Re-exported Chia surface** — `ProtocolMessageTypes`, `ChiaProtocolMessage`, `TimestampedPeerInfo`, `Streamable`, `ChiaCertificate`, `NodeType`, `Network`, `Client`/`ClientState`, `Connector`, `RateLimit`, `load_ssl_cert`, `create_native_tls_connector`/`create_rustls_connector`, `ClientError`.

**Chia Rust crates used directly (not reimplemented).** They arrive by two different routes, and the
distinction is normative because it decides what a reimplementation must declare in its own manifest:
`chia-protocol` and `chia-traits` are **direct dependencies** of this crate (`Cargo.toml`; the wire
types are re-exported straight from `chia_protocol` — see `src/lib.rs`), while `chia-sdk-client` and
`chia-ssl` are reached **transitively**, through `dig-peer-protocol`'s re-exports above, and are not
declared here at all.
- **`chia-protocol`** ([crates.io](https://crates.io/crates/chia-protocol)): Wire protocol types — `Handshake`, `NodeType`, `ProtocolMessageTypes`, `RequestPeers`, `RespondPeers`, `RequestPeersIntroducer`, `RespondPeersIntroducer`, `NewPeak`, `NewTransaction`, `RequestTransaction`, `RespondTransaction`, `RequestBlock`, `RespondBlock`, `RequestBlocks`, `RespondBlocks`, `NewUnfinishedBlock`, `RequestUnfinishedBlock`, `RespondUnfinishedBlock`, `RequestMempoolTransactions`, `SpendBundle`, `FullBlock`, `Bytes32`, `ChiaProtocolMessage` trait.
- **`chia-sdk-client`** ([crates.io](https://crates.io/crates/chia-sdk-client)): `Client`/`ClientState` (peer manager with ban/trust), `Network` (DNS introducer lookup), `RateLimit` (rate-limit table row), `load_ssl_cert()`, `create_native_tls_connector()`/`create_rustls_connector()` (TLS setup), `ClientError`. Consumed through `dig-peer-protocol`'s re-exports, never as a direct dependency. The peer connection itself is `dig_peer_protocol::DigLink`, not this crate's `Peer`.
- **`chia-ssl`** ([crates.io](https://crates.io/crates/chia-ssl)): TLS certificates — `ChiaCertificate` (generate/load), `CHIA_CA_CRT` (Chia CA certificate). Consumed through `dig-peer-protocol`'s re-exports, never as a direct dependency.
- **`chia-traits`** ([crates.io](https://crates.io/crates/chia-traits)): Serialization — `Streamable` trait for wire format encoding/decoding. A direct dependency.

**Chia Python source (reference for address manager and discovery loop logic):**
- **Peer discovery**: [`chia/server/node_discovery.py`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py)
- **Address manager**: [`chia/server/address_manager.py`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/address_manager.py) (Bitcoin `CAddrMan` port — no Rust equivalent exists)
- **Introducer peers**: [`chia/server/introducer_peers.py`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/introducer_peers.py)

**DIG-specific extensions (from `l2_driver_state_channel`):**
- **Relay client**: `l2_driver_state_channel/src/services/relay/client.rs`, `l2_driver_state_channel/src/services/relay/types.rs`
- **Introducer client**: `l2_driver_state_channel/src/services/network/introducer_client.rs`

**Hard boundary:** Inputs = application payloads (`Vec<u8>` or typed via `chia-protocol`'s `Streamable + ChiaProtocolMessage`) to broadcast/send. Outputs = received payloads delivered to the caller via async channels as `dig_peer_protocol::DigMessage`. Block validation, CLVM execution, mempool management, coinstate, and consensus are outside this crate. The gossip crate is **payload-agnostic** — it transports `dig_peer_protocol::DigMessage` envelopes between peers. The caller defines what those bytes mean. It does **not** transport `chia_protocol::Message`: that type's discriminant is a closed `#[repr(u8)]` enum which cannot name a DIG opcode, and a reimplementation that builds on it will reject every frame in the DIG 200-222 band at decode time.

### 1.1 Design Principles

- **Chia crate reuse over reimplementation**: Every type and behavior that exists in the Chia Rust crates (`chia-protocol`, `chia-sdk-client`, `chia-ssl`, `chia-traits`) is used as-is — the wire types from `chia-protocol`/`chia-traits` directly, the client and TLS surfaces via `dig-peer-protocol`'s re-exports. We do NOT redefine `Handshake`, `NodeType`, `ProtocolMessageTypes`, `ClientState`, or TLS handling. We only implement what doesn't exist upstream: address manager, discovery loop, relay fallback, introducer registration, gossip fanout, and message deduplication.
- **One dependency for the peer wire**: `dig-peer-protocol` is the sole owner of the peer link and the sole path to the client/TLS surfaces. `dig-gossip` MUST NOT depend on `chia-sdk-client` or `chia-ssl` directly, and MUST NOT vendor or patch a Chia crate. It MAY depend on `chia-protocol`/`chia-traits` directly, and does — they carry only wire *types*, not a transport, so a direct dependency cannot reintroduce a second peer link. Chia's `ProtocolMessageTypes` is a closed `#[repr(u8)]` enum that cannot name a DIG opcode; `DigLink` frames a raw `u8` instead, so the DIG 200-222 band needs no fork of the Chia types.
- **Chia protocol parity**: The handshake, message framing, peer exchange, and discovery protocols match Chia's networking protocol. `chia-protocol`'s `Handshake` struct is used directly with DIG-specific `network_id` and `capabilities` values.
- **Relay as transparent fallback**: When direct P2P fails (NAT, firewall), the relay server acts as a message proxy. The caller sees no difference — messages arrive through the same channel regardless of transport. Matches `l2_driver_state_channel/src/services/relay/service.rs`.
- **Introducer for bootstrap**: New nodes register with an introducer and query it for initial peers, matching Chia's `FullNodeDiscovery._introducer_client()` ([`node_discovery.py:173-184`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L173)) and `l2_driver_state_channel/src/services/network/introducer_client.rs`.
- **Payload-agnostic transport**: The gossip layer does not inspect or validate message payloads. It transports `dig_peer_protocol::DigMessage` envelopes between peers. The caller registers handlers keyed by the envelope's raw `msg_type` opcode.
- **Peer sharing via gossip**: Connected peers exchange peer lists periodically via `chia-protocol`'s `RequestPeers`/`RespondPeers` ([`full_node_protocol.py:207-216`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/protocols/full_node_protocol.py#L207)).
- **Address manager with tried/new tables**: Peer addresses are managed using the Bitcoin/Chia bucket-based address manager ([`address_manager.py`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/address_manager.py)), providing resistance to eclipse attacks. This is the one major component that must be ported to Rust — no Chia Rust crate provides it.

### 1.2 Crate Dependencies

| Crate | Purpose | Reuse vs New |
|-------|---------|-------------|
| `chia-protocol` | Wire protocol types: `Handshake`, `NodeType`, `ProtocolMessageTypes`, `Bytes32`, `RequestPeers`, `RespondPeers`, `NewPeak`, `NewTransaction`, `SpendBundle`, `FullBlock`, all request/respond/reject types. `ChiaProtocolMessage` trait. | **Direct reuse** |
| `dig-peer-protocol` | `DigLink` (WebSocket peer link), `LinkOptions`, `DigMessage`/`DigMessageType`, the DIG opcode constants, the introducer wire types, `OpcodeRateLimiter`/`OpcodeRateLimits`, and the re-exported Chia surface below. | **Direct dependency** |
| `chia-sdk-client` | `Client`/`ClientState` (peer manager), `Network` (DNS lookup), `RateLimit`, `ClientError`, TLS utilities. | **Transitive**, via `dig-peer-protocol` re-exports |
| `chia-ssl` | `ChiaCertificate`, `CHIA_CA_CRT`. TLS certificate generation and loading. | **Transitive**, via `dig-peer-protocol` re-exports |
| `chia-traits` | `Streamable` trait for wire serialization/deserialization. | **Direct reuse** |
| `tokio` | Async runtime. Timers, tasks, channels, TCP listeners. | Dependency |
| `tokio-tungstenite` | WebSocket (also a dependency of `dig-peer-protocol`). | Dependency |
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
| 1 | Reuse `dig_peer_protocol::DigLink` for connections | `DigLink` handles WebSocket TLS connections, message framing (4-byte length prefix), `Streamable` serialization, request/response correlation via message IDs, and outbound rate limiting — and, unlike Chia's `Peer`, frames the discriminant as a raw `u8`, so the DIG 200-222 band travels on a stock envelope. No reason to reimplement. |
| 2 | Reuse `dig_peer_protocol::OpcodeRateLimiter` | Chia-compatible rate limiting: `OpcodeRateLimits` carries Chia's published `V2_RATE_LIMITS` rows re-keyed by raw wire opcode. The DIG per-opcode table is keyed by the same raw byte and is dig-gossip's own (`DigRateLimiter`), composed with the Chia bound rather than merged into it. |
| 3 | Reuse `chia-protocol::Handshake` for connection setup | The handshake struct has `network_id`, `protocol_version`, `software_version`, `server_port`, `node_type`, `capabilities`. We pass DIG-specific values, not a new struct. The outbound module drives the handshake exchange over the raw WebSocket before upgrading to `DigLink`. |
| 4 | Reuse `chia-ssl` for TLS | `ChiaCertificate::generate()`, `load_ssl_cert()`, and `create_native_tls_connector()` / `create_rustls_connector()` already exist. |
| 5 | Reuse the re-exported `Network` for DNS seeding | `Network::lookup_all()` handles DNS resolution with timeout and batching. We configure with DIG DNS servers. |
| 6 | Port `AddressManager` from Python (no Rust crate exists) | Chia's `address_manager.py` is a Python port of Bitcoin's `CAddrMan`. No Rust equivalent exists in the Chia crate ecosystem. This must be ported. |
| 7 | Port discovery loop from Python (no Rust crate exists) | Chia's `node_discovery.py` discovery loop (introducer backoff, feeler connections, peer connect logic) has no Rust equivalent. This must be ported. |
| 8 | Relay as fallback, not primary | Direct P2P via `DigLink` is attempted first. Relay is used only when direct connection fails. Matches `l2_driver_state_channel/src/services/relay/types.rs` `RelayConfig::prefer_relay` default `false`. |
| 9 | DIG opcodes travel as raw bytes, never as `ProtocolMessageTypes` | Chia's `ProtocolMessageTypes` enum doesn't include DIG L2 messages (attestations, checkpoints), and it is a closed `#[repr(u8)]` enum, so a DIG discriminant is not representable in it. `dig_peer_protocol::DigMessageType` names the DIG extension opcodes (200-222, an unused band upstream — Chia's highest is `RespondCostInfo = 107`) and `DigMessage` carries the discriminant as a raw `u8`. No Chia type is forked, extended, or renumbered. |
| 10 | The re-exported `ClientState` extended for reputation | `ClientState` provides basic ban/trust per IP. We extend with penalty-based reputation tracking per `PeerId`. |
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
| `DigMessage` | `dig-peer-protocol` | Wire-level message envelope (`msg_type: u8`, `id`, `data`) — layout-identical to Chia's `Message`, with the discriminant left as a raw byte so DIG opcodes 200-222 are expressible |
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
| `DigLink` | `dig-peer-protocol` | WebSocket peer link (client and server side) |
| `LinkOptions` | `dig-peer-protocol` | Link options (rate-limit factor, budget timeout) |
| `DigMessageType` | `dig-peer-protocol` | DIG extension opcode names (200-222) |
| `OpcodeRateLimiter` / `OpcodeRateLimits` | `dig-peer-protocol` | Chia's rate-limit table re-keyed by raw wire opcode |
| `RegisterPeer` / `RegisterAck` / `RequestPeersIntroducer` / `RespondPeersIntroducer` | `dig-peer-protocol` | Introducer wire types |
| `Client` / `ClientState` | `chia-sdk-client`, re-exported by `dig-peer-protocol` | Peer connection manager with ban/trust |
| `Network` | `chia-sdk-client`, re-exported by `dig-peer-protocol` | DNS introducer lookup |
| `RateLimits` / `RateLimit` / `V2_RATE_LIMITS` | `chia-sdk-client`, re-exported by `dig-peer-protocol` | Chia's published rate-limit configuration |
| `load_ssl_cert()` | `chia-sdk-client`, re-exported by `dig-peer-protocol` | TLS certificate loading |
| `create_native_tls_connector()` / `create_rustls_connector()` | `chia-sdk-client`, re-exported by `dig-peer-protocol` | TLS connector creation |
| `ClientError` | `chia-sdk-client`, re-exported by `dig-peer-protocol` | Connection error types |
| `ChiaCertificate` | `chia-ssl`, re-exported by `dig-peer-protocol` | TLS certificate generation |
| `Streamable` | `chia-traits`, re-exported by `dig-peer-protocol` | Wire serialization trait |

### 1.5 Chia Behaviors Adopted (via crate reuse)

| # | Behavior | How Adopted | Reference |
|---|----------|-------------|-----------|
| 1 | Handshake with capabilities | The outbound module sends `chia-protocol::Handshake` with the capabilities list over the raw WebSocket, mirroring upstream's `connect.rs` flow, before upgrading to `DigLink`. | [`chia-sdk-client/src/connect.rs:20-32`](https://github.com/Chia-Network/chia-wallet-sdk) |
| 2 | V2 rate limiting | `dig_peer_protocol::OpcodeRateLimiter` enforces Chia's `V2_RATE_LIMITS` frequency and size limits, keyed by raw wire opcode. | [`chia-sdk-client/src/rate_limits.rs`](https://github.com/Chia-Network/chia-wallet-sdk) |
| 3 | TLS mutual authentication | `chia-ssl::ChiaCertificate::generate()` + `create_native_tls_connector()` or `create_rustls_connector()`. | [`chia-sdk-client/src/tls.rs`](https://github.com/Chia-Network/chia-wallet-sdk) |
| 4 | Message framing | `dig_peer_protocol::DigMessage` uses `Streamable` for binary encoding, byte-identical to Chia's `Message`. `DigLink` handles WebSocket binary frames. | [`chia-protocol`](https://crates.io/crates/chia-protocol) |
| 5 | Request/response correlation | `DigLink`'s request methods assign message IDs and wait for correlated responses via its request map. | [`chia-sdk-client/src/peer.rs:302-316`](https://github.com/Chia-Network/chia-wallet-sdk) |
| 6 | DNS seeding | `Network::lookup_all()` with timeout and batching. | [`chia-sdk-client/src/network.rs:40-68`](https://github.com/Chia-Network/chia-wallet-sdk) |
| 7 | Network ID validation | Handshake validation rejects peers with a mismatched `network_id`. | [`chia-sdk-client/src/connect.rs:54-58`](https://github.com/Chia-Network/chia-wallet-sdk) |
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
| 3 | DIG protocol message types | Attestation, checkpoint, and status messages (opcodes 200-222), carried as raw `msg_type` bytes in a `DigMessage`. |
| 4 | Inbound connection listener | `DigLink` is built for outbound `wss://` dials. We add a `TcpListener` accepting inbound and upgrade the accepted server stream via `DigLink::from_server_websocket()`. |

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

### 1.10 IPv6-First, IPv4-Fallback Peer Communication

**NORMATIVE (ecosystem-wide hard rule):** all peer/node communication in `dig-gossip` prefers
IPv6, using IPv4 only as a fallback when IPv6 is unavailable. IPv4 remains a fully supported
fallback — it is never removed or treated as second-class in terms of correctness, only in
ordering preference.

**Inbound listener (CON-002, §5.2):**
- [`GossipConfig::listen_addr`](#) defaults to `[::]:9444` — the IPv6 unspecified address on
  [`DEFAULT_P2P_PORT`](#).
- [`GossipService::start`] binds this address with `IPV6_V6ONLY` explicitly cleared BEFORE
  `bind()` (via `socket2`, since neither `tokio::net::TcpListener::bind` nor
  `tokio::net::TcpSocket` expose this option). One dual-stack socket therefore accepts both
  native IPv6 connections and IPv4-mapped (`::ffff:a.b.c.d`) connections — an IPv6 node still
  serves IPv4-only peers without a second listening socket.
- An explicit IPv4 `listen_addr` (e.g. `127.0.0.1:0` in tests) is bound as a plain IPv4 socket;
  `IPV6_V6ONLY` is only meaningful for — and only touched for — an IPv6 bind address.

**WebSocket transport size caps (CON-002 / §5.2 DoS hardening):** every WebSocket handshake —
the two inbound accept paths (`accept_async_with_config`), the outbound peer dial
(`connect_async_tls_with_config`), AND the relay-discovery dial (`nat::discovery`,
`connect_async_with_config`) — is constructed with a single explicit bounded
`WebSocketConfig` (`connection::ws_config()`), NOT tungstenite's defaults. The caps are
`max_message_size = 8 MiB` ([`WS_MAX_MESSAGE_BYTES`]) and `max_frame_size = 8 MiB`
([`WS_MAX_FRAME_BYTES`]). tungstenite's default `max_message_size` is **64 MiB**, which sits
ABOVE every DIG application cap (the reassembler's per-stream `MAX_BUFFERED_BYTES` = 4 MiB and the
dig-message envelope ceiling): without an explicit transport bound a hostile peer could make
tungstenite buffer up to 64 MiB PER MESSAGE before any application cap rejects it. The bounded
config refuses an over-cap frame/message at the transport layer while leaving generous headroom
(2× the 4 MiB reassembler cap) so no legitimate payload is clipped. The number of connections that
can each hold an in-flight WS read buffer is itself bounded by two accept-loop admission gates —
`max_connections` (default 50) and the audit-#179 `max_inflight_handshakes` semaphore (default 200) —
so the AGGREGATE in-flight transport-buffer memory is bounded at `(max_connections + max_inflight_handshakes) × WS_MAX_MESSAGE_BYTES ≈ 2 GiB`
(defaults), regardless of peer count. Both handshake directions share the one `ws_config()` source of truth so the caps cannot drift apart.

When the transport refuses an over-cap frame/message, tungstenite surfaces it as
`Error::Capacity(CapacityError::MessageTooLong { size, max_size })`. The inbound accept-loop error
mapper (`connection::listener::ws_err`) classifies this distinctly via
`is_transport_capacity_rejection` — emitting a `tracing::warn!` (target `dig_gossip::listener`)
that names it a transport capacity rejection tied to [`WS_MAX_MESSAGE_BYTES`] (#10) — before
collapsing it, like every other transport error, into `ClientError::Io` (the external
`dig_peer_protocol::ClientError` has no WebSocket variant). The classification is pinned by a
deterministic in-crate unit test (`ws_err_classifies_transport_capacity_rejection`) that constructs
the synthetic `Capacity` error directly; a socket-level test cannot deterministically distinguish a
transport-layer rejection from an app-layer one because both surface to the client as a connection close.

**Peer selection / outbound dial candidate ordering:**
- [`AddressManager::select_peer`] itself is a Bitcoin/Chia-style single-address weighted-random
  draw over the whole address book and is family-blind by design (this is unchanged — the
  address book's own grouping, `PeerInfo::get_group` / `subnet_group`, is already family-aware
  for `/16` vs `/32` eclipse-resistance grouping and is NOT part of this rule). An IPv4-mapped
  IPv6 address (`::ffff:a.b.c.d`) is canonicalized to its IPv4 form before the group key is
  computed, so it shares the mapped `/16` group of its plain-v4 twin (and resolves to the same AS
  in the BGP classifier) — a mapped-v6 presentation cannot dodge the one-outbound-per-`/16`
  (INT-006) or per-AS (INT-007) eclipse cap. Genuine IPv6 still groups by its `/32`.
- The CANDIDATE LIST assembled from repeated draws — `GossipHandle`'s `gather_pool_candidates`,
  the source of dial candidates for `run_pool_maintenance_once` / the connected-peer-pool
  planner (POOL-\*) — is passed through
  [`dig_gossip::util::ip_address::order_by_local_stack`] before being returned. That helper is a
  thin adapter over the canonical **`dig-ip`** crate (the single ecosystem authority for the
  address-family / dial contract, CLAUDE.md §5.2), and applies TWO rules:
  1. **IPv6-first** — candidates are grouped by [`dig_ip::Family`] (which orders `V6` before `V4`)
     so every gathered IPv6 candidate sorts before every gathered IPv4 candidate, with relative
     order within each family (e.g. tried-vs-new bias) preserved. The pool planner (`plan_pass`)
     and its dialer therefore attempt IPv6 candidates first for a given maintenance pass, falling
     back to IPv4 only after the pass's IPv6 candidates are exhausted or fail.
  2. **Local∩candidate intersection** — a candidate of a family THIS host cannot originate on
     (per [`dig_ip::LocalStack`]) is DROPPED, so an IPv4-only host never emits an IPv6 SYN and an
     IPv6-only host never emits an IPv4 SYN. When local and candidates are disjoint the pass yields
     no candidates (the multi-peer analog of `dig_ip::dial_order`'s `NoCommonFamily` — a clean
     "nothing dialable", never a doomed attempt).
- Family classification and the local-stack check are delegated entirely to **`dig-ip`**
  ([`dig_ip::Family::of`] / [`dig_ip::LocalStack`]); this crate no longer hand-rolls a family sort
  or an `is_ipv4()` key. `dig_ip::Family::of` correctly treats an IPv4-mapped IPv6 address as IPv4
  reachability. The relay-resolved dialable candidate order in `PeerRecord::from_nat_relay_peer_info`
  is likewise keyed on `dig_ip::Family`.
- `crate::connection::outbound::connect_outbound_peer` dials exactly one already-resolved
  `SocketAddr` per call and has no candidate list of its own; the IPv6-first ordering is enforced
  entirely at the candidate-list-assembly layer above it (this crate does not implement a
  concurrent multi-address happy-eyeballs race within a single dial — IPv6 candidates are
  attempted first across the SEQUENCE of dials, not raced in parallel against IPv4 for one peer).

---

## 2. Data Model

### 2.1 Types Reused from Chia Crates

The following types are **re-exported**, not redefined. The Chia types are reached through
`dig-peer-protocol`; `chia-protocol` remains a direct dependency only for the full-node wire
structs it does not re-export.

```rust
// From chia-protocol
pub use chia_protocol::{
    Bytes32,
    Handshake,
    // Full node protocol messages
    NewPeak, NewTransaction, RequestTransaction, RespondTransaction,
    RequestBlock, RespondBlock, RejectBlock,
    RequestBlocks, RespondBlocks, RejectBlocks,
    NewUnfinishedBlock, RequestUnfinishedBlock, RespondUnfinishedBlock,
    RequestMempoolTransactions,
    RequestPeers, RespondPeers,
    // Payload types
    SpendBundle, FullBlock,
    // Peer info
    TimestampedPeerInfo,
};

// The DIG peer wire, owned by dig-peer-protocol.
pub use dig_peer_protocol::{
    Bytes, ChiaProtocolMessage, DigLink, DigMessage, LinkError, LinkOptions,
    NodeType, ProtocolMessageTypes,
    OpcodeRateLimiter, OpcodeRateLimits,
};

// The Chia surface, re-exported by dig-peer-protocol rather than depended on directly.
pub use dig_peer_protocol::{
    Client, ClientState, ClientError,
    Network,
    RateLimits, RateLimit, V2_RATE_LIMITS,
    load_ssl_cert,
    ChiaCertificate,   // chia-ssl
    Streamable,        // chia-traits
};
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

The `200..=219` band is the **consensus** band (`DigMessageType` above, plus
`RegisterPeer = 218` / `RegisterAck = 219`). The `220..=255` band is **free** for
application protocols — directed (`DIG_MESSAGE = 220`, `PROFILE_BODY_REQUEST = 224`,
`PROFILE_BODY = 225`) or broadcast (`STORE_MELTED = 221`, `HOLDINGS_ANNOUNCE = 222`,
`PROFILE_ROOT_ANNOUNCE = 223`).

#### 2.3.1 `DIG_MESSAGE = 220` — directed dig-message transport (WU6, epic #796)

Opcode **220** (`DIG_MESSAGE`) carries a `dig-message` **directed envelope** between
two peers. It is a first-class `ProtocolMessageTypes::DigMessage` variant so it rides
the ordinary [`DigMessage`](dig_peer_protocol::DigMessage) transport (send / inbound), and the
canonical constant is exported as `dig_gossip::DIG_MESSAGE` (mirrored by
`dig_peer_protocol::DIG_MESSAGE` for non-gossip consumers).

- **Envelope is OPAQUE.** dig-gossip is the transport only — the sealed envelope rides
  verbatim in `DigMessage.data` (bytes in equal bytes out). dig-gossip never seals, opens,
  or parses it, and has no BLS / recipient-key dependency (Wave A, envelope-only). The
  end-to-end sealing to the recipient's DID key is `dig-message`'s (CLAUDE.md §5.4).
- **Directed, never broadcast.** `classify_broadcast(DigMessage) = Unicast`; a directed
  message is delivered 1:1 via `send_dig_message`, never Plumtree-flooded.
- **Correlation.** `DigMessage.id` pairs the frames of one exchange (e.g. a stream).

**Send/route API** (on `GossipHandle`, plus free functions in `service::dig_message`):

| Item | Purpose |
|------|---------|
| `send_dig_message(peer, envelope, correlation_id)` | Send a directed envelope over opcode 220. |
| `dig_message_payload(&Message) -> Option<&[u8]>` | Inbound routing: lift the opaque envelope from an opcode-220 frame (else `None`). |
| `is_dig_message(u8) -> bool` | Recognise opcode 220. |
| `frame_envelope(&[u8], Option<u16>) -> DigMessage` | Build the outbound opcode-220 frame. |

**Opcode 220 (`DigMessage`, directed envelope) — base-bounded by design (accepted).**
Unlike the 221/222 public-flood broadcasts, opcode 220 carries a *directed* (unicast) dig-message envelope as opaque bytes; dig-gossip is pure transport and never opens, decodes, or verifies the envelope. Opcode 220 therefore has NO dedicated DIG rate-limit row and is deliberately bounded only by the Chia `default_settings` base limit — 100 frames/min, 1 MiB/frame, 100 MiB cumulative per connection — applied FIRST and unconditionally by `RateLimiter::handle_message` inside `InboundRateLimiter::allows`. This bound is REAL and non-fail-open: the fail-open `DigRateLimiter::check` runs only afterward and can add, never loosen, a restriction.

This is a conscious classification (`BASE_BOUND_ONLY_BAND_OPCODES`), asserted by the `every_220_band_opcode_is_classified` completeness guard. A tighter dedicated row is intentionally NOT added because (a) dig-gossip performs no per-frame crypto on a 220 frame (the envelope is opaque), so the per-frame cost the base bound already caps is only buffering + service broadcast; and (b) opcode 220 is the directed-message STREAMING transport (`StreamFrame` OPEN/DATA/CLOSE ride inside the opaque payload), so legitimate transfers fragment into many 220 frames and require high per-connection frame cadence — a tighter row would clip legitimate streaming while adding no security benefit against any abuse the base per-connection bound does not already cover.

**Inner `DigMessageType` limiting is out of scope for dig-gossip** and deferred to the recipient (dig-node), which alone decrypts the envelope and dispatches the inner type post-decrypt (cf. the per-origin churn limit). Any per-subtype ingress limiting is recipient-side defense-in-depth layered on top of this transport bound.

#### 2.3.2 Streaming seam

A dig-message **stream** rides as a sequence of opcode-220 frames whose payloads are
`StreamFrame`s (`Open` / `Data{seq}` / `Close`). dig-gossip provides only the framing +
**ordered delivery** seam; the streaming *state machine* (windowing, credit/backpressure,
timeouts) belongs to `dig-message` (WU4).

| Item | Purpose |
|------|---------|
| `open_dig_stream(peer, stream_id)` / `send_dig_stream_data(peer, stream_id, seq, payload)` / `close_dig_stream(peer, stream_id)` | Send OPEN/DATA/CLOSE frames over opcode 220. |
| `StreamFrame::{encode,decode}` | Serialize a stream frame into / out of an opaque opcode-220 payload. |
| `StreamReassembler` | Restore in-order delivery of `Data` chunks across out-of-order transport; drops duplicates. **Safe-by-default bounded:** the pending out-of-order buffer is capped by chunk count (`MAX_BUFFERED_CHUNKS`, default 256) AND total bytes (`MAX_BUFFERED_BYTES`, default 4 MiB); a chunk that would exceed either cap is rejected with `ReassembleError` (buffer never grows past the cap, never panics) so a peer withholding `next_seq` cannot exhaust memory. A gap-filling chunk at `next_seq` is always accepted (it drains, not grows). Single-stream primitive — bounding *concurrent* streams is the WU4 registry's job. |

#### 2.3.3 `STORE_MELTED = 221` — store-melt broadcast (epic #1316)

Opcode **221** (`STORE_MELTED`) announces that a dig-store's on-chain coin has been
**melted** (the store-lifecycle "delete"), so peers stop hosting the store's `.dig`
content and reclaim disk. It is a first-class `ProtocolMessageTypes::StoreMelted`
variant (the second opcode of the free `220..=255` band, after `DIG_MESSAGE = 220`);
the canonical constant is exported as `dig_gossip::STORE_MELTED`.

- **PUBLIC broadcast, flood-disseminated.** A store deletion is public-by-nature and
  addressed to everyone, so `classify_broadcast(StoreMelted) = Plumtree` (eager/lazy
  flood) at **Bulk** priority. Termination is the receiver's job: the transport
  `seen_set` dedups, and the dig-node handler (#3) rebroadcasts ONLY on a real
  `holding → deleted` transition, so the epidemic converges (§SYSTEM.md).
- **§5.4-EXEMPT (signed + mTLS, NOT recipient-sealed).** Because it carries no
  recipient-specific content — it is a public all-peers broadcast, exactly the L2
  consensus-gossip carve-out — `store-melted` is mTLS-authenticated and signed but NOT
  end-to-end sealed to a recipient key. This is a deliberate, documented exemption.
- **The signature is attribution/anti-spam, NOT authority to delete.** The receiver
  MUST verify the melt **on-chain** (singleton-lineage walk, NC-9, fail-closed) before
  deleting anything; a forged or replayed `store-melted` for a live store deletes
  nothing. `melt_height` is an ADVISORY hint (a starting point for the chain lookup),
  never trusted on its face.

**`StoreMeltedAnnounce` wire layout** — fixed length `ENCODED_LEN = 164`, big-endian:

| Offset | Len | Field | Type | Notes |
|-------:|----:|-------|------|-------|
| 0 | 32 | `store_id` | `Bytes32` | Melted store's singleton launcher id. |
| 32 | 4 | `melt_height` | `u32` big-endian | Advisory hint only. |
| 36 | 32 | `sender_peer_id` | `Bytes32` | Announcer's `peer_id = SHA-256(TLS SPKI DER)` — attribution, NOT the verify key. |
| 68 | 96 | `signature` | `[u8; 96]` | BLS AugScheme (G2) compressed. |

`decode` rejects any frame not exactly 164 bytes.

**Signature.** `signature = BLS-AugScheme-sign(sk, SHA-256("dig:store-melted:v1" ‖
store_id ‖ melt_height_be))` over the identity key `sk` (`dig_tls::bls`, the same
AugScheme primitive as the #1204 cert binding — no new cryptography). `verify` recomputes
the preimage and checks the signature against the signer's **48-byte BLS G1 identity
key**, supplied by the caller from the peer's mTLS cert binding (the message carries a
32-byte `peer_id` hash, not a public key). Fail-closed on any malformed input.

**Send/route API** (free functions in `service::store_melted`):

| Item | Purpose |
|------|---------|
| `StoreMeltedAnnounce::new_signed(sk, store_id, melt_height, sender_peer_id)` | Build a signed announcement (originator). |
| `StoreMeltedAnnounce::verify(&self, signer_pk_g1: &[u8; 48]) -> bool` | Verify the signature against the signer's BLS G1 key (receiver). |
| `StoreMeltedAnnounce::{encode,decode}` | Fixed-length big-endian wire round-trip. |
| `sign_store_melted(sk, store_id, melt_height) -> [u8; 96]` / `store_melted_sig_preimage(store_id, melt_height) -> [u8; 32]` | Signature helpers. |
| `frame_store_melted(&StoreMeltedAnnounce) -> DigMessage` | Build the outbound opcode-221 broadcast frame (`id = None`). |
| `store_melted_payload(&DigMessage) -> Option<StoreMeltedAnnounce>` | Inbound routing: lift + decode an opcode-221 frame (else `None`). |
| `is_store_melted(u8) -> bool` | Recognise opcode 221. |

#### 2.3.4 `HOLDINGS_ANNOUNCE = 222` — holdings-announce broadcast (#1428, spec #1394)

Opcode **222** (`HOLDINGS_ANNOUNCE`) lets a provider (a dig-node hosting `.dig` content)
flood a **signed batch** of holdings add/remove deltas telling every peer which content
keys it now serves and at which addresses. dig-node verifies each announcement
(`verify_holdings_announce`) before feeding the deltas into **dig-dht's holder set**. It
is a first-class `ProtocolMessageTypes::HoldingsAnnounce` variant (the third opcode of the
free `220..=255` band, after `STORE_MELTED = 221`); the canonical constant is exported as
`dig_gossip::HOLDINGS_ANNOUNCE`.

- **PUBLIC broadcast, flood-disseminated.** Holdings are public discovery data addressed
  to everyone, so `classify_broadcast(HoldingsAnnounce) = Plumtree` (eager/lazy flood) at
  **Bulk** priority. The transport `seen_set` dedups by the announcement bytes; a later
  `seq` from the same provider supersedes an earlier one.
- **Inbound rate limit (CON-005, #1720).** Opcode 222 carries a DELIBERATE DIG rate-limit row —
  `frequency = 20`/min, `max_size = 131072` (128 KiB) — NOT the loose `default_settings`
  (100 frames/min, 1 MiB) it would otherwise fall through to. The row bounds the expensive
  post-decode P-256 verify a hostile peer can force, while `frequency` (~2x the 221 anchor of
  10/min) caps a connection at 20 signature verifies/min.
- **Encoded-size bound (#1760 B) — makes 128 KiB PROVABLY sufficient.** The 128 KiB `max_size`
  is not merely assumed to fit a legit batch: `holdings_announce` ENFORCES a matching bound.
  An announce whose `encode()`d frame exceeds **`MAX_ANNOUNCE_FRAME_BYTES = 131072`** is
  REJECTED by both `new_signed` and `verify_holdings_announce` (`AnnounceTooLarge`), plus
  per-field caps — **`MAX_ADDRS_PER_CHANGE = 32`** addresses per `Add` (`TooManyAddresses`) and
  **`MAX_HOST_LEN = 253`** bytes per host (`HostTooLong`). The total-size bound is the
  load-bearing guarantee (per-field caps are defense-in-depth): it directly guarantees every
  accepted announce is `<= max_size` regardless of how addresses/hosts distribute, so a legit
  provider's full-holdings frame is never hard-dropped. `MAX_ANNOUNCE_FRAME_BYTES` IS the value
  of the opcode-222 `max_size`, so the enforced bound and the rate-limit cap cannot drift.
  Arithmetic: fixed framing ≈ 282 B; per `Add` delta = `43 + addr_count×(host_len+4)`; a
  realistic IPv6-first (§5.2) full re-announce (256 changes × ~6 v6-literal addresses) ≈ 86 KiB,
  well under the bound. **This is a cross-repo canonical bound: dig-node, which recomputes and
  re-verifies the announce, MUST enforce the SAME `MAX_ANNOUNCE_FRAME_BYTES`/`MAX_ADDRS_PER_CHANGE`/
  `MAX_HOST_LEN` values.** Backwards-compatible: purely a reject-over-bound validation — the
  `canonical_encode` wire LAYOUT is unchanged, so every within-bound legit frame is byte-identical.
- **§5.4-EXEMPT (signed + mTLS, NOT recipient-sealed).** It carries no recipient-specific
  content — it is a public all-peers broadcast, exactly the L2 consensus-gossip carve-out
  (NC-1) — so it is mTLS-authenticated and signed but NOT end-to-end sealed to a recipient
  key. Deliberate, documented exemption.
- **The signature IS the DHT-poisoning gate** (unlike store-melt, whose authority is an
  on-chain proof). It binds the batch of `(content_key, addresses)` deltas to the provider
  identity, so no third party can advertise content on the provider's behalf or point
  resolvers at attacker-controlled addresses. `verify_holdings_announce` performs the
  fail-closed gate:
  1. `changes.len() <= 256` (else `TooManyChanges`).
  2. the size bounds — per-`Add` `MAX_ADDRS_PER_CHANGE`/`MAX_HOST_LEN` caps and the total
     `MAX_ANNOUNCE_FRAME_BYTES` encoded-frame bound (else `TooManyAddresses` / `HostTooLong` /
     `AnnounceTooLarge`); checked BEFORE the P-256 verify so an oversized frame is dropped cheaply.
  3. `provider_peer_id` decodes as 64-hex → `[u8; 32]` (else `BadPeerIdHex`).
  4. `SHA-256(provider_spki)` equals the carried peer id (else `PeerIdMismatch`) — the peer
     id is VERIFIED against the SPKI, never trusted.
  5. `provider_spki` parses as an `id-ecPublicKey` / `prime256v1` (P-256) key (else `BadSpki`).
  6. the ECDSA-P256 signature verifies over the signing message under that key (else
     `InvalidSignature`).
- **Leaf-key identity — sound standalone (decider-locked, #1428).** An announcement carries
  the provider's TLS leaf `SubjectPublicKeyInfo` DER (`provider_spki`) and is signed by that
  leaf key (ECDSA-P256). The SPKI is BOTH what the `peer_id` hashes (`peer_id =
  SHA-256(SPKI DER)`, §5.2) AND the key that verifies the signature — so possession of the
  leaf private key IS the authority, and the peer_id already commits to the signing key. No
  full certificate, no binding extension, no CA chain, and no handshake/proof-of-possession
  are needed; dig-dht (#1424) and dig-warden (#1449) re-verify standalone. This REPLACES the
  earlier BLS "inline cert + #1204 binding" draft, which was **forgeable**: because the
  DigNetwork CA key is public, an attacker could graft a self-consistent BLS binding onto a
  copied victim SPKI and forge an announce under the victim's peer_id. Signing with the leaf
  key itself removes the separate binding there was to graft. The builder side
  (`HoldingsSigner`) exposes `sign(signing_message) -> Vec<u8>` (ECDSA-P256 ASN.1-DER) and
  `spki_der() -> Vec<u8>`; the v1 concrete signer is `EcdsaHoldingsSigner`.

**`HoldingsAnnounce` wire layout** — variable length, big-endian; a `⟨lp⟩` field is
`u16`-big-endian length-prefixed:

| Field | Type | Notes |
|-------|------|-------|
| `provider_peer_id` | `⟨lp⟩` ASCII | 64 lowercase hex chars = `SHA-256(provider_spki)`; VERIFIED against the SPKI, not trusted. |
| `provider_spki` | `⟨lp⟩` bytes | TLS leaf `SubjectPublicKeyInfo` DER; the P-256 key that signs AND whose hash is the peer_id. ~91 B. |
| `seq` | `u64` BE | Monotonic; later supersedes earlier. |
| `announced_at` | `u64` BE | Unix seconds. |
| `change_count` | `u16` BE | `<= 256`; decode rejects a larger count. |
| `changes` | `canonical_encode` | See below. |
| `signature` | `⟨lp⟩` bytes | ECDSA-P256 ASN.1-DER over the signing message (~70-72 B, variable). |

`decode` rejects any truncated frame, a `change_count > 256`, an `Add` whose `addr_count >
MAX_ADDRS_PER_CHANGE` (32) — rejected before the per-address buffer is reserved, so a crafted
`addr_count` cannot force an over-allocation on a small frame (#1777) — or trailing bytes. Decode
thus enforces the same per-change address invariant as the verify-time size check.

**`canonical_encode(changes)`** — the signed bytes; per delta a **kind-tag** byte then:

- `Add`: `0x01 ‖ content_key[32] ‖ addr_count(u16 BE) ‖ (host⟨lp⟩ ‖ port(u16 BE))* ‖ expires_at(u64 BE)` — addresses ARE signed.
- `Remove`: `0x02 ‖ content_key[32]`.

**Signing message / signature.** `signing_message = "dig:holdings:v1" ‖ provider_peer_id(32B)
‖ seq_be ‖ announced_at_be ‖ canonical_encode(changes)`, where `provider_peer_id(32B)` is
the raw peer id (`SHA-256(provider_spki)`). The provider's leaf key signs this message with
ECDSA-P256 (SHA-256, ASN.1-DER); the verifier checks it with the same algorithm — sign and
verify operate over the FULL message (ring hashes it internally), NOT a pre-hashed 32-byte
digest. The preimage layout is unchanged from the prior draft — only the SOURCE of
`provider_peer_id` (the leaf SPKI) and the signature ALGORITHM (ECDSA-P256, not BLS) changed.
The domain tag `"dig:holdings:v1"` is a cross-repo canonical constant — dig-node's verify and
dig-dht's ingest recompute it byte-identically.

**Send/route API** (in `service::holdings_announce`):

| Item | Purpose |
|------|---------|
| `HoldingsAnnounce::new_signed(&signer, seq, announced_at, changes) -> Result` | Build a signed announcement (rejects `> 256` changes and any batch over the size bounds). |
| `verify_holdings_announce(&HoldingsAnnounce) -> Result<(), HoldingsError>` | The DHT-ingest gate — the fail-closed verify above (change-count + size bounds + identity + signature). |
| `MAX_ANNOUNCE_FRAME_BYTES` / `MAX_ADDRS_PER_CHANGE` / `MAX_HOST_LEN` | The enforced size bounds (#1760 B); `MAX_ANNOUNCE_FRAME_BYTES` = the opcode-222 rate-limit `max_size`. Cross-repo: dig-node MUST match. |
| `HoldingsSigner` (`sign(&[u8]) -> Vec<u8>`, `spki_der() -> Vec<u8>`) / `EcdsaHoldingsSigner::new(key_pair, spki_der)` | Build-side abstraction; v1 ECDSA-P256 leaf-key signer paired with its SPKI. |
| `HoldingsAnnounce::{encode,decode}` | Variable-length big-endian wire round-trip. |
| `canonical_encode(&[HoldingsDelta]) -> Vec<u8>` / `holdings_signing_message(&peer_id, seq, announced_at, &changes) -> Vec<u8>` | Signed-bytes + signing-message helpers. |
| `signing_message_digest(&peer_id, seq, announced_at, &changes) -> [u8;32]` | SHA-256 fingerprint of the signing message (KAT/layout helper; NOT what is signed). |
| `frame_holdings_announce(&HoldingsAnnounce) -> DigMessage` | Build the outbound opcode-222 broadcast frame (`id = None`). |
| `holdings_announce_payload(&DigMessage) -> Option<HoldingsAnnounce>` | Inbound routing: lift + decode an opcode-222 frame (else `None`). |
| `is_holdings_announce(u8) -> bool` | Recognise opcode 222. |

**KAT golden vector.** The ECDSA-P256 signature is randomized, so it is NOT hex-pinnable;
`service::holdings_announce` pins only the signing-MESSAGE byte layout (via its SHA-256
fingerprint) under a fixed literal peer id + fixed changes, so CI fails on any drift in the
domain tag / `canonical_encode` / field order of this cross-repo wire contract. The
SPKI→peer_id binding and the sign/verify behaviour (including the "sign with a foreign key,
present the victim's SPKI" forgery rejection) are covered by behavioural tests.

#### 2.3.5 `PROFILE_ROOT_ANNOUNCE = 223` / `PROFILE_BODY_REQUEST = 224` / `PROFILE_BODY = 225` — profile sync (#3014, epic #3008)

A **dig-profile** is a DID singleton plus a dig-store whose contents are summarised by a
sparse-merkle-tree **root**. Peers keep their view of a profile fresh with a three-message
exchange carried on the ordinary gossip transport. `service::profile_sync` defines the wire;
the canonical opcode values mirror `dig_peer_protocol::{PROFILE_ROOT_ANNOUNCE,
PROFILE_BODY_REQUEST, PROFILE_BODY}`, which are the single definition.

| Opcode | Shape | Body | Payload type |
|---|---|---|---|
| 223 `PROFILE_ROOT_ANNOUNCE` | public flood | `store_id[32] ‖ root[32]`, exactly `ENCODED_LEN` = 64 bytes | `ProfileRootRef` |
| 224 `PROFILE_BODY_REQUEST` | directed | `store_id[32] ‖ root[32]`, exactly `ENCODED_LEN` = 64 bytes | `ProfileRootRef` |
| 225 `PROFILE_BODY` | directed | `store_id[32] ‖ root[32] ‖ len[4, big-endian] ‖ body[len]` | `ProfileBody` |

- **Dissemination.** `classify_broadcast(223) = Plumtree` (eager/lazy flood): a profile root is
  public data addressed to everyone. `classify_broadcast(224) = classify_broadcast(225) =
  Unicast`: a body is sent to the one peer that asked for it, never flooded. The exchange is
  correlated by the `(store_id, root)` pair the 225 answer echoes, not by `DigMessage.id`, so
  every frame carries `id = None`. Priority follows the shape: `MessagePriority::from_dig_type(223)
  = Bulk` (a periodic public flood), while 224 and 225 take the `Normal` default so a body request
  a user is waiting on never queues behind bulk flood traffic.
- **223 is deliberately UNSIGNED, and a receiver MUST NOT reject it for lacking a signature.**
  The authority for a profile root is the **on-chain** root, never the announcing peer: a
  receiver compares any announced root against chain before trusting it. A forged announce
  therefore costs an attacker at most one wasted `PROFILE_BODY_REQUEST` whose answer then fails
  that compare, while requiring a signature would add a verification to the highest-volume
  broadcast in the band and buy no additional guarantee. A receiver that demanded one would
  silently drop the entire protocol, since no honest sender produces one. No code path in this
  crate consults a signature for 223, and none may be added.
- **dig-gossip NEVER parses a profile body.** `ProfileBody::body` is **opaque bytes** here —
  exactly the discipline `DIG_MESSAGE = 220` already follows. This crate validates only the
  FRAME: both hashes present, the declared `len` agreeing with the bytes actually carried (in
  BOTH directions — a short read and trailing garbage are both refusals), and the whole frame
  within `MAX_PROFILE_BODY_FRAME_BYTES`. Every semantic check — rehashing the body against
  `root`, comparing that root against chain, canonicality, and any bound inside the body —
  belongs to dig-node. A decoder here would put a parser for untrusted peer input in the
  transport layer and duplicate a check that must exist downstream anyway.
- **Frame bounds.** `ProfileRootRef::decode` accepts a slice ONLY at exactly `ENCODED_LEN` = 64:
  a truncated or padded 223/224 frame is refused, never reinterpreted. `ProfileBody::decode`
  refuses any frame over **`MAX_PROFILE_BODY_FRAME_BYTES` = 1 MiB**, and `frame_profile_body`
  refuses to BUILD one, so this crate never emits a frame the receiving gate would drop. The
  cap is taken from the protocol's own ceiling: it is exactly the `max_size` of Chia's
  `default_settings` row, which the inbound gate applies to every frame before the DIG row is
  consulted, and it sits far below `DigMessage::MAX_MESSAGE_SIZE` (16 MiB).
  `MAX_PROFILE_BODY_BYTES` = `MAX_PROFILE_BODY_FRAME_BYTES − 68` is the largest body that fits.
- **Inbound rate limits (CON-005) — load-bearing, not hygiene.** `DigRateLimiter::check` **fails
  OPEN** for a 220-band opcode with no row, so an opcode added without one is bounded only by the
  loose `default_settings` (100 frames/min, 1 MiB) — and 223 is a *broadcast* any internet host
  may originate. All three opcodes therefore carry a DELIBERATE row, each `max_size` referencing
  the enforced constant above rather than a literal, so the two cannot drift:
  223 `frequency = 20`/min, `max_size = ENCODED_LEN` (64);
  224 `frequency = 60`/min, `max_size = ENCODED_LEN` (64);
  225 `frequency = 60`/min, `max_size = MAX_PROFILE_BODY_FRAME_BYTES` (1 MiB).
  Because each decoder enforces the same bound the row declares, every frame this crate accepts
  is provably within its limiter cap and is never hard-dropped.
- **Penalty attribution (#1626/#1796).** 223 joins `STORE_MELTED` and `HOLDINGS_ANNOUNCE` in the
  public-flood set: an over-cap **rate** rejection of a 223 is EXEMPT from the reputation penalty
  (on a multi-hop flood the delivering connection is a forwarder, not the origin), while an
  oversized 223 IS penalised (no honest relayer emits a frame larger than the enforced bound).
  224 and 225 are directed, so neither exemption applies to them.

**Public API (`dig_gossip::service::profile_sync`).**

| Item | Behaviour |
|------|---------|
| `PROFILE_ROOT_ANNOUNCE` / `PROFILE_BODY_REQUEST` / `PROFILE_BODY` | The canonical opcodes 223 / 224 / 225. |
| `ENCODED_LEN` | Exact wire length (64) of a `ProfileRootRef` — the 223 and 224 payload. |
| `MAX_PROFILE_BODY_FRAME_BYTES` / `MAX_PROFILE_BODY_BYTES` | The enforced 225 frame cap (1 MiB) and the largest body that fits it. Cross-repo: dig-node MUST match. |
| `ProfileRootRef { store_id, root }` + `::{encode,decode}` | The fixed 64-byte `store_id ‖ root` payload. `decode` refuses any other length. |
| `ProfileBody { store_id, root, body }` + `::{encode,decode,encoded_len,fits_frame_cap}` | The 225 payload. `decode` refuses a truncated frame, a declared/actual length disagreement in either direction, and an over-cap frame. |
| `frame_profile_root_announce(&ProfileRootRef) -> DigMessage` | Build the outbound opcode-223 broadcast frame (`id = None`). |
| `frame_profile_body_request(&ProfileRootRef) -> DigMessage` | Build the outbound opcode-224 directed frame (`id = None`). |
| `frame_profile_body(&ProfileBody) -> Option<DigMessage>` | Build the outbound opcode-225 directed frame; `None` when it would exceed the frame cap. |
| `profile_root_announce_payload` / `profile_body_request_payload` / `profile_body_payload` | Inbound routing: lift + decode a frame of that exact opcode (else `None`). |
| `is_profile_root_announce` / `is_profile_body_request` / `is_profile_body` | Recognise opcodes 223 / 224 / 225. |
| `GossipHandle::send_frame(peer_id, DigMessage)` | Send an already-framed message to ONE peer — the directed counterpart of `broadcast`, used for 224/225. |
| `GossipHandle::live_peer_ids() -> Vec<PeerId>` | The peers a directed frame can actually reach (live transport only, stub rows excluded). |


### 2.4 PeerConnection (DIG extension of `dig_peer_protocol::DigLink`)

`DigLink` handles the WebSocket connection and message I/O. `PeerConnection` wraps it with additional metadata for the gossip layer.

```rust
/// Extended peer connection state for the gossip layer.
/// Wraps `dig_peer_protocol::DigLink` with gossip-specific metadata.
pub struct PeerConnection {
    /// The underlying DigLink connection.
    pub peer: DigLink,
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
    pub inbound_rx: mpsc::Receiver<DigMessage>,
}
```

### 2.5 PeerReputation (DIG extension)

Extends `ClientState`'s binary ban/trust with numeric penalties.

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
    /// Relay-resolved dialable candidate address(es), IPv6-first (§5.2 / #924 B1). The relay
    /// substitutes its observed reflexive IP for any unspecified/loopback/private advertised
    /// `listen_addr` host, keeping the port, so a NAT'd peer gets a real dialable candidate.
    /// Additive since protocol v1 (NC-6 soft-fork): `#[serde(default, skip_serializing_if = Vec::is_empty)]`,
    /// so pre-#924 peers omit it and the wire stays byte-identical. Byte-identical to
    /// dig-relay-protocol 0.2.0 (the canonical crate) and dig-nat's vendored copy.
    pub addresses: Vec<SocketAddr>,
}
```

The RLY-001 `Register` message likewise gains an additive `listen_addrs: Vec<SocketAddr>` (the node's
advertised gossip listen candidates, IPv6-first), same `#[serde(default, skip_serializing_if)]`
soft-fork rules. dig-gossip's own introducer-query registration advertises none (identity-only); the
candidates are advertised by dig-nat over the persistent reservation.

### 2.10 GossipConfig

```rust
/// Configuration for the gossip service.
pub struct GossipConfig {
    /// Listen address for inbound P2P connections. Default: `[::]:9444` — IPv6 unspecified,
    /// bound dual-stack with `IPV6_V6ONLY` disabled so IPv4 peers are still accepted (§1.10).
    pub listen_addr: SocketAddr,
    /// Our peer ID.
    pub peer_id: PeerId,
    /// Network ID (e.g., SHA256("dig_mainnet")).
    pub network_id: Bytes32,
    /// Network config for DNS lookup (uses the re-exported `Network`).
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
    /// The SOFTWARE build advertised on the handshake in BOTH directions. Default:
    /// `dig-gossip/<crate version>`. See §2.10.1.
    pub software_version: String,
}
```

#### 2.10.1 `software_version` — the advertised software build

`GossipConfig::software_version` is the ONE value a node advertises as
`Handshake.software_version`. It MUST be used by every handshake this node sends: the outbound dial
hello, the inbound accept reply, and both introducer dials. A node MUST NOT advertise a different
build depending on the direction of the connection.

**Format.** UA-shaped `product/semver`, e.g. `dig-node/0.99.1`. The value is sanitized (CON-008) and
length-capped (CON-003) by the receiver, so it MUST stay under `MAX_SOFTWARE_VERSION_BYTES`.

**This is not the protocol version.** Compatibility is gated by `protocol_version`
(`ADVERTISED_PROTOCOL_VERSION` / `MIN_COMPATIBLE_PROTOCOL_VERSION`). Two peers can speak the same
protocol while running builds months apart. An implementation MUST NOT accept or reject a peer on
`software_version`.

**The application sets it.** The default names this crate, which is the transport, not the product a
peer wants to know about. An embedding application sets its own name and version. This crate does
not infer the application's version, and MUST NOT: doing so is how the pre-#2215 values (`"0.0.0"`
on the dial path, the crate version on the accept path) came to be advertised as if they were the
node's build.

**Empty means "not advertising".** `Handshake.software_version` is a non-optional string, so a peer
that predates this field sends `""`. An implementation MUST accept such a peer normally. An operator
who prefers not to advertise sets the empty string and is indistinguishable from such a peer.

**This crate does not interpret the value.** A received `software_version` is carried as an opaque
sanitized string, exposed by `GossipHandle::connected_pool_peers_with_software()`. The mapping to a
build — including VERSION ZERO, the legacy sentinel that every pre-#2215 peer advertises, which
means "unknown" rather than a real version, in any decoration (`0.0.0`, `0.0.0-rc.1`, `0.0.0+build`)
— is defined once, at the control boundary, by `dig-node-control-interface`'s `PeerSoftware`.

**Privacy trade-off (accepted).** Advertising an exact build is a fingerprinting aid: it tells an
observer precisely which peers run a version with a publicly disclosed defect, turning a disclosure
into a target list. This was accepted for the diagnostic value on a pre-release network. The
mitigation available to an operator is to coarsen the advertised value or to disable it entirely
with the empty string; neither affects connectivity.

An advertised value MUST be either the empty string or a full `product/MAJOR.MINOR.PATCH`, and MUST
NOT be version zero in any form. A two-part `dig-node/0.99` is NOT a valid coarsening: it is not
valid semver, so the far end reads it as *unknown* — an operator who asked to say less would
accidentally have said nothing. The supported coarsening levels are rendered by
`dig-node-control-interface`'s `SoftwareVersionDetail`; an implementation MUST NOT hand-roll a
spelling of its own.

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

    /// Broadcast a DigMessage to connected peers via gossip fanout.
    pub async fn broadcast(
        &self,
        message: Message,
        exclude: Option<PeerId>,
    ) -> Result<usize, GossipError>;

    /// Broadcast a typed Streamable + ChiaProtocolMessage.
    /// Serializes to DigMessage internally using chia-traits::Streamable.
    pub async fn broadcast_typed<T: Streamable + ChiaProtocolMessage>(
        &self,
        body: T,
        exclude: Option<PeerId>,
    ) -> Result<usize, GossipError>;

    /// Send a message to a specific peer (via their `DigLink`).
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
    pub fn inbound_receiver(&self) -> Result<broadcast::Receiver<(PeerId, DigMessage)>, GossipError>;

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

    /// Connect to a peer (drives the handshake, then upgrades to `DigLink`).
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
    pub async fn register_with_introducer(&self) -> Result<RegisterAck, GossipError>;

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
    /// CONNECTED pool peers reached over the relay transport (`TraversalKind::Relayed`, #924 B2) — a
    /// subset of `connected_peers`, surfacing the NAT-blocked last-resort peers distinctly.
    pub relay_transport_peer_count: usize,
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
    /// Wraps the re-exported `ClientError` for connection-level errors.
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

    // Holds `dig_nat::SafeText`, not `String`: a relay is untrusted and chooses the `message` of a
    // `RelayMessage::Error` frame, so the text is neutralized as it enters the error rather than at
    // each place that renders it (#1883).
    #[error("relay error: {0}")]
    RelayError(SafeText),

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

### 5.1 Outbound Connection

The outbound module mirrors upstream's `connect.rs` flow rather than calling it, because
upstream discards the parsed `Handshake` and never exposes the remote TLS SubjectPublicKeyInfo
bytes — both of which `PeerConnection` and `PeerId` (§5.3, API-005) require.

```
Outbound connection:
   │
   ├─ 1. Load TLS cert via load_ssl_cert() / ChiaCertificate::generate()
   ├─ 2. Create connector via create_native_tls_connector() or create_rustls_connector()
   ├─ 3. Dial wss:// with that connector
   │      → Capture remote_spki_der from the WebSocketStream before it is consumed
   │      → Send chia-protocol::Handshake with DIG network_id
   │      → Receive and validate the Handshake response
   │      → Upgrade via DigLink::from_websocket(ws, options)
   │      → Yields (DigLink, mpsc::Receiver<DigMessage>, Handshake, remote_spki_der)
   ├─ 4. Wrap in PeerConnection with gossip metadata
   ├─ 5. Add peer to address manager
   ├─ 6. Send RequestPeers for discovery (node_discovery.py:135-136)
   └─ 7. Spawn per-connection message loop task

Step 7 includes the CON-004 keepalive. Every `PING_INTERVAL_SECS` the loop sends a `RequestPeers`
probe **with no correlation id** and waits up to `PEER_TIMEOUT_SECS` for the peer's `RespondPeers`
on the application inbound stream.

The probe MUST NOT be correlated. Both peers allocate correlation ids from a counter starting at
zero and both keepalive loops start at handshake on the same interval, so two correlated probes can
carry the same id — and because a link matches an inbound frame on correlation id before forwarding
it, each side's waiter would receive the peer's **request** rather than a response. The peer's
request would never reach the auto-reply path, neither side would record a success, and both would
disconnect at the staleness check while logging a timeout that names the wrong cause.

The design fails loose: an alive-but-silent peer is kept, and a round whose reply cannot be observed
at all (the inbound stream is absent while the service starts or stops) is skipped without charging
the staleness window.

Relay fallback (when direct P2P fails):
   │
   ├─ 1. Connect to relay via WebSocket
   ├─ 2. Send Register { peer_id, network_id }
   ├─ 3. Relay messages transparently
   └─ 4. Inbound relay messages delivered to same channel
```

### 5.2 Inbound Connection

`DigLink::from_websocket()` types the stream as the client-oriented `MaybeTlsStream`, so it cannot
take a server-side TLS stream. For inbound, we accept TCP/TLS connections and use
`DigLink::from_server_websocket()`:

```
Listener bind (GossipService::start, once at startup):
   │
   ├─ 0a. If listen_addr is IPv6: build socket via socket2, clear IPV6_V6ONLY, THEN bind()
   │      → one dual-stack [::] socket accepts both native IPv6 and IPv4-mapped connections (§1.10)
   └─ 0b. If listen_addr is IPv4: plain bind() (IPV6_V6ONLY does not apply)

Inbound connection (per accepted socket):
   │
   ├─ 1. TcpListener::accept()
   ├─ 2. TLS handshake (using chia-ssl certificate)
   ├─ 3. tokio_tungstenite::accept_async()
   ├─ 4. DigLink::from_server_websocket(ws, remote_addr, options)
   │      → Returns (DigLink, mpsc::Receiver<DigMessage>)
   ├─ 5. Receive Handshake, validate network_id
   ├─ 6. Send Handshake response
   ├─ 7. Wrap in PeerConnection
   ├─ 8. Add to address manager "new" table (node_discovery.py:120-125)
   └─ 9. Relay peer info (node_discovery.py:126-127)
```

### 5.2.1 Inbound Admission Control (audit #179 HIGH — normative)

The accept loop enforces **two independent** admission gates before spawning a per-connection
handshake task; either alone is insufficient:

1. **`GossipConfig::max_connections`** — checked against `ServiceState::peers.len()`, i.e. the
   count of already-REGISTERED peers (post-handshake). A connection is only inserted into `peers`
   after TLS + the full Chia `Handshake` exchange completes (step 6 above), which can take up to
   the inbound handshake timeout (30s).
2. **`GossipConfig::max_inflight_handshakes`** — checked against a `tokio::sync::Semaphore` sized
   to this value at `ServiceState` construction (clamped to a minimum of 1). The accept loop MUST
   call `try_acquire_owned()` on this semaphore immediately after the `max_connections` check and
   BEFORE `tokio::spawn`ing the handshake task; on `Err` (budget exhausted) it MUST drop the
   accepted socket without spawning a task. The acquired permit MUST be held for the full lifetime
   of the spawned handshake task (moved into the task, dropped on completion or panic).

**Why both are required:** gate 1 alone is blind to every connection currently mid-handshake
(TLS negotiation, or stalled before ever sending a `Handshake` message) — an attacker exploiting
only gate 1 can hold an unbounded number of concurrent sockets/tasks/FDs open indefinitely (up to
the per-connection handshake timeout), which is a slowloris-style resource-exhaustion vector. Gate
2 bounds that population directly, independent of whether any of those connections ever registers.

**Default:** `max_inflight_handshakes` defaults to `max_connections * 4` — enough concurrent
headroom for legitimate reconnect/churn bursts while remaining a small, finite multiple rather
than unbounded.

### 5.2.2 Self-Connection Guard (normative — both directions)

A node MUST NEVER admit a connection whose verified remote `PeerId` equals its own
`GossipConfig::peer_id`, on EITHER direction, and MUST NOT let such a peer become a pool member or be
published as a `PoolEvent`:

1. **Inbound** — `precheck_inbound_peer` rejects the accepted connection when the handshake-derived
   `PeerId` equals `config.peer_id` (`ConnectionRefused`, "inbound self-connection").
2. **Outbound direct WSS** (`connect_to`) — in addition to the address-based `dial_targets_local_listen`
   check (which only catches a dial to the node's OWN listen address), the handshake-verified `peer_id`
   is re-checked against `config.peer_id`; a match returns `GossipError::SelfConnection` and the peer is
   closed BEFORE it is inserted into the pool or a `PoolEvent::PeerAdded` is published.
3. **Outbound `dig-nat` pool-add** (`adopt_nat_connection`) — the adopted connection's verified
   `peer_id` is checked against `config.peer_id` before any pool insert / churn publish; a match returns
   `GossipError::SelfConnection`.

**Why the address guard alone is insufficient:** a relay introducer advertises this node to peers at its
EXTERNAL address, which does not match the local listen bind (e.g. `[::]:port`), so an introduced self
entry slips past `dial_targets_local_listen`. Only the identity-based guard is reliable. Without the
outbound guards the self entry is adopted, published as `PeerAdded`, and fed to the DHT routing table +
peer selector as a provider — a reader then "discovers" itself, self-dials on a content read, and
dead-ends instead of fetching from the real holder (#1584).

### 5.2.3 Reconnect Admission — newest-wins (normative; #1691)

A node MUST admit a **restarted peer** that redials with the same verified `PeerId`, even while the
node still holds a peer-map slot from that peer's prior (now-dead) connection. No per-slot liveness
value exists for a guard to consult: a slot is NOT reaped when its connection drops (the inbound
forwarder task simply ends), and the CON-004 keepalive REMOVES a slot on failure rather than stamping
a freshness timestamp on it. Therefore `precheck_inbound_peer` MUST NOT reject an inbound session
merely because `peers.contains_key(peer_id)`.

Instead the freshly-authenticated inbound session is admitted and **supersedes** the incumbent slot:
`negotiate_inbound_over_ws` inserts the new `LiveSlot` over the existing key (`HashMap::insert`,
newest-wins) and, after releasing the `peers` lock, MUST tear down the displaced slot — abort its
keepalive task then `Peer::close()` it (dropping a `LiveSlot` does not close its socket). This
teardown duty is the POOL's. A relayed slot registered by liveness handle through
`adopt_relayed_inbound_handle` is torn down by NOTIFICATION rather than by closure — the pool fires
the `SupersedeNotice` registered with that session and its owner ends it — see §5.2 (#1871/#71). That
is a different mechanism for the same duty, not an exemption from it. Rationale + invariants:

1. **Cert-gated displacement.** The `peer_id` at the guard is derived from the **completed, verified**
   mTLS handshake (`SHA-256` of the captured client-cert SPKI, §5.3). Only the holder of that identity's
   private key can complete the handshake, so no third party can reach the newest-wins path for an
   identity it does not own — a live peer cannot be displaced by anyone lacking its key.
2. **Map-boundedness.** Exactly one slot per `PeerId` (`insert` replaces, never grows), so a single
   identity cannot accumulate slots or exhaust the map under reconnect churn; the map stays bounded by
   the count of distinct authenticated identities.
3. **Ban/penalty handling is unchanged** — the CON-007 ban expiry + ban check still precede admission;
   a banned identity is rejected before the newest-wins path.
4. **No stale-session eviction of the reconnect (session generations).** Two per-session tasks can
   evict a slot by `PeerId`: the CON-004 keepalive (on by default — `keepalive_*_secs = None` resolves
   to `PING_INTERVAL_SECS` / `PEER_TIMEOUT_SECS`, i.e. 30 s / 90 s) and the CON-005 rate-limit → CON-007
   ban trip. Either, left ungated, would let a superseded session's lingering keepalive OR buffered
   rate-limit violations charge and evict the *reconnect*. Every `LiveSlot` therefore carries a
   monotonic **session generation** (allocated from `ServiceState::next_peer_generation` at insert, so
   a reconnect out-ranks the slot it replaces), and EVERY per-session teardown/charge keyed by `PeerId`
   MUST be a **compare-and-remove**: it charges/evicts the map entry only when the entry still has the
   SAME generation as the caller's session — specifically `disconnect_after_keepalive_failure` and
   `apply_inbound_rate_limit_violation` → `enforce_timed_ban_and_disconnect(_, Some(gen))`. A stale task
   thus becomes a no-op against a newer slot. The supersede path additionally ABORTS the displaced
   slot's keepalive immediately; the generation guard is the load-bearing invariant and the abort is
   the prompt first line of defence. **Operator-initiated bans** (`ban_peer`/`penalize_peer` via the
   handle) pass `None` and remain a blind, identity-scoped remove — that is the correct intent and is
   not reachable from a stale per-session task.

This restores reconnection for a bounced peer (upgrade/crash/service restart); before it, the stale
slot refused every reconnect and the peer's subsequent reads 404'd (observed on the #1640 fleet).

**Outbound symmetry (normative; #1703).** The same newest-wins policy holds for the OUTBOUND dial
path (`GossipHandle::connect_to`), not only the inbound listener. A dropped outbound link leaves this
node's slot for that peer in the map (again, no reaping), so `connect_to` MUST NOT refuse a re-dial to
a peer whose slot survives (no `DuplicateConnection`): the freshly mTLS-authenticated outbound session
supersedes the stale slot at insert time (keyed by the handshake-verified `peer_id`, `HashMap::insert`
replace-not-grow), aborts the displaced slot's keepalive, and `Peer::close()`s it — identical to the
inbound supersede. The invariants (cert-gated displacement, map-boundedness, unchanged ban/penalty
handling, session-generation guard against stale-session eviction) and the **always-enforced
max-connections admission** apply unchanged.

The outbound diversity budget (one-outbound-per-/16 INT-006, one-per-AS INT-007) MUST be derived from
the **live peer map — the single source of truth — never a parallel occupancy set**, and decided on
the **handshake-verified identity, NOT the pre-handshake dialed address**. Two rationales, both
normative:

- *Single source of truth.* Outbound `/16`+AS occupancy MUST be computed on demand by scanning the
  peer map (each OUTBOUND slot's `remote()` classified to its `/16` group via `subnet_group` and, when
  a BGP table is loaded, to its AS number), NOT tracked in a separate mutable `HashSet` mutated on
  connect/disconnect. A refcount-free side-set drifts out of agreement with the map: when two outbound
  peers share a group and one is removed or superseded, an unconditional "remove group" deletes the
  entry while the other peer still occupies it — an UNDER-COUNT that then re-admits a second outbound
  into the occupied group, defeating the cap. The map cannot under-count what it contains.
- *Verified identity, not address.* A peer-map slot sharing the dialed address may be an INBOUND slot
  or a Nat slot (whose address is sourced from attacker-influenced `RespondPeers`) that does NOT occupy
  this node's outbound budget; deciding on address would let a peer place a second outbound in an
  already-full group and widen an eclipse.

Therefore, ATOMICALLY under one hold of the `peers` lock (the same hold that performs the insert, so
two concurrent net-new dials into the same empty group cannot both pass): if the map already holds an
**outbound** slot under the verified `peer_id`, the admission is a genuine outbound reconnect whose
group/AS the map already counts (it is excluded from the scan) — the diversity check is skipped and
the slot is superseded. Otherwise (a net-new identity, or an admission that would replace a
non-outbound slot at that address) it is net-new outbound occupancy and MUST have zero other outbound
slots in its `/16` (INT-006) or AS (INT-007) in the map, else be refused (the completed handshake
stream is closed and a `ConnectionFiltered` error returned). No add/remove bookkeeping runs on
admit/supersede/disconnect — inserting and removing map slots IS the accounting. (A same-identity
outbound reconnect that MOVES into a different, already-occupied group is reconciled by the
departed-peer reaper, #1703 item 2.) Without the outbound path, a node could never re-establish a
dropped outbound link to a peer until the stale slot was cleared.

### 5.2.4 Departed-peer reaper (normative; #1703 item 2)

A `dig-nat` pool member (`PeerSlot::Nat`) carries no keepalive — unlike a live TLS peer, which the
CON-004 keepalive tears down within `PEER_TIMEOUT_SECS` (90 s). So a NAT peer that leaves and never
returns would otherwise linger in the peer map until `stop()`, over-counting `peer_count` and the
`max_connections` / outbound-diversity budgets under high peer turnover (a slow leak). To bound this, a
running service MUST run a periodic **departed-peer reaper**:

- **Cadence.** The reaper wakes every `reaper_interval_secs` (config; `None` resolves to
  `REAPER_INTERVAL_SECS` = 30 s) and is spawned unconditionally at `start()` (a node may adopt NAT
  peers whether or not the pool loop runs), aborted + joined at `stop()`.
- **Provable departure only.** A slot is reaped ONLY when its transport is provably closed from a
  cheap synchronous check: a `PeerSlot::Nat` whose multiplexed session has closed
  (`NatPeerConnection::is_transport_closed`, backed by dig-nat's `ClosedHandle`). A live-but-quiet NAT
  peer reports open and MUST NOT be reaped — a false reap of a live peer is worse than a slow leak.
  `PeerSlot::Live` is left to the CON-004 keepalive (it exposes no cheap synchronous closed signal);
  `PeerSlot::Stub` has no transport.
- **Atomic decide-and-remove — subsumes the §5.2.3 generation guard.** The liveness judgement and the
  removal MUST happen under ONE hold of the `peers` lock, so the slot judged departed is EXACTLY the
  slot removed. This closes the newest-wins race (#1762) without a generation field on `NatSlot`: a
  same-`peer_id` reconnect that already superseded a dead session is seen as the CURRENT slot, whose
  transport is open, so it is kept. (The §5.2.3 generation guard is needed for the keepalive/rate-limit
  paths because they judge liveness across `await`s and THEN remove; the reaper never separates the
  two, so atomicity is strictly stronger.) Dropping a reaped `PeerSlot::Nat` tears down its yamux mux
  session (the #1717 drop invariant), releasing the transport as part of the eviction.
- **Full cleanup parity with `disconnect()`.** Removing the slot from the peer map is not enough — the
  reaper MUST perform the same downstream cleanup `disconnect()` does, or it leaves sibling leaks of
  the same class: (i) each reaped `peer_id` is removed from Plumtree state (`plumtree.remove_peer`,
  PLT-006 self-healing), else the id lingers in `eager_peers`/`lazy_peers`; and (ii) a
  `PoolEvent::PeerRemoved` is emitted so event-driven consumers (dig-node) drop their stale
  "connected" view. The reaper uses removal reason `Reaped` (distinct from keepalive's `Dead` and the
  operator `Disconnected`) for churn observability. **Lock ordering (normative):** both steps run
  AFTER the `peers` lock is released — the reaped ids are collected under the `peers` lock, then the
  publish + Plumtree removal happen outside it, in the SAME order `disconnect()` uses (publish, then
  Plumtree). The reaper MUST NOT call `plumtree.remove_peer` or publish a `PoolEvent` while holding
  the `peers` lock (that would invert the lock order / hold the map lock across a broadcast send).
- **Reconnect guard on the trailing Plumtree removal (normative; #1792).** Because the map removal and
  the Plumtree removal are deliberately NOT atomic (they must not nest the `peers` and `plumtree`
  locks), a concurrent reconnect (`adopt_nat_connection` / `connect_to` → `plumtree.add_peer`) can land
  in the gap and re-insert the id into `peers` with a FRESH eager membership; an unconditional trailing
  `plumtree.remove_peer` would then wipe that live membership — a transient partition of a healthy
  peer. So before the trailing `plumtree.remove_peer`, both departure paths (the reaper Phase 2 AND
  `disconnect()`) MUST re-read `peers` and SKIP the Plumtree removal when the id is present again (the
  reconnect's `add_peer` wins). This guard is **best-effort**: the `peers` re-check and the
  `plumtree.remove_peer` are taken as two SEPARATE (never nested) locks to preserve the no-lock-order-
  inversion invariant above, so it NARROWS — does not eliminate — the window (a reconnect landing
  between the re-check and the removal is still possible). That residual is accepted and self-healing:
  Plumtree's PLT-006 IHAVE/GRAFT re-grafts the peer.

This outbound `/16`+AS diversity gate is enforced on **EVERY** path that adds an outbound peer, not
only the operator-initiated dial. Both `GossipHandle::connect_to` (manual dial) AND
`GossipHandle::adopt_nat_connection` (the AUTO-POOL adoption path: pool maintenance → `HandleDialer::dial`
→ `connect_via_nat_full_ladder` → adopt) MUST apply the identical `outbound_diversity_conflict` check
under the same held `peers` lock immediately before the insert. The auto-pool path is in fact the
attacker-influenceable surface — its candidates originate from `RespondPeers` — so gating only the
manual dial would leave the eclipse caps trivially bypassable via automatic peering. On the adoption
path the check is UNCONDITIONAL: adoption already refuses a duplicate `peer_id` outright, so every
adopted connection is net-new outbound occupancy **unless it is a re-adoption of a peer that already
holds an outbound slot** (below), which the map already counts.

**`dig-nat` adoption symmetry (normative; #1762).** `GossipHandle::adopt_nat_connection` is the single
path EVERY `dig-nat` connection — relayed and direct alike — becomes a pool member through, and it too
MUST NOT refuse an adoption because a slot is already held for that `peer_id` (no
`DuplicateConnection`): the freshly SPKI-pinned-mTLS-authenticated `dig-nat` session supersedes the
held slot at insert time, exactly as the inbound (#1691) and `connect_to` (#1703) paths do. A displaced
`Live` slot has its keepalive aborted and its `Peer` closed; a displaced `Stub` slot holds no
transport; a displaced `Nat` slot is RETIRED by whoever owns its transport — an owned mux is torn down
by being dropped, and an observed session's owner is told (§5.2 #71).

The rule is normative over the **CLASS** of stale slots, not any single cause. A peer-map slot carries
no liveness value to consult (slots are never reaped on disconnect), so a `contains_key` refusal cannot
distinguish a live peer from a relay circuit whose mTLS failed, a half-open TCP link, a vanished peer,
or a timed-out mapping. Because relayed and direct adoptions share this one path, such a refusal let a
DEAD RELAY CIRCUIT block the DIRECT adoption that would have worked — one side logging `duplicate
connection to peer` while the other reported zero connected peers (observed on the #1062 fleet).

Both admission budgets are exempted **only where the arithmetic requires it**, and every NET-NEW
identity still faces them in full:

- **`max_connections`** is not charged when the insert REPLACES a held slot for the same `peer_id`
  (`HashMap::insert` replace-not-grow: the map does not grow, so the cap is already satisfied).
  Charging it would strand a peer behind its own stale slot whenever the pool is full.
- **The outbound diversity budgets** (INT-006 `/16`, INT-007 AS, INT-006a relayed-outbound) are not
  charged when the map already holds an **OUTBOUND** slot under that `peer_id` — the peer already
  occupies its group / one relayed slot, so re-dialling it is not net-new occupancy; counting it would
  be an off-by-one that refuses the last relayed peer's own recovery. A held INBOUND (or otherwise
  non-outbound) slot occupies no outbound budget and therefore earns NO diversity exemption.

Supersession relaxes the duplicate rule ONLY: the self-connection (#1584) and timed-ban (CON-007)
refusals are evaluated before the insert and are unaffected — a re-adoption is not a route around them.
All of it is decided under ONE hold of the `peers` lock, the same hold that inserts, so the
check→insert stays atomic.

### 5.2.5 Discovery-driven displacement — cycling an UNUSED connection out (normative; dig_ecosystem#3128 requirement 8)

Eviction from the pool was **failure-only**: `PoolRemovalReason` could express `Disconnected`, `Dead`,
`Banned` and `Reaped` and nothing else, and at `max_connections` admission was simply refused. A holder
content discovery found outside the persistent set was therefore dialled once, read from, and dropped —
and rediscovered from scratch on every subsequent read. A service MUST support admitting such a holder
by cycling out a connection that is contributing nothing.

- **A separate entry point.** `GossipHandle::adopt_discovered_nat_connection` MAY displace;
  `adopt_nat_connection` MUST NOT and MUST keep refusing with `MaxConnectionsReached` at the cap. The
  maintenance loop dials toward a target and has no reason to prefer a candidate over a held peer;
  discovery does, having found a peer that demonstrably holds wanted content. Both MUST share ONE
  admission path so no other rule can differ between them.
- **Usefulness is REPORTED, not observed.** This crate never sends over a `dig-nat` peer's transport,
  so it cannot see a peer being used. A caller MUST hold a `PeerActivityGuard`
  (`GossipHandle::peer_activity_guard`) for the duration of any work over a pool peer; the guard marks
  the peer busy while alive and stamps it active at both ends. A peer the pool does not hold MUST NOT
  be able to create a usefulness record, which is what bounds that map by membership.
- **Scope.** Only `PeerSlot::Nat` members are displaceable. They are the persistent connection set this
  requirement speaks of and the only slots whose usage this crate is told about; a Chia-protocol
  WebSocket peer is busy with gossip nothing stamps here and would read as permanently idle.
- **The victim.** Among displaceable members, the pool MUST choose the one used LONGEST AGO — not the
  longest-established — breaking ties on the older admission and then on identity so the choice is
  deterministic rather than dependent on map iteration order.
- **Four bounds, all required.** A member MUST NOT be displaced when it has work in flight, when it has
  been held for less than `min_established_secs`, or when it has been used within `min_idle_secs`; and
  a displacement MUST NOT take the pool to or below `min_peers`. The in-flight rule is what makes
  "never evict a peer mid-request" structural: a long transfer emitting no intermediate signal stays
  protected where a last-used stamp would decay. The establishment floor stops the maintenance loop and
  discovery undoing each other's dials.
- **The churn bound.** At most ONE displacement per `displacement_interval_secs`
  (default **600 s**). **This is the bound on an attacker-reachable lever**: a provider record is a
  CLAIM by an untrusted peer (NC-12), so a hostile peer that gets itself returned as a holder reaches
  this admission directly, and without a rate it could displace one honest incumbent per lookup and so
  CHOOSE the node's persistent set — inverting the cycling NC-12 mandates into a means of holding one.
  At one per ten minutes, replacing a default 16-slot map takes at least 160 minutes of sustained
  hostile records, while the maintenance loop, peer exchange and the introducer keep admitting peers by
  paths this lever cannot touch, and every peer it does admit must itself become established and then
  idle before it can be recycled.
- **The bounds have a configuration floor, enforced by `PeerPoolConfig::normalized()`.** A configured
  `displacement_interval_secs` MUST be raised to at least **600 s** — the churn bound is the only
  globally-charged, attacker-reachable bound, and a configured `0` retires it entirely, so the
  sufficiency argument above MUST NOT be defeatable by configuration. A configured
  `min_established_secs` MUST be raised to at least `min_idle_secs`: the reverse ordering is incoherent,
  because a member would become old enough to displace before it could have been observed going unused.
  Both repairs only ever RAISE a value, so a deliberately stricter operator setting survives. There is
  deliberately NO absolute floor on `min_idle_secs`/`min_established_secs`: with the churn bound floored
  and the in-flight rule structural, they govern thrash and victim quality rather than the
  attacker-reachable lever.
- **Usefulness records are dropped at the REMOVAL SITE.** Departures paired with `PeerRemoved` publishing MUST forget the peer's usefulness
  record inside the SAME `peers`-lock hold as the removal from the peer map. Three removal paths do not publish an announcement — `enforce_timed_ban_and_disconnect` (state.rs:1160, :1165) and the keepalive timeout (keepalive.rs:421) — and leave the usefulness record behind, roughly 56 bytes each, one full mTLS handshake per record, until swept when the pool reaches capacity. The `PeerRemoved` churn
  announcement MUST NOT remove records. Announcements are published after the lock is released, so a removal
  performed there is the trailing cleanup a concurrent reconnect races: the reconnect re-admits the id
  with a fresh record and the trailing removal would wipe the live session. A record that outlives its
  peer is nonetheless harmless — only records whose peer is in the live eligible set are reported to the
  planner, and the membership sweep is the backstop — so this path fails SAFE in both directions.
- **A supersede MUST NOT clear a member's in-flight count.** The newest-wins re-admission resets both
  clocks, because the session being measured is new, but `PeerActivityGuard`s are held by the work and
  not by the session. Zeroing the count on re-admission would downgrade "never evict a peer
  mid-request" from structural to a matter of timing.
- **No route around any other guard.** A discovered peer faces the self, ban, `/16` (INT-006), AS
  (INT-007) and relayed-outbound caps exactly as any other. Those MUST be evaluated BEFORE anything is
  displaced, so a peer they will refuse never costs the node an incumbent — otherwise a hostile peer
  could churn the pool without ever joining it.
- **Atomicity.** The decision, the victim's removal, the churn-bound charge and the insert MUST happen
  under ONE hold of the `peers` lock, so two concurrent discoveries can neither both spend the last
  slot nor both charge one interval. The victim is retired (§5.2 #71) and announced as
  `PoolRemovalReason::Displaced` AFTER the lock is released, in the same order `disconnect()` uses.
- **`Displaced` is not a failure.** Every other removal reason reports a peer that broke, misbehaved or
  left; a consumer MUST NOT read `Displaced` as evidence against the peer.

### 5.3 Mandatory Mutual TLS (mTLS) via chia-ssl

**ALL peer-to-peer connections MUST use mutual TLS (mTLS).** Both the client and server present certificates and verify each other. This is a hard security requirement — unencrypted connections and server-only TLS are never permitted for P2P.

- **Mutual authentication**: Both sides of every P2P connection present a `chia-ssl` certificate. The connecting peer presents its certificate to the listener, and the listener presents its certificate to the connecting peer. Both sides extract `PeerId = SHA256(remote_certificate_public_key)` from the peer's presented certificate.
- **Certificate management**: Exclusively via `chia-ssl`. `ChiaCertificate::generate()` creates new node certificates on first run. `load_ssl_cert()` loads existing certificates on subsequent runs.
- **Outbound mTLS**: `create_native_tls_connector()` or `create_rustls_connector()` creates a TLS connector that includes the node's own certificate (client cert) for mutual authentication. This connector is used for the `wss://` dial that the `DigLink` is built on.
- **Inbound mTLS**: The TLS acceptor is configured to **request + require** the peer client certificate (matching Chia's [`server.py:67`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/server.py#L67) `ssl_context.verify_mode = ssl.CERT_REQUIRED`). The listener requires the connecting peer to present a certificate; if none is presented, or if the TLS handshake fails, the connection is dropped. Under the `rustls` feature (the production `dig-node` build) the acceptor is a **rustls `ServerConfig`** presenting the node's `chia-ssl` certificate with a **CA-agnostic `ClientCertVerifier`** that requests, requires, and captures the peer certificate but does not validate it against any CA (self-signed peers are expected — see below); proof-of-possession of the peer's private key is still enforced via the TLS CertificateVerify signature. This replaces the `native-tls` acceptor for `rustls` builds because a `[patch.crates-io]` `native-tls` fork does not propagate through a git dependency, which left the stock acceptor **not requesting** the client certificate on OpenSSL/Linux (peer certificate absent → `PeerId` underivable → inbound dropped). The `native-tls` acceptor is retained for `native-tls`-only builds; its `[patch.crates-io]` fork sets `CERT_REQUIRED` plus Chia CA trust on the OpenSSL server acceptor, which upstream `TlsAcceptorBuilder` offers no way to request. The captured server-side stream is handed to `DigLink::from_server_websocket()` (the server counterpart to `DigLink::from_websocket()`, which only types the client `MaybeTlsStream`).
- **Peer identity from mTLS**: `PeerId = SHA256(remote_TLS_certificate_public_key)`. Because mTLS guarantees both sides present certificates, each side can derive the other's `PeerId` from the certificate exchanged during the TLS handshake. This binds peer identity to cryptographic key material — impersonation requires possessing the private key. Matches Chia's `peer_node_id` derivation from certificate hash ([`ws_connection.py:95`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/ws_connection.py#L95)).
- **Self-signed certificates**: Expected (Chia model). Both connector and acceptor use `danger_accept_invalid_certs(true)` / skip CA chain validation — peer identity is verified by `PeerId` hash, not by a certificate authority. The Chia CA cert (`CHIA_CA_CRT` from `chia-ssl`) is used as a root but verification is relaxed for self-signed node certs.
- **No fallback**: If mTLS handshake fails for any reason (missing cert, expired cert, corrupt cert), the connection MUST be dropped. There is no fallback to plain WebSocket or server-only TLS.
- **Relay connections are separate**: Relay uses standard `wss://` TLS (server-only, not mTLS). Relay identity is verified by the relay server, not by mutual certificate exchange. The relay server does not participate in the `chia-ssl` mTLS system.

This matches Chia's mTLS design where both client and server present certificates ([`server.py:54-71`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/server.py#L54), [`server.py:67`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/server.py#L67) `verify_mode = ssl.CERT_REQUIRED`).

### 5.4 Rate Limiting

Uses `dig_peer_protocol::OpcodeRateLimiter` for the Chia bound, composed with dig-gossip's own
`DigRateLimiter` for the DIG per-opcode bound (dig_ecosystem#2228). Both are keyed by the raw
wire opcode, so no rate-limit decision names `ProtocolMessageTypes`:

```rust
// Outbound: rate limiting is built into DigLink's send path
// (it waits for budget, up to LinkOptions::budget_timeout)

// Inbound: create a separate admission gate for each connection. It composes the Chia
// bound (OpcodeRateLimiter over OpcodeRateLimits, i.e. V2_RATE_LIMITS re-keyed by opcode)
// with DigRateLimiter (dig_extension_rate_limits_map(), keyed by the raw opcode byte)
// behind one lock.
let inbound_limiter = InboundRateLimiter::new(config.peer_options.rate_limit_factor);

// For DIG extension messages, extend V2_RATE_LIMITS with additional entries
```

### 5.4.1 Rate-Limit Ban Recording (Accepted Async-Gap Residual)

**Rate-limit ban recording (accepted async-gap residual).** A rate-limit penalty that crosses `PENALTY_BAN_THRESHOLD` is charged synchronously on the inbound bridge (under the #1691 per-generation guard), while the ban row (`banned` table, keyed by `peer_id = SHA-256(TLS SPKI DER)`) is written by a spawned enforcement task. A session MUST NOT be able to evade the resulting ban by reconnecting inside the µs spawn→enforce gap: this is prevented not by synchronous recording but by the cost asymmetry — a same-`peer_id` reconnect requires a full SPKI-pinned mTLS handshake (milliseconds), which cannot complete inside the microsecond gap, and confers no amplification (a fresh identity is a different `peer_id`; a won dodge still requires re-crossing the threshold at another full handshake). The ban table is identity-scoped and durable across reconnects once written. Implementations MAY instead record the threshold-cross into the `peer_id`/IP ban table synchronously at charge time for defence-in-depth; this is not required for correctness and is deliberately not done, to avoid a banned-but-still-Live map inconsistency when the guarded async enforce no-ops against a superseding reconnect.

### 5.4.2 Public-Flood Penalty Exemption (#1626)

**Public-flood opcodes are frame-dropped at the per-connection cap but EXEMPT from the `RateLimitExceeded` reputation penalty ONLY for a rate/frequency (over-cap) violation.** The two public-flood broadcast opcodes — `StoreMelted` (221) and `HoldingsAnnounce` (222), the opcodes any internet host may originate and that flood to every peer via `classify_broadcast(...) = Plumtree` — are the ONLY opcodes eligible for exemption; the exemption is scoped by BOTH the opcode AND the KIND of violation (#1796). A SIZE/format-violating 221/222 frame (payload exceeding the opcode's enforced `max_size` — `ENCODED_LEN` = 164 B for 221, `MAX_ANNOUNCE_FRAME_BYTES` for 222) is dropped AND penalised; every non-flood over-cap opcode is still penalised.

When a received frame is rejected by the per-connection inbound cap, the forwarder ALWAYS drops it (the cap behaviour is unchanged). It charges the `RateLimitExceeded` penalty (`PenaltyReason`, 15 pts, → `PENALTY_BAN_THRESHOLD` → timed ban) in all cases EXCEPT one: a legit-sized public-flood frame rejected purely for exceeding its RATE/frequency cap. Rationale for that single exemption: on a multi-hop public flood the delivering connection is a **forwarder, not the origin**, so a single hostile origin emitting an over-cap flood would otherwise get every honest peer that redistributes it banned by false attribution. Dropping the excess frame alone is graceful — the receiver's `seen_set`, Plumtree eager/lazy redundancy, and the provider's periodic re-announce all recover the message without punishing the delivering peer. A SIZE-violating flood frame gets NO such pass: no honest relayer emits a frame larger than the enforced bound, so an oversized 221/222 is origin-attributable and IS penalised. The exemption set is a single source of truth (`is_public_flood_opcode`) kept in lockstep with the canonical `classify_broadcast` public-flood grouping so the two cannot drift; the size-vs-rate classification (`exceeds_dig_wire_max_size`) reads the opcode's `max_size` from the `dig_extension_rate_limits_map` row (never a hardcoded literal).

---

## 6. Peer Discovery

### 6.1 Overview

Uses the re-exported `Network::lookup_all()` for DNS resolution. The discovery loop and address manager are ported from Chia Python.

### 6.2 DNS Seeding (reuses the re-exported `Network`)

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

**Test-hook memory bound (audit #179 HIGH — normative):** `AddressManager` retains, for test
observability only, the MOST RECENT `add_to_new_table` batch (`(peer_list, source)`) — never more
than one. This state exists solely so integration tests can assert what the last peer-exchange
merge contained; production code never reads it. Implementations MUST NOT accumulate a history of
batches (e.g. an ever-growing `Vec`): every inbound peer-exchange merge (outbound connect
`RequestPeers` response, introducer discovery, relay-introducer merge) calls
`add_to_new_table`, so unbounded retention is an attacker-reachable, unbounded memory-growth
vector over the lifetime of a long-running node.

### 6.4 Discovery Loop (Rust port, improved)

Ported from [`node_discovery.py:244-349`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/node_discovery.py#L244) with the following improvements over Chia:

1. If address manager empty → DNS first (via `Network::lookup_all()`), then introducer with exponential backoff.
2. **Parallel connection establishment** (DSC-009 — future roadmap, not yet implemented): the design is to select a batch of peers from the address manager and connect concurrently using `FuturesUnordered`, versus Chia connecting one at a time with `asyncio.sleep()` between attempts. The v0.17.6 `parallel_connect_batch` simulation stub (which faked successes without dialing) was removed; the **live** outbound dialer today is the pool-maintenance path (`HandleDialer::dial` → `connect_via_nat_full_ladder` → `adopt_nat_connection`) plus manual `connect_to` → `connect_outbound_peer` (CON-001).
3. **AS-level diversity** (improvement over Chia's /16 grouping): First check /16 group (fast filter), then verify AS number is unique among outbound connections. AS numbers resolved via cached BGP prefix table. This cap applies to the **DIRECT tier only** — `connect_to` (TLS dial, real remote) and non-relayed `adopt_nat_connection` (Direct / UPnP / NAT-PMP / PCP / HolePunch). **Relayed-tier outbound is EXEMPT (INT-006a):** a relayed link's remote address is the RELAY endpoint, not the peer's own routable address, so keying /16//AS on it is meaningless — every relayed peer would collapse into one group (zero eclipse value, plus a self-throttle to a single relayed peer that strands NAT'd nodes) and a relayed slot would wrongly block a direct candidate sharing the relay's /16. A relayed slot therefore neither is checked against nor occupies a /16//AS group. To still bound a relayed-Sybil flood, the relayed tier has its own cap `max_relayed_outbound = target_outbound_count − max(target_outbound_count/4, 1)` (**6** with the default target of 8), enforced in `adopt_nat_connection` under the same `peers`-lock hold as the insert; it reserves ≥`max(target/4, 1)` outbound slots (≥2) for the diversity-checked non-relayed tier. Rejections: INT-006 (`Subnet`) / INT-007 (`As`) for the direct tier, INT-006a (`relayed outbound cap reached`) for the relayed tier.
4. Feeler connections on Poisson schedule (240s average).
5. On successful connect → `mark_good()`. On failure → `attempt(count_failure=true)`.
6. **Latency-aware peer selection**: When multiple candidate peers pass the group/AS filter, prefer the one with the lowest average RTT from the peer scorer.

### 6.5 Introducer Client (DIG extension)

From `l2_driver_state_channel/src/services/network/introducer_client.rs`. Adds registration capability not in Chia.

**Query flow:** Connect → Handshake → `get_peers` → receive `peers` → close.
**Register flow:** Connect → Handshake → `register_peer { ip, port, node_type }` → receive `register_ack` → close.

**Cap parity with peer-exchange (audit #179 MEDIUM finding 3 — normative):** an introducer is a
single, network-configurable endpoint, strictly weaker-trust than a connected peer. The discovery
loop (`run_discovery_loop`) MUST route every introducer response through the SAME
`cap_received_peers` gate (§6.6, §1.6#10/#11) — the SAME shared `total_peers_received` counter
node peer-exchange (`GossipHandle::connect_to`) uses — before folding it into the address
manager. A malicious/compromised introducer MUST NOT be able to add more peers, in total, than a
connected peer could via `RequestPeers`/`RespondPeers`.

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

### 7.0.1 Relay-Introducer Discovery Bounds (audit #179 MEDIUM finding 4 — normative)

The relay is explicitly **untrusted** — it is a single, network-configurable rendezvous, and its
WebSocket stream may be tampered with by an on-path attacker. `relay_get_peers` (§4a discovery, RLY-005
`get_peers`) MUST bound both axes of that untrusted input:

1. **Frame count.** The read loop that skips non-`peers`/non-`error` frames (`register_ack`, pings,
   stray notifications) while waiting for the response MUST give up with an error after
   `MAX_RELAY_DISCOVERY_FRAMES` (64) such frames, rather than relying solely on the outer
   per-call `timeout`. Without this, a hostile/compromised relay can stream filler frames for the
   entire timeout window on every discovery pass (CPU/bandwidth amplification).
2. **Peers-list length.** The accepted `RelayMessage::Peers { peers }` list MUST be truncated to
   `MAX_PEERS_RECEIVED_PER_REQUEST` (the SAME per-request cap node peer-exchange applies to
   `RespondPeers`, §6.6/§1.6#10) before being converted to `PeerRecord`s. A single oversized
   `peers` frame from an untrusted relay MUST NOT be able to add more records in one response than
   a connected peer could via `RequestPeers`.

Both bounds live in `relay_get_peers` itself (`src/nat/discovery.rs`) — the earliest point the
untrusted relay's response is decoded — so any caller of that RLY-005 decode inherits the bound
automatically. (Since #870 the LIVE discovery path is `dig-nat`'s persistent reservation, §7.0.2;
the equivalent bound on that path is `dig-nat`'s `MAX_KNOWN_PEERS` set cap plus the capped fold
below.)

**Cumulative bound across repeated passes.** The pool-maintenance loop folds the relay-discovered
set every maintenance interval, so per-response caps alone bound one snapshot but not the running
total. `GossipHandle::fold_relay_known_peers` (the #870 consumption seam) MUST merge via
`merge_records_into_address_manager_capped`, which additionally routes the batch through
`cap_received_peers` against the SAME shared `total_peers_received` counter node peer-exchange and
introducer discovery use (§6.6/§7.0.1 cap parity) — so the relay source cannot cumulatively exceed
the combined global budget any more than repeated `RequestPeers` rounds could. The plain
`merge_records_into_address_manager` (uncapped) remains available for callers that already apply
their own bound or operate on a trusted/local source.

### 7.0.2 Persistent-Reservation Peer Discovery (#870 — normative)

The LIVE relay-discovery path is `dig-nat`'s **persistent reservation**, NOT an ephemeral per-pass
socket. `dig-nat` owns the relay transport: its `run_relay_connection` loop holds ONE long-lived
WebSocket that registers once (RLY-001), keeps the reservation alive (RLY-006 keepalive + capped-
exponential reconnect), AND discovers peers over the SAME socket (RLY-005 `GetPeers` after register +
periodically, plus pushed `PeerConnected`/`PeerDisconnected`). It exposes the discovered set via
`RelayStatus::known_peers()` (deduped by `peer_id`, bounded to `MAX_KNOWN_PEERS`, cleared on each
reconnect).

A node MUST run at most ONE reservation and share its `RelayStatus` with the gossip service via
`GossipHandle::attach_relay_status`. The pool-maintenance DISCOVER step then folds
`RelayStatus::known_peers()` in through `GossipHandle::fold_relay_known_peers` each pass. dig-gossip
MUST NOT open its own ephemeral relay socket for discovery — the removed open→register→get_peers→close
path reconnected every maintenance interval, so two nodes' sub-second registration windows never
overlapped and neither ever appeared in the other's `get_peers` (the proven root cause of
`connected_peers` staying `0`). Holding ONE reservation live makes the relay advertise each node to
the other's discovery, so relay-introduced nodes find each other.

**Relay-reachable peers survive and count.** A relay-discovered peer with NO dialable candidate is
identity-only (`Via::Relay`, no address — the relay addresses it by `peer_id`), so it is never placed
in the by-address book. It MUST nonetheless SURVIVE as a **relay-reachable** peer (tracked in a set
folded wholesale from `known_peers()` each pass, so a `PeerDisconnected` drops it) and count toward the
connected total so it shrinks the pool's free-slot dial budget like a direct peer, and is
reported in `GossipStats::relay_peer_count` (with `GossipStats::relay_connected` reflecting whether
the reservation socket is currently held). This is what makes two relay-introduced nodes each show a
non-zero connected count.

**Dialable fold (#924 B1).** When a relay-discovered peer carries a relay-resolved dialable candidate
(`RelayPeerInfo.addresses` non-empty), the fold builds a **dialable** `PeerRecord`: each candidate
becomes an `AddressKind::Direct` address, ordered IPv6-first (§5.2), and the record is `Via::Direct`.
Such a record has a `to_timestamped_peer_info()` and therefore SURVIVES the dialable-only address-book
merge (§7.0.1 caps still apply) — the pool then direct-dials the peer over the existing mTLS path, and
a successful handshake lands it in the DIRECT pool (`connected_peers`). An empty `addresses` keeps the
identity-only `Via::Relay` behavior above (legacy peers).

**Auto-dial pins the discovered `peer_id` (#1517).** When discovery resolves a peer's dialable
candidate ADDRESS and its `peer_id` together (the relay introducer / `dig-nat` reservation, `Via::Direct`
fold above), the pool auto-dialer MUST pin the mTLS SPKI to that discovered `peer_id` — never a zero /
placeholder pin. The Chia address book stores only `host:port`, so the discovered id is retained in a
side map (address → `peer_id`) folded alongside the dialable record and threaded into the
`PoolCandidate` (`with_id`). A candidate with NO discovered id (node peer-exchange, which never carries
an id) is NOT dialed over the `dig-nat` ladder — the SPKI verifier would reject any pin — rather than
dialed with an all-zeros pin that always fails.

**Auto-dial attempts the FULL ladder, relay circuit included (#1517).** The pool auto-dialer MUST enable
the full traversal ladder — Direct → UPnP → NAT-PMP → PCP → hole-punch → **Relayed** — over a
`NatRuntime` carrying the relay dialer (built from the attached reservation `RelayStatus`), so a peer
that fails every direct / port-mapping / hole-punch tier is still reached over the SPKI-pinned relay
circuit. Enabling only `Direct` (so the strategy stops after Direct fails and never exercises the relay
transport) is a defect.

**Self-filter.** The relay-reachable set MUST exclude this node's own `peer_id` if the relay echoes it
back. The comparison is done in NORMALIZED form (a stripped optional `0x` prefix + lowercase) on both
sides, so a relay that echoes the id in a different spelling than the node renders it does not inflate
`relay_peer_count` by one (#924 self-filter).

**Relay-transport peers count as connected (#924 B2).** A peer reached over `dig-nat`'s relayed
transport (`TraversalKind::Relayed` — the traversal ladder's last tier, tunnelled through the relay's
RLY-002 forwarder) is adopted as a CONNECTED pool peer exactly like a directly-dialed one: it counts in
`connected_peers`, is tallied distinctly in `GossipStats::relay_transport_peer_count`, and is reported
`Via::Relay` by `connected_pool_peers_with_via()`. This moves `connected_peers` off zero for a
NAT-blocked pair with no direct dialability. Per **NC-1** the relay only ever forwards OPAQUE bytes:
the RLY-002 `payload` is a `Vec<u8>` the relay cannot interpret, so a directed gossip frame handed to
the transport is carried verbatim (the same frame the direct path carries) and no plaintext-to-relay
path is introduced.

**The RESPONDER half of a relayed circuit is a pool member too (#870/#1871).** A relay circuit has two
ends. The dialer's end is adopted through `adopt_nat_connection`; the reservation HOLDER's end — the
authenticated `PeerConnection` `dig_nat::RelayAcceptor::accept` returns for a circuit a peer opened
through the relay — MUST be registered through `GossipHandle::adopt_relayed_inbound` or
`GossipHandle::adopt_relayed_inbound_handle`. A node serving a peer over such a circuit and reporting
`connected_peers = 0` is a defect: the pool is what every subsystem reads to answer "am I connected".

**Every ACCEPTED connection is a pool member, including a DIRECT one (#3124).** The rule above is not
about relays; it is about direction. A node that ACCEPTS a direct mTLS connection and serves the peer
MUST register it through `GossipHandle::adopt_direct_inbound_handle`, which takes
`(peer_id, remote, method, ObservedSession, Option<NatBroadcastSink>)`. Reporting such a peer as
unconnected is the same defect as for a circuit, on the far more common path.

The direct-inbound entry point is SEPARATE from the other four, and MUST NOT be replaced by any of
them, because each carries a fact that is false for an accepted direct peer:

- A slot adopted through `adopt_relayed_inbound_handle` is `TraversalKind::Relayed`. `Via` and both
  relayed caps derive from that tier, so a directly-connected peer would be reported as
  relay-tunnelled and charged against the budget bounding relay-chosen peers.
- A slot adopted through `adopt_nat_connection` is `is_outbound = true`, charging the INT-006 /16 and
  INT-007 AS **outbound** diversity budgets for a peer this node never dialed. An accepted slot MUST
  be `is_outbound = false` and MUST occupy no outbound diversity group.
- `adopt_direct_inbound_handle` MUST refuse `TraversalKind::Relayed`; a circuit accounted against the
  direct tier would escape the relayed cap.

**DIALABILITY IS A PROPERTY OF THE TIER *AND* THE DIRECTION (#3124).** A `dig-nat` slot's `remote` is
a dial target only when THIS node chose it. An accepted connection's `remote` is the peer's EPHEMERAL
SOURCE PORT — valid for that one connection, and bound to nothing — so a slot this node accepted MUST
report `dial_addr = None` regardless of its traversal tier, and MUST NOT appear in
`dialable_pool_peers()`. It is still reported as `session_addr` for observability. The two reasons a
slot is undialable are independent and MUST NOT be collapsed: a relayed slot is undialable in either
direction because of its tier, an accepted slot because of its direction.

**Accepted DIRECT peers are CAPPED (#3124).** At most `max_direct_inbound(max_connections)` — the same
reserved quarter as `max_relayed_inbound`, counted separately so the two inbound tiers cannot pool
their budgets — may hold slots at once. Every slot an accepted connection holds is one the maintenance
loop cannot spend dialing a peer of this node's own choosing, so an unbounded accepted tier would let
anyone able to complete a handshake choose this node's entire peer set. An accepted connection also
MUST NOT supersede a slot this node can DIAL: that would trade a peer reachable at a known address for
one reachable only while the peer keeps its connection open, at the peer's initiative.

**Registration MUST NOT cost the caller the session (#1871).** `adopt_relayed_inbound` takes the
connection by value, and `dig_nat::PeerSession` is neither `Clone` nor splittable, so a node whose L7
serve loop needs `&mut PeerSession` cannot use that entry point without ceasing to serve the peer —
counted but no longer served, which is strictly worse than uncounted. `adopt_relayed_inbound_handle`
therefore takes `(peer_id, remote, ObservedSession)`: the pool never sends over a relayed slot's
transport, and the ONE question it asks — whether the peer is still up, for the departed-peer reaper —
is exactly what the `dig_nat::ClosedHandle` inside an `ObservedSession` answers. Normatively:

- Both entry points share ONE admission path; every rule below applies identically to each.
- An `ObservedSession` pairs that `ClosedHandle` with a `SupersedeNotice` — the callback reaching
  whoever owns the session — and the two MUST NOT be registrable apart. A slot with no way to notify
  its owner is a silent accounting failure by construction, which is the class of defect this pairing
  exists to remove.
- The `ClosedHandle` MUST observe the session serving that peer. It is the slot's only departure
  signal, so a handle for another (or an already-dead) session makes the peer unreapable or reaps it
  at once.
- Transport TEARDOWN follows OWNERSHIP. Dropping a slot registered by value closes the mux; dropping a
  slot registered by handle MUST NOT, because the caller still owns and serves the session — the pool
  MUST NOT hang up on a peer another task is serving.
- **RETIRE is not RELINQUISH, and a retired slot's owner MUST be told (#71).** Two different things
  remove a slot, and only one of them ends the peer's session.
  - **Relinquish** — `disconnect()` and the departed-peer reaper stop ACCOUNTING for the peer. A
    by-handle slot's session MUST be left running: its owner may still be mid-conversation, and the
    pool MUST NOT hang up on a peer another task is serving.
  - **Retire** — a newer session for the same `peer_id` supersedes the slot (§5.2.3 newest-wins), or
    the pool displaces it to admit a discovered holder (§5.2.5). The session is then obsolete:
    uncounted, unreplaceable, and closable only by its owner. The pool MUST fire that session's
    `SupersedeNotice` exactly once, after releasing the `peers` lock.

  Ownership is unchanged by this — the pool runs the CALLER's callback and the caller ends the
  session — so it satisfies §5.2.3's teardown duty rather than exempting the by-handle path from it.
  Firing a notice on a RELINQUISH would be a defect: it would hang up on a peer the node is serving,
  which is the very failure the by-handle path exists to prevent.

The registration is normatively:

- **Authenticated only.** The caller MUST pass a connection whose `peer_id` came from a completed mTLS
  handshake — the `PeerConnection` `dig_nat` produces once its verifier has captured the peer's
  certificate-derived id. A relay MUST NOT be able to inflate a node's peer count with peers it never
  authenticated; it cannot, because it is not in the node's process and cannot invoke this path. This
  is an obligation on the CALLER, not a guarantee of the argument type: `dig_nat::PeerConnection` has
  public fields, so an in-process caller can construct one carrying any identity.
- **Relay-typed and INBOUND.** The slot carries `TraversalKind::Relayed` and `is_outbound = false`; it
  reports `Via::Relay`, and it occupies NO outbound diversity group and NO `max_relayed_outbound` slot
  (the responder dialed nothing).
- **Non-dialable, structurally.** Every relayed slot — in EITHER direction — has
  `ConnectedPoolPeer::dial_addr == None` and MUST NOT appear in `dialable_pool_peers()`. A relayed
  link's recorded remote is the relay endpoint (unspecified for an accepted circuit), never an address
  the peer answers at; offering it to a dialer produces a guaranteed failure and risks evicting the
  working circuit already carrying that peer's traffic. Non-dialability belongs to the TIER, not the
  direction.
- **Bounded.** At most `max_relayed_inbound = max_connections − max(max_connections/4, 1)` accepted
  circuits (**6** at `max_connections = 8`), enforced under the same `peers`-lock hold as the insert, so
  a single relay cannot fill the pool with peers of its own choosing (eclipse by introduction). The
  reserved quarter is the same derivation as `max_relayed_outbound` and the direct-dial floor. The cap
  counts slots that are themselves accepted circuits — relayed and INBOUND; a relayed OUTBOUND peer
  MUST NOT consume it, or a node that dials out over relays refuses legitimate circuits while under
  its own cap.
- **A held slot exempts only the budget it occupies.** Re-adopting an identity that already holds an
  accepted circuit is charged nothing (the map does not grow and the circuit already exists), but
  converting a relayed OUTBOUND slot into an accepted circuit MUST still be charged the
  `max_relayed_inbound` cap. A blanket held-slot exemption makes the cap a formality: any peer a relay
  can get admitted by another path could then be converted into a circuit, and iterated over distinct
  peers that fills `max_connections` entirely with relay-introduced circuits.
- **A circuit never supersedes a NON-relayed slot.** A peer already holding a direct slot is REFUSED
  here. Superseding it would drop a dialable peer's dial address and demote it to non-dialable at that
  peer's own initiative, and the direct link is the better path regardless.
- Re-adoption is otherwise newest-wins on the #1762 terms, and the self (#1584) / ban (CON-007) guards
  run first.

Two accounting rules govern how relay-reachable peers feed the dial budget:

- **Union, not sum.** The connected total counts the UNION of directly-connected and relay-reachable
  peers. A peer reachable BOTH directly and via the relay (routine during the relay→direct hole-punch
  upgrade window, and for any direct peer that stays relay-registered) MUST count ONCE — as a direct
  peer. Summing the raw relay-reachable count with the direct peer count double-counts such a peer,
  inflates the connected total, and wrongly shrinks the free-slot budget so the node under-populates
  its direct pool. Only relay-reachable peers NOT already directly connected contribute to the total.
- **Direct-dial floor.** Relay-reachable peers reduce redundant direct dialing but MUST NOT be able to
  drive the direct-dial budget to zero. The pool always works toward a minimum of `target_peers / 4`
  (at least 1) DIRECT connections regardless of how many peers a relay advertises, so a compromised or
  misbehaving relay reporting `>= target_peers` reachable peers cannot suppress all direct dialing and
  strand the node on that single relay. Direct dialing still never exceeds the hard `max_peers` cap.

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
fan_out(message: Message, origin: Option<PeerId>, source: Local | Forwarded):
  1. hash = SHA256(message.msg_type || message.data)
  2. if source == Forwarded and seen_set.contains(hash) → return 0 (already seen)
  3. seen_set.insert(hash)
  4. Deliver to local inbound channel (application layer)
  5. For each peer in eager_peers (excluding origin):
       peer.send_raw(message)         // Full message via eager push
  6. For each peer in lazy_peers (excluding origin):
       peer.send_raw(LazyAnnounce { hash, msg_type })  // Hash-only
  7. If relay connected: relay.broadcast(message, exclude_list)
  8. Return the number of peers actually sent to
```

**Message origin (normative).** The seen set suppresses a message the node has already
disseminated. That is correct ONLY for a `Forwarded` message — one received from a peer and
relayed onward, where a repeat is a loop. A `Local` message is produced by this node and describes
its own state, so a periodic re-announce of unchanged state is byte-identical by design and MUST
NOT be suppressed: the peers that need it are exactly those that were not connected when it was
first announced. `broadcast()` disseminates `Forwarded` messages; `broadcast_local()`
disseminates `Local` ones. Both MUST insert the hash (step 3), so a `Local` message echoed back by
a peer and offered to `broadcast()` is still suppressed and the epidemic still terminates.

**A `dig-nat` peer is a broadcast target (normative, #69).** A `dig-nat` pool member has no
`DigLink` and this crate frames nothing over the mux, so the fan-out MUST NOT be the party that
writes to it — but it MUST NOT skip the peer either. A peer excluded from the fan-out by its slot
CLASS never hears an announcement at all, which silences every node that depends on a relay to
receive them. The peer's session belongs to whoever serves it (see `adopt_relayed_inbound_handle`),
so that owner supplies a `NatBroadcastSink`, drains it, and frames each message onto the peer's
stream; the fan-out offers every non-excluded `dig-nat` peer its message through that sink.
Normatively:

- Offering MUST NOT block and MUST NOT await while the peer map is locked. A sink whose owner has
  stopped draining, or is behind, yields an UNREACHABLE peer — never a stalled broadcast.
- A `dig-nat` peer with NO sink is unreachable, exactly as before: nothing can write to it.
- A sink MAY be attached after adoption (`set_nat_broadcast_sink`), because the dialer path adopts
  before any serve loop exists. A peer is a delivery target from the moment its sink is attached.

**Return value (normative).** The value returned is a DELIVERY count: a peer is counted only when
this call placed the frame on that peer's transport — for a `dig-nat` peer, when the message was
accepted by its sink. A connected peer this fan-out could not write to — a `dig-nat` peer with no
sink or a sink that would not accept the message, or a Plumtree-lazy peer while step 6's
`LazyAnnounce` producer is unimplemented — MUST NOT be counted, and is instead reported by
`GossipHandle::unreachable_peer_count()`. A count that includes peers sent nothing is
indistinguishable from a healthy broadcast and hides exactly the failures it should surface.

**Lock scope (audit #179 LOW finding 5 — normative, optimization-class):** the classification
step (building the eager/lazy peer lists in step 5/6 above, which requires locking both the peer
map and `PlumtreeState`) MUST release both locks before step 5's per-peer send loop begins.
Neither lock may be held across a `send_raw`/`send_protocol_message(...).await` point — a
`std::sync::MutexGuard` held across an await is `!Send`, so `GossipHandle::broadcast`'s future
would itself become non-`Send`, breaking `tokio::spawn`-ability. `dig-gossip`'s implementation
satisfies this today. Each eager send clones the outbound `DigMessage` body (a `Vec<u8>`-backed
`dig_peer_protocol::Bytes`, not reference-counted) — this is an accepted O(N) per-broadcast cost
proportional to the eager fan-out (bounded by `GossipConfig::gossip_fanout`, default 8), not a
growth-over-time or attacker-amplifiable vector; eliminating it would require changing the wire
envelope to a refcounted buffer in `dig-peer-protocol`, which is out of scope for this crate.

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
    critical: VecDeque<DigMessage>,  // Drained first, always
    normal: VecDeque<DigMessage>,    // Drained when critical is empty
    bulk: VecDeque<DigMessage>,      // Drained when both above are empty
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

#### 8.6.1 DIG L2 per-opcode routing contract (`200..=219`)

`DigMessageType` is **consumed from `dig-peer-protocol`** (the authoritative wire crate), not
hand-rolled in dig-gossip, so the discriminants + `u8` serde encoding are byte-identical across every
peer crate. Every opcode carries exactly ONE declared dissemination strategy. `route_dig_message(op)
-> RoutingStrategy` is the single per-opcode routing authority (exhaustive over `DigMessageType`); this
table is normative and MUST match it:

| Opcode | `DigMessageType` | `RoutingStrategy` |
|--------|------------------|-------------------|
| 200 | `NewAttestation` | `PlumtreeEager` |
| 201 | `NewCheckpointProposal` | `PlumtreeEager` |
| 202 | `NewCheckpointSignature` | `PlumtreeEager` |
| 203 | `RequestCheckpointSignatures` | `UnicastRequest` |
| 204 | `RespondCheckpointSignatures` | `UnicastResponse` |
| 205 | `RequestStatus` | `UnicastRequest` |
| 206 | `RespondStatus` | `UnicastResponse` |
| 207 | `NewCheckpointSubmission` | `PlumtreeEager` |
| 208 | `ValidatorAnnounce` | `BroadcastFlood` |
| 209 | `RequestBlockTransactions` | `UnicastRequest` |
| 210 | `RespondBlockTransactions` | `UnicastResponse` |
| 211 | `ReconciliationSketch` | `ErlayReconciliation` |
| 212 | `ReconciliationResponse` | `ErlayReconciliation` |
| 213 | `StemTransaction` | `DandelionStem` |
| 214 | `PlumtreeLazyAnnounce` | `PlumtreeLazy` |
| 215 | `PlumtreePrune` | `PlumtreeControl` |
| 216 | `PlumtreeGraft` | `PlumtreeControl` |
| 217 | `PlumtreeRequestByHash` | `PlumtreePull` |
| 218 | `RegisterPeer` | `UnicastToIntroducer` |
| 219 | `RegisterAck` | `UnicastFromIntroducer` |

A Plumtree-eager consensus type MUST NOT be flooded naively, and a unicast request/response MUST NOT be
broadcast. INT-016 tests assert every opcode routes by its declared strategy.

##### Dispatch authority — `broadcast_dig` / `send_dig`

`route_dig_message` is not only the routing map; it is the **live per-opcode dispatch authority**.
The two `GossipHandle` entry points below are the ONLY sanctioned way to put a `200..=219` opcode on
the wire — a caller MUST NOT hand-frame a DIG opcode and call `broadcast` / `send_directed_message`
directly. Both frame the opcode through the single encoder `frame_dig_message`, which writes the
`DigMessageType` discriminant directly into `DigMessage::msg_type` as a raw `u8`. No Chia enum is
consulted or extended: `ProtocolMessageTypes` is a closed `#[repr(u8)]` enum that cannot name a DIG
opcode, and the raw-byte envelope is what makes the 200-222 band expressible without forking it.
Dispatch then proceeds by strategy:

| Strategy (opcodes) | Entry point | Behaviour | Wrong entry point |
|--------------------|-------------|-----------|-------------------|
| `PlumtreeEager` (200/201/202/207), `BroadcastFlood` (208) | `broadcast_dig` | fan-out via `broadcast()` — **seen-set-deduped + message-cached** | `send_dig` → `WrongDispatchShape` |
| `UnicastRequest` (203/205/209), `UnicastResponse` (204/206/210) | `send_dig` | unicast via `send_directed_message()` — **NOT seen-set-deduped** (a directed request is never content-deduped) | `broadcast_dig` → `WrongDispatchShape` |
| `UnicastToIntroducer` (218), `UnicastFromIntroducer` (219) | neither | classified correctly, then `UseDedicatedIntroducerMethod` — introducer traffic uses the bespoke `IntroducerClient` socket, not the peer map (`register_with_introducer` / `RegisterAck`) | — |
| `ErlayReconciliation` (211/212), `DandelionStem` (213), `PlumtreeLazy` (214), `PlumtreeControl` (215/216), `PlumtreePull` (217) | neither | `StrategyNotYetProduced { strategy, opcode }` — these are STATE-only with no live producer; the real send leg lands with the producer (fail-safe, never a speculative send) | — |

Fan-out dissemination is seen-set-deduped; unicast dissemination is not. INT-017 tests assert every
opcode's dispatch outcome-class equals its `route_dig_message` classification (the anti-drift guard).

---

## 9. Compatibility Notes

### 9.1 Crate Boundary

`dig-gossip` is a **library crate** (`lib`). It wraps `dig-peer-protocol` (and, through it, the Chia crates) to provide a gossip layer. It does **not** include block validation, CLVM, mempool, coinstate, or consensus.

**Input**: `chia-protocol::Message` (or typed `T: Streamable + ChiaProtocolMessage`) via `broadcast()` / `send_to()`.
**Output**: `(PeerId, dig_peer_protocol::DigMessage)` via inbound channel receiver.

### 9.2 What dig-gossip Implements vs Reuses

| Component | Source | dig-gossip Role |
|-----------|--------|----------------|
| Wire protocol types | `chia-protocol` | **Reuse** (re-export) |
| Peer connection (WebSocket + TLS) | `dig_peer_protocol::DigLink` | **Reuse** |
| Handshake flow | `chia-protocol::Handshake` over the raw WebSocket, then `DigLink` | **Reuse** the wire struct; the flow is dig-gossip's own (it must capture the SPKI DER) |
| Rate limiting | `dig_peer_protocol::OpcodeRateLimiter` (Chia bound) + `DigRateLimiter` (DIG per-opcode bound) | **Reuse** the Chia table; the DIG table is dig-gossip's own |
| TLS certificates | `chia-ssl` + the re-exported TLS utils | **Reuse** |
| DNS resolution | the re-exported `Network` | **Reuse** |
| Ban/trust management | the re-exported `ClientState` | **Reuse** + extend with reputation |
| Serialization | `chia-traits::Streamable` | **Reuse** |
| Address manager | Chia Python `address_manager.py` | **Port to Rust** (no crate exists) |
| Discovery loop | Chia Python `node_discovery.py` | **Port to Rust** (no crate exists) |
| Introducer peers | Chia Python `introducer_peers.py` | **Port to Rust** (no crate exists) |
| Inbound connection listener | New | **Implement** (`DigLink::from_server_websocket` exists) |
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
│   │   │                              #   PeerConnection (wraps dig_peer_protocol::DigLink)
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
│   │   └── listener.rs                # TcpListener + TLS accept + DigLink::from_server_websocket()
│   │                                  #   (DigLink handles the rest)
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
    ├── connection_tests.rs            # Handshake + DigLink upgrade, lifecycle
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
    Bytes32, Handshake,
    NewPeak, NewTransaction, RequestTransaction, RespondTransaction,
    RequestBlock, RespondBlock, RejectBlock,
    RequestBlocks, RespondBlocks, RejectBlocks,
    NewUnfinishedBlock, RequestUnfinishedBlock, RespondUnfinishedBlock,
    RequestMempoolTransactions,
    RequestPeers, RespondPeers,
    SpendBundle, FullBlock, TimestampedPeerInfo,
};
pub use dig_peer_protocol::{
    Bytes, DigLink, DigMessage, LinkError, LinkOptions,
    NodeType, ProtocolMessageTypes,
    OpcodeRateLimiter, OpcodeRateLimits,
    // Re-exported Chia surface
    Client, ClientState, Network,
    RateLimits, RateLimit, V2_RATE_LIMITS,
    ClientError, load_ssl_cert,
    ChiaCertificate, Streamable,
};

// =========================================================================
// DIG-specific types (implemented in this crate)
// =========================================================================
pub use types::peer::{PeerId, PeerInfo, PeerConnection};
pub use types::config::{GossipConfig, IntroducerConfig, RelayConfig};
pub use types::stats::{GossipStats, RelayStats};
pub use types::reputation::{PeerReputation, PenaltyReason};
pub use types::dig_messages::DigMessageType;
pub use discovery::introducer_register_wire::{RegisterPeer, RegisterAck};
pub use discovery::introducer_wire::{RequestPeersIntroducer, RespondPeersIntroducer};

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
native-tls = ["dig-peer-protocol/native-tls", "dep:native-tls", "dep:tokio-native-tls"]      # native-tls outbound + inbound acceptor
rustls = ["dig-peer-protocol/rustls", "dep:rustls", "dep:tokio-rustls", "dep:rustls-pemfile"] # rustls outbound + inbound acceptor (#1371)
relay = []                                        # Relay fallback + NAT traversal support
erlay = ["minisketch-rs"]                         # ERLAY-style transaction relay with set reconciliation
compact-blocks = ["siphasher"]                    # Compact block relay (BIP 152 equivalent)
dandelion = []                                    # Dandelion++ transaction origin privacy
tor = ["arti-client", "tokio-socks"]             # Tor/SOCKS5 proxy transport (opt-in)
```

### 10.4 Cargo.toml Dependencies

```toml
[dependencies]
# The DIG peer wire — the single path to the Chia crates.
dig-peer-protocol = { version = "0.4", default-features = false }

# Chia crates named directly only because `chia_streamable_macro` reads Cargo.toml
# for them and generates `chia_protocol::` paths at compile time. Code imports these
# types through `dig-peer-protocol`, never from these entries.
chia-protocol = "0.26"
chia-traits = "0.26"
chia-sha2 = "0.26"
chia_streamable_macro = "0.26"

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

- **Outbound connect integration**: connect two nodes through the outbound module, verify handshake with DIG `network_id`.
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
- **Rate limiting**: verify `InboundRateLimiter` enforces both the Chia bound and the DIG per-opcode bound on DIG message types.
- **Address manager persistence**: save, reload, verify peers restored.
- **AS-level diversity**: verify outbound connections span distinct AS numbers, reject second connection to same AS.

### 11.3 Benchmark Tests

- **Message throughput**: messages/second through `DigLink`.
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
