# Crate API - Normative Requirements

> **Domain:** crate_api
> **Prefix:** API
> **Spec reference:** [SPEC.md - Sections 2, 3, 4](../../resources/SPEC.md)

## Requirements

### API-001: GossipService Constructor

GossipService MUST provide a `new(config: GossipConfig) -> Result<Self, GossipError>` constructor that accepts a GossipConfig and sets up TLS via chia-ssl (`load_ssl_cert()` / `ChiaCertificate::generate()`). Construction MUST NOT start networking; the caller invokes `start()` separately.

**Spec reference:** SPEC Section 3.1 (Construction)

### API-002: GossipHandle Methods

GossipHandle MUST be cheaply cloneable (inner Arc) and provide the following methods: `broadcast`, `broadcast_typed`, `send_to`, `request`, `inbound_receiver`, `connected_peers`, `peer_count`, `get_connections`, `connect_to`, `disconnect`, `ban_peer`, `penalize_peer`, `discover_from_introducer`, `register_with_introducer`, `request_peers_from`, `stats`, `relay_stats`. GossipHandle is returned by `GossipService::start()`.

**Spec reference:** SPEC Section 3.2 (Lifecycle), Section 3.3 (GossipHandle)

### API-003: GossipConfig Struct Fields

GossipConfig MUST contain fields: `listen_addr`, `peer_id`, `network_id`, `network`, `target_outbound_count`, `max_connections`, `bootstrap_peers`, `introducer`, `relay`, `cert_path`, `key_path`, `peer_connect_interval`, `gossip_fanout`, `max_seen_messages`, `peers_file_path`, `peer_options`. Additionally, GossipConfig MUST contain optional sub-config fields: `dandelion: Option<DandelionConfig>` (SPEC Section 1.9.1), `peer_id_rotation: Option<PeerIdRotationConfig>` (SPEC Section 1.9.2), `tor: Option<TorConfig>` (SPEC Section 1.9.3, feature-gated behind `tor`), `erlay: Option<ErlayConfig>` (SPEC Section 8.3, feature-gated behind `erlay`), `backpressure: Option<BackpressureConfig>` (SPEC Section 8.5). Types and defaults MUST match SPEC Section 2.10 and the respective sub-config sections.

**Spec reference:** SPEC Section 2.10 (GossipConfig), Section 1.9.1 (DandelionConfig), Section 1.9.2 (PeerIdRotationConfig), Section 1.9.3 (TorConfig), Section 8.3 (ErlayConfig), Section 8.5 (BackpressureConfig)

### API-004: GossipError Enum Variants

GossipError MUST be a `#[derive(Debug, Clone, thiserror::Error)]` enum wrapping `chia-sdk-client::ClientError` via `#[from]` and providing variants: `ClientError`, `PeerNotConnected`, `PeerBanned`, `MaxConnectionsReached`, `DuplicateConnection`, `SelfConnection`, `RequestTimeout`, `IntroducerNotConfigured`, `IntroducerError`, `RelayNotConfigured`, `RelayError`, `ServiceNotStarted`, `ChannelClosed`, `IoError`, `SketchError(String)`, `SketchDecodeFailed`. The `SketchError` variant covers minisketch encoding/decoding errors during ERLAY reconciliation. `SketchDecodeFailed` is a unit variant for when sketch decoding produces no result (symmetric difference too large for sketch capacity).

**Spec reference:** SPEC Section 4 (Error Types), Section 8.3 (ERLAY reconciliation error paths)

### API-005: PeerConnection Struct

PeerConnection MUST wrap `chia-sdk-client::Peer` with gossip-specific metadata fields: `peer`, `peer_id`, `address`, `is_outbound`, `node_type`, `protocol_version`, `software_version`, `peer_server_port`, `capabilities`, `creation_time`, `bytes_read`, `bytes_written`, `last_message_time`, `reputation`, `inbound_rx`.

**Spec reference:** SPEC Section 2.4 (PeerConnection)

### API-006: PeerReputation and PenaltyReason

PeerReputation MUST track `penalty_points`, `is_banned`, `ban_until`, `last_penalty_reason`, `avg_rtt_ms`, `rtt_history`, `score`, `as_number`. PenaltyReason MUST enumerate: `InvalidBlock`, `InvalidAttestation`, `MalformedMessage`, `Spam`, `ConnectionIssue`, `ProtocolViolation`, `RateLimitExceeded`, `ConsensusError`. PeerReputation extends `chia-sdk-client::ClientState`'s binary ban/trust with numeric penalties.

**Spec reference:** SPEC Section 2.5 (PeerReputation)

### API-007: PeerId Type Alias and PeerInfo

PeerId MUST be a type alias for `chia-protocol::Bytes32` (SHA256 of TLS public key). PeerInfo MUST contain `host: String` and `port: u16` with methods `get_group() -> Vec<u8>` (/16 for IPv4, /32 for IPv6) and `get_key() -> Vec<u8>` for address manager bucket computation.

**Spec reference:** SPEC Section 2.2 (PeerId), Section 2.7 (PeerInfo)

### API-008: GossipStats and RelayStats

GossipStats MUST derive `Debug, Clone, Default` and contain fields: `total_connections`, `connected_peers`, `inbound_connections`, `outbound_connections`, `messages_sent`, `messages_received`, `bytes_sent`, `bytes_received`, `known_addresses`, `seen_messages`, `relay_connected`, `relay_peer_count`. RelayStats MUST derive `Debug, Clone, Default` and contain fields: `connected`, `messages_sent`, `messages_received`, `bytes_sent`, `bytes_received`, `reconnect_attempts`, `last_connected_at`, `relay_peer_count`, `latency_ms`.

**Spec reference:** SPEC Section 3.4 (Statistics)

### API-009: DigMessageType Enum

DigMessageType MUST be `#[repr(u8)]` and enumerate DIG L2-specific message types in the 200+ range: `NewAttestation = 200`, `NewCheckpointProposal = 201`, `NewCheckpointSignature = 202`, `RequestCheckpointSignatures = 203`, `RespondCheckpointSignatures = 204`, `RequestStatus = 205`, `RespondStatus = 206`, `NewCheckpointSubmission = 207`, `ValidatorAnnounce = 208`, `RequestBlockTransactions = 209`, `RespondBlockTransactions = 210`, `ReconciliationSketch = 211`, `ReconciliationResponse = 212`, `StemTransaction = 213`, `PlumtreeLazyAnnounce = 214`, `PlumtreePrune = 215`, `PlumtreeGraft = 216`, `PlumtreeRequestByHash = 217`. These avoid collision with Chia's `ProtocolMessageTypes`. Wire types for compact block relay (209-210), ERLAY reconciliation (211-212), Dandelion++ stem phase (213), and Plumtree protocol messages (214-217) are included alongside the original DIG L2 application types.

**Spec reference:** SPEC Section 2.3 (DIG Extension Message Types), Section 8.1 (Plumtree), Section 8.2 (Compact Block Relay), Section 8.3 (ERLAY), Section 1.9.1 (Dandelion++)

### API-010: IntroducerConfig and RelayConfig

IntroducerConfig MUST contain: `endpoint`, `connection_timeout_secs`, `request_timeout_secs`, `network_id`. RelayConfig MUST contain: `endpoint`, `enabled`, `connection_timeout_secs`, `reconnect_delay_secs`, `max_reconnect_attempts`, `ping_interval_secs`, `prefer_relay`. Both MUST derive `Debug, Clone, Serialize, Deserialize` with defaults matching the SPEC.

**Spec reference:** SPEC Section 2.11 (IntroducerConfig), Section 2.12 (RelayConfig)

### API-011: ExtendedPeerInfo and VettedPeer

ExtendedPeerInfo MUST contain: `peer_info`, `timestamp`, `src`, `random_pos`, `is_tried`, `ref_count`, `last_success`, `last_try`, `num_attempts`, `last_count_attempt`. This is a Rust port of Chia's `address_manager.py:43`. VettedPeer MUST contain: `host`, `port`, `vetted`, `vetted_timestamp`, `last_attempt`, `time_added`. This is a Rust port of Chia's `introducer_peers.py:12-28`.

**Spec reference:** SPEC Section 2.6 (ExtendedPeerInfo), Section 2.8 (VettedPeer)
