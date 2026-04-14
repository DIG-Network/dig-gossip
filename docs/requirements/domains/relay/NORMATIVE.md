# Relay - Normative Requirements

> **Domain:** relay
> **Prefix:** RLY
> **Spec reference:** [SPEC.md - Section 7](../../resources/SPEC.md)

## Requirements

### RLY-001: Relay Client Connect and Register

Relay client MUST connect to the relay server via WebSocket and send `Register { peer_id, network_id, protocol_version }`. Server MUST respond with `RegisterAck { success, message, connected_peers }`. Connection MUST fail gracefully with `GossipError::RelayError` on timeout or rejection.

The `RelayMessage` enum MUST define all relay protocol wire types as a single `#[serde(tag = "type")]` enum serialized as JSON. The complete set of variants is: `Register`, `RegisterAck`, `Unregister`, `RelayGossipMessage`, `Broadcast`, `PeerConnected`, `PeerDisconnected`, `GetPeers`, `Peers`, `Ping`, `Pong`, `Error`, `HolePunchRequest`, `HolePunchCoordinate`, `HolePunchResult`. Individual variant semantics are specified in RLY-001 through RLY-007.

**Spec reference:** SPEC Section 7 (Relay Fallback), Section 5.1 (Connection Lifecycle - Relay fallback)

### RLY-002: Relay Message Forwarding

Relay client MUST support forwarding messages to a specific peer via `RelayGossipMessage { from, to, payload, seq }`. The `from` field MUST be the sender's PeerId, `to` MUST be the target PeerId, `payload` MUST be the serialized message bytes, and `seq` MUST be a monotonically increasing sequence number.

**Spec reference:** SPEC Section 7 (Relay Fallback)

### RLY-003: Relay Broadcast

Relay client MUST support broadcasting messages to all relay-connected peers via `Broadcast { from, payload, exclude }`. The `exclude` list MUST contain PeerIds that should not receive the broadcast (e.g., the original sender of a relayed message).

**Spec reference:** SPEC Section 7 (Relay Fallback), Section 8.1 step 7 (broadcast algorithm relay integration)

### RLY-004: Auto-Reconnect on Disconnect

Relay service MUST automatically reconnect on unexpected disconnects. Reconnect delay MUST be configurable via `RelayConfig::reconnect_delay_secs` (default: 5). Reconnection attempts MUST stop after `RelayConfig::max_reconnect_attempts` (default: 10) consecutive failures.

**Spec reference:** SPEC Section 2.12 (RelayConfig), Section 7 (Relay Fallback)

### RLY-005: Relay Peer List

Relay client MUST support querying connected peers via `GetPeers { network_id }`. Server MUST respond with `Peers { peers }` where peers is a `Vec<RelayPeerInfo>`. The peer list MUST be used by the gossip layer to know which peers are reachable via relay.

**Spec reference:** SPEC Section 2.9 (RelayPeerInfo), Section 7 (Relay Fallback)

### RLY-006: Relay Keepalive

Relay client MUST send `Ping` messages at the interval specified by `RelayConfig::ping_interval_secs` (default: 30). Server MUST respond with `Pong`. If no `Pong` is received within `PEER_TIMEOUT_SECS` (90), the connection MUST be considered dead and reconnection initiated.

**Spec reference:** SPEC Section 2.12 (RelayConfig), Section 2.13 (Constants - PING_INTERVAL_SECS, PEER_TIMEOUT_SECS)

### RLY-007: NAT Traversal Hole Punching

Relay client MUST support NAT traversal via `HolePunchRequest` sent to the relay with the peer's observed external address. Relay MUST forward `HolePunchCoordinate` to the target peer. Both peers MUST attempt simultaneous direct connection. On success, traffic MUST migrate to the direct connection and the relay path MUST be dropped. On failure, relay path MUST be kept and retry MUST occur after `HOLE_PUNCH_RETRY_SECS` (default: 300). The constant `HOLE_PUNCH_RETRY_SECS: u64 = 300` MUST be defined in `src/constants.rs`. **Note:** This constant is defined in SPEC Section 7.1 but not in the SPEC Section 2.13 constants listing; it is nonetheless a required constant for this crate.

**Crate-internal types:** `HolePunchState` (enum with variants `Idle`, `AwaitingCoordination`, `Connecting`, `Upgraded`, `RetryScheduled`) is a crate-internal type used to track the NAT traversal state machine for a single peer pair. It is NOT part of the public API and MUST NOT be re-exported from `lib.rs`.

**Spec reference:** SPEC Section 7.1 (NAT Traversal Upgrade)

### RLY-008: Transport Selection

Transport selection MUST attempt direct P2P connection first. If direct connection fails, relay MUST be used as fallback. The `RelayConfig::prefer_relay` flag (default: false) MUST override this behavior to use relay as the primary transport when set to true. The caller MUST see no difference in message delivery regardless of transport.

**Spec reference:** SPEC Section 7 (Relay Fallback), Design Decision 8 (Relay as fallback, not primary)
