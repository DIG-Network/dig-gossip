# Connection - Normative Requirements

> **Domain:** connection
> **Prefix:** CON
> **Spec reference:** [SPEC.md - Section 5](../../resources/SPEC.md)

## Requirements

### CON-001: Outbound Connection via connect_peer()

Outbound connections MUST use `chia-sdk-client::connect_peer()`. TLS MUST be loaded via `load_ssl_cert()` or generated via `ChiaCertificate::generate()`. A TLS connector MUST be created. The `Handshake` MUST include the DIG `network_id`. The resulting `Peer` MUST be wrapped in `PeerConnection` with gossip metadata. `RequestPeers` MUST be sent after a successful outbound connection.

**Spec reference:** SPEC Section 5.1 (Outbound Connection)

### CON-002: Inbound Connection Listener

Inbound connections MUST be accepted via `TcpListener`, TLS handshake, `tokio_tungstenite::accept_async()`, and `Peer::from_websocket()`. The server MUST receive and validate the inbound `Handshake`, send a `Handshake` response, wrap in `PeerConnection`, add the peer to the address manager "new" table, and relay peer info to other connected peers.

**Spec reference:** SPEC Section 5.2 (Inbound Connection)

### CON-003: Handshake Validation

Handshake validation MUST reject peers with mismatched `network_id`. Incompatible `protocol_version` values MUST be rejected. The `software_version` field MUST be sanitized by stripping Unicode Cc and Cf characters. The `software_version` MUST be no longer than 128 bytes after sanitization.

**Spec reference:** SPEC Section 5.1, 5.2; Chia ws_connection.py:61-63

### CON-004: Keepalive via Ping/Pong

A `Ping` message MUST be sent at `PING_INTERVAL_SECS` (30-second) intervals. If no `Pong` response is received within `PEER_TIMEOUT_SECS` (90 seconds), the connection MUST be disconnected.

**Spec reference:** SPEC Section 2.13 (Constants: PING_INTERVAL_SECS, PEER_TIMEOUT_SECS)

### CON-005: Per-Connection Rate Limiting

Inbound connections MUST each have a separate `chia-sdk-client::RateLimiter` instance initialized with `V2_RATE_LIMITS`. DIG extension message types (200+ range) MUST be added to the rate limit configuration. Outbound rate limiting is handled internally by `Peer::send_raw()`.

**Spec reference:** SPEC Section 5.3 (Rate Limiting)

### CON-006: Connection Metrics Tracking

`PeerConnection` MUST track: `bytes_read`, `bytes_written`, `messages_sent`, `messages_received`, `last_message_time`, and `creation_time`. These fields MUST be updated on every message send and receive.

**Spec reference:** SPEC Section 2.4 (PeerConnection)

### CON-007: Peer Banning via Reputation

Peer banning MUST use `ClientState::ban()` combined with `PeerReputation` penalty accumulation. A peer MUST be banned when `penalty_points` reaches `PENALTY_BAN_THRESHOLD` (100 points). Banned peers MUST be automatically unbanned after `BAN_DURATION_SECS` (3600 seconds).

**Spec reference:** SPEC Sections 2.5, 2.13 (PeerReputation, Constants)

### CON-008: Version String Sanitization

The `software_version` field from the `Handshake` MUST have Unicode Cc (control) and Cf (format) characters stripped. This matches the sanitization in Chia's `ws_connection.py:61-63`.

**Spec reference:** SPEC Section 5.1, 5.2; Chia ws_connection.py:61-63

### CON-009: Mandatory Mutual TLS (mTLS) via chia-ssl on All Peer Connections

ALL peer-to-peer connections (both inbound and outbound) MUST use mutual TLS (mTLS) where both sides present `chia-ssl` certificates. TLS certificates MUST be managed exclusively via the `chia-ssl` crate (`ChiaCertificate::generate()` for new nodes, `load_ssl_cert()` for existing). Outbound connections MUST use `create_native_tls_connector()` or `create_rustls_connector()` from `chia-sdk-client`, which include the node's own certificate as a client cert for mutual authentication. Inbound connections MUST use a TLS acceptor configured with `verify_mode = CERT_REQUIRED` (matching Chia's [`server.py:67`](https://github.com/Chia-Network/chia-blockchain/blob/6e7a4954edccd8ab83fcacf938cfc42ddfcad7f2/chia/server/server.py#L67)) so the connecting peer MUST present its certificate. Connections where the peer does not present a certificate MUST be rejected. Unencrypted WebSocket connections (plain `ws://`) MUST be rejected. Server-only TLS (where only the listener has a cert) MUST NOT be accepted for P2P — both sides MUST present certificates. Peer identity (`PeerId`) MUST be derived from SHA256 of the remote peer's TLS certificate public key, extracted during the mTLS handshake. Relay connections are exempt from mTLS (they use standard `wss://` server-only TLS).

**Spec reference:** SPEC Section 5.3 (Mandatory Mutual TLS), Section 1.2, Section 1.3 Design Decision 4, Section 1.5 Behavior 3, Section 2.2 (PeerId from TLS key)
