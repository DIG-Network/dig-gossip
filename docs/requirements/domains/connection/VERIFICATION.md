# Connection - Verification Matrix

> **Domain:** connection
> **Prefix:** CON
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                          | Verification Approach                                                                      |
|---------|--------|--------------------------------------------------|--------------------------------------------------------------------------------------------|
| CON-001 | verified | Outbound connection via connect_peer() | `tests/con_001_tests.rs`: TLS load/generate/connector; WSS harness handshake + RequestPeers; `GossipHandle::connect_to` + `AddressManager` batch; `ClientError` → `GossipError`; peer field wiring / creation_time |
| CON-002 | verified | Inbound connection listener                    | `tests/con_002_tests.rs`: bind `:0`, TLS+WSS+Handshake, wrong network_id reject, PeerConnection inbound metadata, AddressManager batch, RespondPeers relay to live peer, max_connections cap; self-connection reject on non-Windows (cert-based PeerId) |
| CON-003 | verified | Handshake validation                           | `tests/con_003_tests.rs`: sanitize Cc/Cf; protocol floor; network_id; 128-byte limit; empty id fields; integration two-node `__con003_peer_versions_for_tests` (inbound + outbound) |
| CON-004 | verified | Keepalive via Ping/Pong                        | `tests/con_004_tests.rs`: RequestPeers keepalive probe, RTT samples, bidirectional, remote stop → disconnect + ConnectionIssue penalty; config overrides for timing |
| CON-005 | verified | Per-connection rate limiting                    | `tests/con_005_tests.rs`: V2 + `dig_wire` merged limits, per-connection independence, `handle_message` / `check_dig_extension`, factor scaling, window reset, `PenaltyReason::RateLimitExceeded` points; `apply_inbound_rate_limit_violation` no-op on missing peer; inbound forwarder + `LiveSlot` limiter (listener + `connect_to`) |
| CON-006 | gap    | Connection metrics tracking                       | Unit test: send/receive messages and verify bytes/message counters and timestamps updated    |
| CON-007 | gap    | Peer banning via reputation                       | Unit test: accumulate penalties to 100, verify ban; wait 3600s, verify auto-unban            |
| CON-008 | gap    | Version string sanitization                       | Unit test: strip Cc/Cf Unicode from software_version, verify length <= 128 bytes             |
| CON-009 | gap    | Mandatory mTLS via chia-ssl on all P2P connections | Integration tests: outbound presents client cert, inbound requires client cert (CERT_REQUIRED), plain ws rejected, server-only TLS rejected, PeerId derived from remote cert by both sides, relay exempt |
