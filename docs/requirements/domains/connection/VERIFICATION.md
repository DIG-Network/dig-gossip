# Connection - Verification Matrix

> **Domain:** connection
> **Prefix:** CON
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                          | Verification Approach                                                                      |
|---------|--------|--------------------------------------------------|--------------------------------------------------------------------------------------------|
| CON-001 | verified | Outbound connection via connect_peer() | `tests/con_001_tests.rs`: TLS load/generate/connector; WSS harness handshake + RequestPeers; `GossipHandle::connect_to` + `AddressManager` batch; `ClientError` → `GossipError`; peer field wiring / creation_time |
| CON-002 | gap    | Inbound connection listener                      | Integration test: start listener, connect client, verify handshake exchange and addr mgr    |
| CON-003 | gap    | Handshake validation                             | Unit tests: reject mismatched network_id, reject bad protocol_version, sanitize versions    |
| CON-004 | gap    | Keepalive via Ping/Pong                          | Integration test: verify Ping sent at 30s, disconnect on Pong timeout after 90s             |
| CON-005 | gap    | Per-connection rate limiting                      | Unit test: create RateLimiter per connection with V2_RATE_LIMITS, verify DIG types added    |
| CON-006 | gap    | Connection metrics tracking                       | Unit test: send/receive messages and verify bytes/message counters and timestamps updated    |
| CON-007 | gap    | Peer banning via reputation                       | Unit test: accumulate penalties to 100, verify ban; wait 3600s, verify auto-unban            |
| CON-008 | gap    | Version string sanitization                       | Unit test: strip Cc/Cf Unicode from software_version, verify length <= 128 bytes             |
| CON-009 | gap    | Mandatory mTLS via chia-ssl on all P2P connections | Integration tests: outbound presents client cert, inbound requires client cert (CERT_REQUIRED), plain ws rejected, server-only TLS rejected, PeerId derived from remote cert by both sides, relay exempt |
