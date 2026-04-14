# Crate API - Verification Matrix

> **Domain:** crate_api
> **Prefix:** API
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| API-001 | verified | GossipService constructor                  | `tests/api_001_tests.rs`: new/start/stop lifecycle, TLS load/generate, IoError path, config validation; `GossipHandle::health_check` after stop                                      |
| API-002 | verified | GossipHandle methods                       | `tests/api_002_tests.rs`: clone/inbound subscription, broadcast (exclude), broadcast_typed, send_to (known/unknown/banned), request peers + timeout path, stats, peer_count, connected_peers/get_connections (empty until CON-001), connect_to (success/duplicate/self/max), disconnect, ban/penalize/auto-ban, introducer + relay stubs, post-stop errors |
| API-003 | verified | GossipConfig struct fields                 | `tests/api_003_tests.rs`: full struct literal + field reads; defaults (listen_addr, targets, max_connections, intervals, fanout, max_seen); optional introducer/relay/subsystems; `Network` / `Bytes32` / `PeerOptions` bindings; `#[cfg(feature="tor")]` tor slot with `--all-features` |
| API-004 | verified | GossipError enum variants                  | `tests/api_004_tests.rs`: Display strings per API-004 table; `From<ClientError>` / `?`; `Clone` (incl. ClientError via Arc); `Debug`; Sketch* variants |
| API-005 | verified | PeerConnection wraps Peer with metadata    | `tests/api_005_tests.rs`: all fields + initial bytes/reputation; inbound/outbound; TLS peer_id derivation (ChiaCertificate + x509-parser); loopback WS RequestPeers → inbound_rx |
| API-006 | --     | PeerReputation and PenaltyReason             | Unit test penalty accumulation, ban threshold, RTT tracking, score computation        |
| API-007 | --     | PeerId type alias and PeerInfo               | Unit test PeerId is Bytes32; PeerInfo get_group/get_key return correct values         |
| API-008 | --     | GossipStats and RelayStats                   | Unit test Default impl and field population from a running service                    |
| API-009 | --     | DigMessageType enum                          | Unit test discriminant values, round-trip serialization, no collision with Chia types  |
| API-010 | --     | IntroducerConfig and RelayConfig             | Unit test Default impls, Serialize/Deserialize round-trip, field validation            |
| API-011 | --     | ExtendedPeerInfo and VettedPeer              | Unit test construction, field access, and compatibility with address manager           |
