# Crate API - Verification Matrix

> **Domain:** crate_api
> **Prefix:** API
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| API-001 | verified | GossipService constructor                  | `tests/api_001_tests.rs`: new/start/stop lifecycle, TLS load/generate, IoError path, config validation; `GossipHandle::health_check` after stop                                      |
| API-002 | --     | GossipHandle methods                         | Integration tests exercising each GossipHandle method against a running service       |
| API-003 | --     | GossipConfig struct fields                   | Unit test verifying all fields exist with correct types and defaults                  |
| API-004 | --     | GossipError enum variants                    | Unit test constructing each variant; verify ClientError From impl                     |
| API-005 | --     | PeerConnection wraps Peer with metadata      | Unit test constructing PeerConnection and verifying all fields are accessible         |
| API-006 | --     | PeerReputation and PenaltyReason             | Unit test penalty accumulation, ban threshold, RTT tracking, score computation        |
| API-007 | --     | PeerId type alias and PeerInfo               | Unit test PeerId is Bytes32; PeerInfo get_group/get_key return correct values         |
| API-008 | --     | GossipStats and RelayStats                   | Unit test Default impl and field population from a running service                    |
| API-009 | --     | DigMessageType enum                          | Unit test discriminant values, round-trip serialization, no collision with Chia types  |
| API-010 | --     | IntroducerConfig and RelayConfig             | Unit test Default impls, Serialize/Deserialize round-trip, field validation            |
| API-011 | --     | ExtendedPeerInfo and VettedPeer              | Unit test construction, field access, and compatibility with address manager           |
