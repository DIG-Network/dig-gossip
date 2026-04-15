# Crate API - Verification Matrix

> **Domain:** crate_api
> **Prefix:** API
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| API-001 | verified | GossipService constructor                  | `tests/api_001_tests.rs`: new/start/stop lifecycle, TLS load/generate, IoError path, config validation; `GossipHandle::health_check` after stop                                      |
| API-002 | verified | GossipHandle methods                       | `tests/api_002_tests.rs`: clone/inbound subscription, broadcast (exclude), broadcast_typed, send_to (known/unknown/banned), request peers + timeout path, stats, peer_count, connected_peers/get_connections (empty until CON-001), connect_to (success/duplicate/self/max), disconnect, ban/penalize/auto-ban, introducer + relay stubs, post-stop errors |
| API-003 | verified | GossipConfig struct fields                 | `tests/api_003_tests.rs`: full struct literal + field reads; defaults (listen_addr, targets, max_connections, intervals, fanout, max_seen, **dns_seed_timeout / dns_seed_batch_size**); optional introducer/relay/subsystems; `Network` / `Bytes32` / `PeerOptions` bindings; `#[cfg(feature="tor")]` tor slot with `--all-features` |
| API-004 | verified | GossipError enum variants                  | `tests/api_004_tests.rs`: Display strings per API-004 table (incl. `AddressManagerStore` / DSC-002); `From<ClientError>` / `?`; `Clone` (incl. ClientError via Arc); `Debug`; Sketch* variants |
| API-005 | verified | PeerConnection wraps Peer with metadata    | `tests/api_005_tests.rs`: all fields + initial bytes/reputation; inbound/outbound; TLS peer_id derivation (ChiaCertificate + x509-parser); loopback WS RequestPeers → inbound_rx |
| API-006 | verified | PeerReputation and PenaltyReason           | `tests/api_006_tests.rs`: defaults; penalty accumulation + saturating add; auto-ban at threshold + ban_until; `refresh_ban_status` expiry; RTT window/mean/score; zero-RTT score; `as_number`; all `PenaltyReason` variants + CON-007 weight regression; `last_penalty_reason` |
| API-007 | verified | PeerId type alias and PeerInfo             | `tests/api_007_tests.rs`: Bytes32 interchange; Debug/Clone/Eq/Hash + HashMap key; get_group IPv4/IPv6/mapped/hostname; get_key layouts, uniqueness, determinism |
| API-008 | verified | GossipStats and RelayStats | `tests/api_008_tests.rs`: Default/Debug/Clone; populated structs; `stats()` topology + cumulative counters + disconnect monotonic `total_connections`; `relay_stats` None/Some; inject → `messages_received`; send_to/broadcast → `messages_sent` |
| API-009 | verified | DigMessageType enum | `tests/api_009_tests.rs`: per-variant `as u8`; uniqueness; serde_json + bincode round-trip; TryFrom; HashSet; sample Chia `msg_type` below200 vs DIG band |
| API-010 | verified | IntroducerConfig and RelayConfig | `tests/api_010_tests.rs`: field access; all SPEC defaults; Debug/Clone; JSON + bincode round-trip; partial JSON defaults |
| API-011 | verified | ExtendedPeerInfo and VettedPeer | `tests/api_011_tests.rs`: all ExtendedPeerInfo fields + new/tried/random_pos/last_success/num_attempts semantics; PeerInfo-not-TimestampedPeerInfo; VettedPeer derives + signed vetted + HashSet; `tests/str_003_tests.rs` re-export |
