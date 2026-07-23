# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.15.0] - 2026-07-22

### Miscellaneous
- **deps:** Move dig-nat to the 0.11 peer stack (#1550) — unifies dig-node on ONE dig-nat 0.11 (enable_accept); additive/API-compatible, no code change; preserves #1541 (nat_identity) + #1517 (auto-dial)

## [0.14.0] - 2026-07-23

### Features
- **dig-gossip:** Inject persistent NodeCert as the dig-nat transport identity (#1541) (#21)

## [0.13.0] - 2026-07-22

### Bug Fixes
- **dig-gossip:** Pool auto-dial pins discovered peer_id + tries the relay circuit (#1517) (#20)

## [0.12.0] - 2026-07-22

### Features
- **dig-gossip:** Opcode 222 HoldingsAnnounce wire + verify + KATs (#1428) (#19)

## [0.11.0] - 2026-07-21

### Features
- **dig-gossip:** Route_dig_message per-opcode dispatch authority (#1404) (#18)

## [0.10.0] - 2026-07-21

### Features
- **deps:** Dig-peer-protocol 0.2 + dig-nat 0.8 migration + per-opcode routing map (v0.10.0) (#17)

## [0.9.0] - 2026-07-21

### Bug Fixes
- **dig-gossip:** Rustls inbound acceptor captures peer cert on Linux (#1371) (#16)

## [0.8.0] - 2026-07-20

### Features
- **gossip:** Store-melted broadcast wire — StoreMelted opcode 221 + StoreMeltedAnnounce (#1316)

## [0.7.1] - 2026-07-20

### Chores
- **deps:** Bump dig-nat to 0.7 (full NAT ladder unification, #836) (#14)

## [0.7.0] - 2026-07-20

### Features
- **deps:** Adopt dig-nat 0.6.0 + dig-tls (self-signed→CA-signed mTLS cutover) (#13)

## [0.6.2] - 2026-07-20

### Refactor
- **peer:** Consume dig-nat's canonical peer_id derivation (#12)

## [0.6.1] - 2026-07-19

### Chores
- **deps:** Consume dig-nat from crates.io (0.5), drop git dep + adapt to 0.5 API (#11)

## [0.6.0] - 2026-07-19

### Bug Fixes
- **stream:** Bound StreamReassembler (chunk/byte/stream caps, DoS) (#8)

## [0.5.0] - 2026-07-19

### Features
- **dig-message:** Opcode-220 transport seam + streaming helper (WU6) (#7)

## [0.4.0] - 2026-07-18

### Features
- **discovery:** Migrate address ordering + outbound dial to dig-ip (#1030) (#6)

## [0.3.0] - 2026-07-18

### Features
- **dig-gossip:** B1 dialable-peer fold + self-filter, B2 relay-transport connected-count (#924 WU4) (#5)

## [0.2.1] - 2026-07-17

### Bug Fixes
- **deps:** Widen dig-constants req to >=0.2,<0.4 + guard premature crates.io publish (#4)

## [0.2.0] - 2026-07-17

### Features
- **discovery:** Consume dig-nat persistent-reservation peer discovery + count relay-reachable peers (#3)

## [0.1.1] - 2026-07-12

### Bug Fixes
- **deps:** Re-resolve DIG git deps to rewritten (co-author/signed) revs

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Release automation (git-cliff changelog + tag on merge); publish is manual workflow_dispatch (#230)- Re-arm crates.io auto-publish on version tag (token in org secrets; auto-publish-everything #230)- Add flaky-test management (#489) (#2)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog

## [0.1.0] - 2026-04-16

### Features
- **STR-001:** Baseline Cargo.toml, features, and verification tests- **STR-002:** Module hierarchy per SPEC 10.1 / STR-002 checklist- **STR-003:** Crate-root re-exports per SPEC 10.2- **STR-004:** Feature flags, tor deps, and verification tests- **STR-005:** Test harness, GossipConfig and PeerConnection fields- **API-001:** GossipService new/start/stop and shared state- **api-002:** GossipHandle RPC surface (stub implementation)- **api-003:** Complete GossipConfig field set and dedicated tests- **api-004:** GossipError Clone, Arc ClientError, ERLAY sketch variants- **api-005:** PeerConnection verification, TLS peer_id hash, api_005 tests- **api-006:** PeerReputation, PenaltyReason, and integration tests- **api-007:** PeerInfo host/port with get_group and get_key- **api-008:** GossipStats and RelayStats with live snapshot wiring- **api-009:** DigMessageType 200-217, serde u8, TryFrom; workflow rules- **api-010:** IntroducerConfig and RelayConfig with serde defaults- **api-011:** Add ExtendedPeerInfo and VettedPeer with tests- **con-001:** Outbound WSS connect, RequestPeers, address manager hook- **connection:** Implement CON-002 inbound listener and verification- **connection:** Implement CON-003 handshake validation- **CON-005:** Per-connection inbound rate limiting and tests- **CON-006:** Per-connection wire metrics and GossipStats aggregation- **connection:** Implement CON-007 peer banning with ClientState mirror- **discovery:** Implement DSC-001 AddressManager (Chia address_manager.py port)- **discovery:** DSC-002 address manager peers-file persistence- **discovery:** DSC-003 DNS seeding via Network::lookup_all- **discovery:** DSC-004 introducer peer query (wire + client)- **discovery:** DSC-005 introducer registration (RegisterPeer/Ack)- **discovery:** DSC-006 discovery loop with DNS-first and introducer exponential backoff- **discovery:** DSC-007 peer exchange with per-request and global caps- **discovery:** DSC-008 feeler connections on Poisson schedule (240s avg)- **discovery:** DSC-009 parallel connection establishment (batch of 8)- **discovery:** DSC-010 AS-level diversity (one outbound per AS number)- **discovery:** DSC-011 /16 subnet group filter (fast first-pass)- **discovery:** DSC-012 IntroducerPeers vetting state machine- **relay:** RLY-001 relay protocol types (RelayMessage enum + RelayPeerInfo)- **relay:** RLY-002/003/005/006 relay client (send, broadcast, peers, ping)- **relay:** RLY-004/007/008 auto-reconnect, NAT traversal, transport selection- **gossip:** PLT-001/002/003/004/005/006/007/008 Plumtree core + seen set + message cache- **gossip:** PLT-009 Plumtree wire types (LazyAnnounce, Prune, Graft, RequestByHash)- **gossip:** CBK-001 through CBK-006 compact block relay (BIP 152 style)- **gossip:** ERL-001 through ERL-008 ERLAY transaction relay- **gossip:** PRI-001 through PRI-008 priority lanes + adaptive backpressure- **performance:** PRF-001 through PRF-006 latency scoring + benchmarks- **concurrency:** CNC-001 through CNC-006 thread safety + task architecture- **privacy:** PRV-001 through PRV-010 Dandelion++ + PeerId rotation + Tor- **requirements:** INT-001 through INT-012 integration requirements- **integration:** INT-001 broadcast via Plumtree (eager/lazy routing)- **gossip:** Implement broadcaster.rs + latency.rs (no more stubs)- **integration:** INT-002 through INT-012 wiring + 66 tests- **requirements:** INT-013/014/015 public API quality requirements- **api:** INT-013/014/015 clean public API + crate docs + lifecycle test- **docs:** Comprehensive README + PRV-006 config fields + INT tracking update- Add dig-protocol crate (DIG wire types extending chia-protocol)

### Bug Fixes
- **CON-004:** Keepalive with vendored chia-sdk-client full-duplex fix- **clippy:** Resolve all -D warnings errors for CI

### Refactor
- **tests:** Split combined test files into per-requirement files- Migrate dig-gossip to import from dig-protocol

### Styling
- Cargo fmt

### Chores
- Add root package.json for local GitNexus (npm/npx)- Add CI publish workflow + cursor MCP config- Depend on dig-protocol 0.1.1 from crates.io

### CON-008
- Dedicated tests and docs for handshake version sanitization

### CON-009
- Vendored native-tls mTLS inbound + con_009_tests


