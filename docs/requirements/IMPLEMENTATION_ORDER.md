# Implementation Order

Phased checklist for dig-gossip requirements. Work top-to-bottom within each phase.
After completing a requirement: write tests, verify they pass, update TRACKING.yaml, VERIFICATION.md, and check off here.

**A requirement is NOT complete until comprehensive tests verify it.**

---

## Phase 0: Crate Structure & Foundation

- [x] STR-001 — Cargo.toml with chia crate dependencies, feature gates, and metadata
- [x] STR-002 — Module hierarchy (`src/lib.rs` root, submodule layout matching SPEC Section 10.1)
- [x] STR-003 — Re-export strategy (chia-protocol, chia-sdk-client, chia-ssl types)
- [x] STR-004 — Feature flags (native-tls, rustls, relay, erlay, compact-blocks)
- [x] STR-005 — Test infrastructure (`tests/` layout, helpers, mock peer harness)

## Phase 1: Crate API Types

- [x] API-001 — GossipService constructor (`new` with GossipConfig)
- [x] API-002 — GossipHandle type (broadcast, send_to, request, inbound_receiver, stats)
- [x] API-003 — GossipConfig struct (listen_addr, peer_id, network_id, network, targets, bootstrap)
- [x] API-004 — GossipError enum (wraps ClientError, peer errors, discovery errors, relay errors)
- [x] API-005 — PeerConnection struct (wraps chia-sdk-client::Peer with gossip metadata)
- [x] API-006 — PeerReputation and PenaltyReason (penalty accumulation, ban threshold, auto-unban)
- [x] API-007 — PeerId type alias and PeerInfo with get_group()/get_key()
- [x] API-008 — GossipStats and RelayStats structs
- [ ] API-009 — DigMessageType enum (type IDs 200+ for attestation, checkpoint, status)
- [ ] API-010 — IntroducerConfig and RelayConfig structs
- [ ] API-011 — ExtendedPeerInfo and VettedPeer types (for address manager and introducer)

## Phase 2: Connection Lifecycle

- [ ] CON-001 — Outbound connection via chia-sdk-client connect_peer()
- [ ] CON-002 — Inbound connection listener (TcpListener + TLS accept + Peer::from_websocket)
- [ ] CON-003 — Handshake validation (network_id match, protocol_version compat)
- [ ] CON-004 — Keepalive (Ping/Pong, timeout detection at PEER_TIMEOUT_SECS)
- [ ] CON-005 — Rate limiting (RateLimiter with V2_RATE_LIMITS, DIG extensions)
- [ ] CON-006 — Connection state tracking (per-connection metadata on PeerConnection)
- [ ] CON-007 — Peer banning (ClientState::ban + PeerReputation penalty)
- [ ] CON-008 — Software version string sanitization (strip control/format characters)
- [ ] CON-009 — Mandatory TLS via chia-ssl on ALL peer connections (no unencrypted)

## Phase 3: Discovery

- [ ] DSC-001 — AddressManager with tried/new tables (Rust port of address_manager.py)
- [ ] DSC-002 — Address manager persistent serialization (save/load to peers file)
- [ ] DSC-003 — DNS seeding via chia-sdk-client Network::lookup_all()
- [ ] DSC-004 — Introducer query (RequestPeersIntroducer flow)
- [ ] DSC-005 — Introducer registration (DIG extension: register_peer)
- [ ] DSC-006 — Discovery loop with DNS-first then introducer with exponential backoff
- [ ] DSC-007 — Peer exchange via RequestPeers/RespondPeers on outbound connect
- [ ] DSC-008 — Feeler connections on Poisson schedule (240s average)
- [ ] DSC-009 — Parallel connection establishment (batch connect with FuturesUnordered)
- [ ] DSC-010 — AS-level diversity (one outbound per AS, cached BGP lookup)
- [ ] DSC-011 — One outbound per /16 group (fast filter before AS check)
- [ ] DSC-012 — IntroducerPeers/VettedPeer tracking (vetting state machine)

## Phase 4: Relay

- [ ] RLY-001 — Relay client connect and register (WebSocket + Register message)
- [ ] RLY-002 — Relay message forwarding (RelayGossipMessage to specific peer)
- [ ] RLY-003 — Relay broadcast (Broadcast to all relay peers)
- [ ] RLY-004 — Relay auto-reconnect with exponential backoff
- [ ] RLY-005 — Relay peer list (GetPeers/Peers exchange)
- [ ] RLY-006 — Relay keepalive (Ping/Pong)
- [ ] RLY-007 — NAT traversal hole punching via relay coordination
- [ ] RLY-008 — Transport selection (direct P2P first, relay fallback, prefer_relay override)

## Phase 5: Plumtree Structured Gossip

- [ ] PLT-001 — PlumtreeState (eager_peers, lazy_peers, lazy_queue, message_cache)
- [ ] PLT-002 — Eager push (full message to eager_peers, exclude origin)
- [ ] PLT-003 — Lazy push (hash-only LazyAnnounce to lazy_peers)
- [ ] PLT-004 — Duplicate detection: demote sender to lazy, send PRUNE
- [ ] PLT-005 — Lazy timeout: promote sender to eager via GRAFT, pull message
- [ ] PLT-006 — Tree self-healing on peer disconnect (lazy promotion)
- [ ] PLT-007 — Message cache (LRU, capacity 1000, TTL 60s) for GRAFT responses
- [ ] PLT-008 — Seen set (LRU deduplication, capacity 100K)
- [ ] PLT-009 — PlumtreeMessage wire types (LazyAnnounce, Prune, Graft, RequestByHash with DigMessageType IDs 214-217)

## Phase 6: Compact Block Relay

- [ ] CBK-001 — CompactBlock encoding (header + short TX IDs + prefilled transactions)
- [ ] CBK-002 — Short TX ID computation (SipHash with block-header-derived key, 6 bytes)
- [ ] CBK-003 — Compact block reconstruction from mempool (match short IDs)
- [ ] CBK-004 — Missing transaction request/response (RequestBlockTransactions)
- [ ] CBK-005 — Fallback to full block request on >5 missing transactions
- [ ] CBK-006 — SipHash key derivation from block header hash

## Phase 7: ERLAY Transaction Relay

- [ ] ERL-001 — Flood set selection (ERLAY_FLOOD_PEER_COUNT random peers)
- [ ] ERL-002 — Low-fanout NewTransaction flooding to flood set only
- [ ] ERL-003 — Minisketch encoding/decoding for transaction ID sets
- [ ] ERL-004 — Periodic set reconciliation per non-flood peer (RECONCILIATION_INTERVAL_MS)
- [ ] ERL-005 — Symmetric difference computation and missing tx exchange
- [ ] ERL-006 — Flood set rotation every ERLAY_FLOOD_SET_ROTATION_SECS
- [ ] ERL-007 — Inbound peers excluded from flood set
- [ ] ERL-008 — ErlayConfig struct (flood_peer_count, reconciliation_interval_ms, sketch_capacity)

## Phase 8: Priority Lanes & Backpressure

- [ ] PRI-001 — MessagePriority enum (Critical, Normal, Bulk) and assignment table
- [ ] PRI-002 — PriorityOutbound queue per connection (three VecDeques)
- [ ] PRI-003 — Priority drain order (exhaust critical, then normal, then one bulk)
- [ ] PRI-004 — Starvation prevention (1 bulk per PRIORITY_STARVATION_RATIO critical/normal)
- [ ] PRI-005 — BackpressureConfig with configurable thresholds
- [ ] PRI-006 — Tx dedup suppression at BACKPRESSURE_TX_DEDUP_THRESHOLD
- [ ] PRI-007 — Bulk message drop at BACKPRESSURE_BULK_DROP_THRESHOLD
- [ ] PRI-008 — Normal message delay at BACKPRESSURE_NORMAL_DELAY_THRESHOLD

## Phase 9: Performance & Optimization

- [ ] PRF-001 — Latency-aware peer scoring (RTT tracking from Ping/Pong, rolling average)
- [ ] PRF-002 — Peer selection preference by composite score
- [ ] PRF-003 — Plumtree tree optimization (prefer low-latency peers as eager)
- [ ] PRF-004 — Parallel bootstrap (PARALLEL_CONNECT_BATCH_SIZE concurrent connects)
- [ ] PRF-005 — Bandwidth benchmarks (Plumtree vs flood, compact vs full, ERLAY vs flood)
- [ ] PRF-006 — Latency benchmarks (NewPeak p99 during bulk sync < 50ms)

## Phase 10: Concurrency

- [ ] CNC-001 — GossipService and GossipHandle Send + Sync + Clone (inner Arc)
- [ ] CNC-002 — Task architecture (listener, discovery, serialization, cleanup, relay, per-connection)
- [ ] CNC-003 — Shared state synchronization primitives (RwLock, mpsc, AtomicU64)
- [ ] CNC-004 — Graceful shutdown (stop all tasks, disconnect peers, save state)
- [ ] CNC-005 — Address manager timestamp update on message receipt from outbound peer
- [ ] CNC-006 — Periodic cleanup task (stale connections, expired bans)

## Phase 11: Privacy

- [ ] PRV-001 — DandelionConfig struct (enabled, fluff_probability, stem_timeout, epoch)
- [ ] PRV-002 — Stem phase forwarding (single relay, not in mempool, not served)
- [ ] PRV-003 — Fluff transition (10% coin flip, mempool + broadcast on fluff)
- [ ] PRV-004 — Stem timeout force-fluff (30s liveness guarantee)
- [ ] PRV-005 — Stem relay epoch rotation (re-randomize every 600s)
- [ ] PRV-006 — PeerIdRotationConfig struct (enabled, interval, reconnect)
- [ ] PRV-007 — Certificate rotation (fresh ChiaCertificate, reconnect, independent of BLS keys)
- [ ] PRV-008 — Rotation opt-out (interval=0 disables)
- [ ] PRV-009 — TorConfig struct (enabled, socks5_proxy, onion_address, prefer_tor)
- [ ] PRV-010 — Tor transport (SOCKS5 outbound, .onion inbound, hybrid, selection order)

---

## Summary

| Phase | Domain | Count |
|-------|--------|-------|
| 0 | Crate Structure | 5 |
| 1 | Crate API | 11 |
| 2 | Connection | 9 |
| 3 | Discovery | 12 |
| 4 | Relay | 8 |
| 5 | Plumtree Gossip | 9 |
| 6 | Compact Blocks | 6 |
| 7 | ERLAY Tx Relay | 8 |
| 8 | Priority & Backpressure | 8 |
| 9 | Performance | 6 |
| 10 | Concurrency | 6 |
| 11 | Privacy | 10 |
| **Total** | | **98** |
