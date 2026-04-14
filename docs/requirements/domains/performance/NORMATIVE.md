# Performance - Normative Requirements

> **Domain:** performance
> **Prefix:** PRF
> **Spec reference:** [SPEC.md - Sections 1.8, 6.4, 11.3](../../resources/SPEC.md)

## Requirements

### PRF-001: Latency-Aware Scoring

Peers MUST be scored by RTT measured from Ping/Pong exchanges. A rolling average over the last RTT_WINDOW_SIZE (10) measurements MUST be maintained. The composite score MUST be computed as `score = trust_score * (1 / avg_rtt_ms)`. RTT data MUST be stored in PeerReputation fields: avg_rtt_ms, rtt_history, and score.

**Spec reference:** SPEC Section 1.8 (Improvement #6: Latency-aware peer scoring), Section 2.5 (PeerReputation), Section 4.4 (Constants: RTT_WINDOW_SIZE)

### PRF-002: Peer Selection Preference

Outbound peer selection MUST prefer higher-scored peers. AddressManager.select_peer() MUST incorporate the composite peer score when choosing among candidate peers that pass group/AS diversity filters. When multiple candidates are available, the one with the highest score MUST be preferred.

**Spec reference:** SPEC Section 1.8 (Improvement #6), Section 6.4 (Discovery Loop, item 6: Latency-aware peer selection)

### PRF-003: Plumtree Tree Optimization

The Plumtree spanning tree MUST prefer low-latency peers as eager push targets. When a lower-latency peer is discovered via lazy push or new RTT measurement, it MUST replace a higher-latency eager peer. The replaced peer MUST be demoted to lazy and sent a PRUNE message.

**Crate-internal types:** `TreeOptimizationAction` (enum or similar decision type used internally to represent optimization decisions such as "swap eager peer X for lower-latency peer Y") is a crate-internal type. It is NOT part of the public API and MUST NOT be re-exported from `lib.rs`.

**Spec reference:** SPEC Section 1.8 (Improvement #6), Section 2.5 (PeerReputation.avg_rtt_ms: "Used for latency-aware peer selection and Plumtree tree optimization"), Section 8.1 (Plumtree Structured Gossip)

### PRF-004: Parallel Bootstrap

Connection establishment during bootstrap MUST use PARALLEL_CONNECT_BATCH_SIZE (8) concurrent connection attempts via FuturesUnordered. The system MUST NOT wait for one connection attempt to complete before starting the next. All batch members MUST be in-flight concurrently.

**Spec reference:** SPEC Section 1.8 (Improvement #5: Parallel connection establishment), Section 4.4 (PARALLEL_CONNECT_BATCH_SIZE), Section 6.4 (Discovery Loop, item 2)

### PRF-005: Bandwidth Benchmarks

Bandwidth benchmarks over a simulated 50-node network MUST demonstrate: Plumtree total bytes < 40% of naive flood for 1000 messages; compact block relay bytes < 10% of full block relay across 10 hops; ERLAY transaction relay bytes < 20% of flood relay per transaction across a 50-connection node.

**Spec reference:** SPEC Section 11.3 (Benchmark Tests: Plumtree vs flood, Compact block vs full block, ERLAY vs flood)

### PRF-006: Latency Benchmarks

Latency benchmarks MUST demonstrate: NewPeak delivery p99 latency < 50ms during concurrent bulk sync (RespondBlocks transfer); bootstrap of 8 outbound connections completes in < 15 seconds using parallel establishment.

**Spec reference:** SPEC Section 11.3 (Benchmark Tests: Priority lane latency, Bootstrap time)
