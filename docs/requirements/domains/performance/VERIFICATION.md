# Performance - Verification Matrix

> **Domain:** performance
> **Prefix:** PRF
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| PRF-001 | gap    | Latency-aware scoring via Ping/Pong RTT      | Unit test: record RTT samples, verify rolling avg and composite score computation     |
| PRF-002 | gap    | Peer selection prefers higher-scored peers    | Unit test: populate AddressManager with varied-score peers, verify select_peer() bias |
| PRF-003 | gap    | Plumtree tree optimization for low latency    | Integration test: inject lower-latency peer, verify eager set replacement and PRUNE   |
| PRF-004 | gap    | Parallel bootstrap via FuturesUnordered       | Integration test: verify 8 connections initiated concurrently, not sequentially       |
| PRF-005 | gap    | Bandwidth benchmarks (Plumtree, compact, ERLAY) | Benchmark test: measure bytes across 50-node sim, assert thresholds                |
| PRF-006 | gap    | Latency benchmarks (NewPeak p99, bootstrap)   | Benchmark test: measure p99 during bulk sync and bootstrap wall-clock time            |
