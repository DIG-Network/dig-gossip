# Integration — Normative Requirements

> **Domain:** integration
> **Prefix:** INT
> **Spec reference:** [SPEC.md](../../../resources/SPEC.md) — cross-cutting integration

These requirements cover the **wiring** of individually-implemented components
into the running GossipService/GossipHandle. Each addresses a gap where types
and algorithms exist but are not connected to the live message flow.

---

## §1 Broadcast Pipeline Integration

<a id="INT-001"></a>**INT-001** `GossipHandle::broadcast()` MUST route messages through the Plumtree state machine: eager push full messages to `eager_peers`, lazy push hash-only to `lazy_peers`. MUST NOT do flat fan-out to all peers. SPEC §8.1.
> **Spec:** [`INT-001.md`](specs/INT-001.md)

<a id="INT-002"></a>**INT-002** `GossipHandle::broadcast()` MUST enqueue outbound messages into `PriorityOutbound` per connection, drained in Critical→Normal→Bulk order with starvation prevention. SPEC §8.4.
> **Spec:** [`INT-002.md`](specs/INT-002.md)

<a id="INT-003"></a>**INT-003** `GossipHandle::broadcast()` MUST apply adaptive backpressure: tx dedup at depth≥25, bulk drop at depth≥50, normal delay at depth≥100. Critical always unaffected. SPEC §8.5.
> **Spec:** [`INT-003.md`](specs/INT-003.md)

<a id="INT-004"></a>**INT-004** When `erlay` feature is enabled, `NewTransaction` messages MUST be routed via ERLAY: flood to flood_set only, reconciliation with remaining peers. Other message types use Plumtree. SPEC §8.3.
> **Spec:** [`INT-004.md`](specs/INT-004.md)

<a id="INT-005"></a>**INT-005** When relay is connected, Plumtree broadcast step 7 MUST also send via `RelayClient::build_broadcast()` to reach relay-only peers. SPEC §8.1 step 7, §7.
> **Spec:** [`INT-005.md`](specs/INT-005.md)

---

## §2 Connection Filtering Integration

<a id="INT-006"></a>**INT-006** `GossipHandle::connect_to()` MUST check `/16 SubnetGroupFilter` before establishing outbound connection. Reject if group already has outbound. SPEC §6.4 item 3, DSC-011.
> **Spec:** [`INT-006.md`](specs/INT-006.md)

<a id="INT-007"></a>**INT-007** `GossipHandle::connect_to()` MUST check `AsDiversityFilter` after /16 filter. Reject if AS already has outbound. SPEC §6.4 item 3, DSC-010.
> **Spec:** [`INT-007.md`](specs/INT-007.md)

---

## §3 Task Spawning Integration

<a id="INT-008"></a>**INT-008** `GossipService::start()` MUST spawn `run_discovery_loop()` as a background task with the shared AddressManager and a CancellationToken tied to stop(). SPEC §6.4, CNC-002.
> **Spec:** [`INT-008.md`](specs/INT-008.md)

<a id="INT-009"></a>**INT-009** `GossipService::start()` MUST spawn `run_feeler_loop()` as a background task with FEELER_INTERVAL_SECS. SPEC §6.4, CNC-002, DSC-008.
> **Spec:** [`INT-009.md`](specs/INT-009.md)

<a id="INT-010"></a>**INT-010** `GossipService::start()` MUST spawn a periodic cleanup task that removes stale connections (last_pong > PEER_TIMEOUT_SECS) and clears expired bans. SPEC §9.1, CNC-006.
> **Spec:** [`INT-010.md`](specs/INT-010.md)

---

## §4 Privacy Integration

<a id="INT-011"></a>**INT-011** When `dandelion` feature is enabled, locally-originated transactions MUST enter stem phase via `StemRelayManager` before normal broadcast. Stem transactions MUST NOT be in mempool or served via RequestTransaction. SPEC §1.9.1, PRV-002/003.
> **Spec:** [`INT-011.md`](specs/INT-011.md)

<a id="INT-012"></a>**INT-012** `GossipService::start()` MUST spawn relay auto-reconnect task when relay is configured. MUST use `ReconnectState` for backoff. SPEC §7, RLY-004, CNC-002.
> **Spec:** [`INT-012.md`](specs/INT-012.md)
