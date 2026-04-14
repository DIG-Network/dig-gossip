# Discovery - Normative Requirements

> **Domain:** discovery
> **Prefix:** DSC
> **Spec reference:** [SPEC.md - Section 6](../../resources/SPEC.md)

## Requirements

### DSC-001: AddressManager with Tried/New Tables

AddressManager MUST implement tried/new bucket tables ported from Chia's address_manager.py (Bitcoin CAddrMan). Constants: TRIED_BUCKET_COUNT=256, NEW_BUCKET_COUNT=1024, BUCKET_SIZE=64. Methods: create(), add_to_new_table(), mark_good(), attempt(), connect(), select_peer(), select_tried_collision(), resolve_tried_collisions(), size().

**Spec reference:** SPEC Section 6.3 (Address Manager)

### DSC-002: Address Manager Persistence

AddressManager MUST support save()/load() to a peers file path. Binary serialization MUST use bincode for compact, fast serialization of the tried/new tables and metadata.

**Spec reference:** SPEC Section 6.3 (Address Manager), Section 10.1 (address_manager_store.rs)

### DSC-003: DNS Seeding

DNS seeding MUST use chia-sdk-client::Network::lookup_all() with configurable timeout and batching. DNS introducers MUST be configurable via GossipConfig.

**Spec reference:** SPEC Section 6.2 (DNS Seeding)

### DSC-004: Introducer Query

Introducer query MUST connect via WebSocket, perform handshake, send get_peers (RequestPeersIntroducer), receive peers (RespondPeersIntroducer), and close. Uses chia-protocol types directly.

**Spec reference:** SPEC Section 6.5 (Introducer Client)

### DSC-005: Introducer Registration

Introducer registration MUST connect via WebSocket, perform handshake, send register_peer{ip, port, node_type}, receive register_ack, and close. This is a DIG extension not present in Chia.

**Spec reference:** SPEC Section 6.5 (Introducer Client)

### DSC-006: Discovery Loop

Discovery loop MUST attempt DNS first (round-robin), then introducer with exponential backoff (1s to 300s). When address manager is empty, retry DNS/introducer. After peers received, wait 5s before next cycle. Ported from node_discovery.py:256-293.

**Spec reference:** SPEC Section 6.4 (Discovery Loop)

### DSC-007: Peer Exchange

On outbound connect, MUST send RequestPeers. On receiving RespondPeers, MUST add peer_list to address manager via add_to_new_table(). Uses chia-protocol RequestPeers/RespondPeers directly. RespondPeers MUST cap accepted peers at MAX_PEERS_RECEIVED_PER_REQUEST (1000); peers beyond the cap MUST be silently discarded. Total peers received from all peers across all requests MUST be capped at MAX_TOTAL_PEERS_RECEIVED (3000).

**Spec reference:** SPEC Section 6.6 (Peer Exchange via Gossip)

### DSC-008: Feeler Connections

Feeler connections MUST follow a Poisson schedule with 240s average interval. A random "new" address is selected, connected, and promoted to "tried" on success. Ported from node_discovery.py:308-325.

**Spec reference:** SPEC Section 6.4 (Discovery Loop, item 4)

### DSC-009: Parallel Connection Establishment

Connection establishment MUST batch up to PARALLEL_CONNECT_BATCH_SIZE (8) concurrent connections via FuturesUnordered. This is an improvement over Chia's sequential one-at-a-time approach.

**Spec reference:** SPEC Section 6.4 (Discovery Loop, item 2)

### DSC-010: AS-Level Diversity

Outbound connections MUST enforce at most one connection per AS number. AS numbers MUST be resolved via a cached BGP prefix table lookup. This provides stronger eclipse attack resistance than Chia's /16 grouping alone.

**Spec reference:** SPEC Section 6.4 (Discovery Loop, item 3)

### DSC-011: /16 Group Filter

Outbound connections MUST enforce at most one connection per IPv4 /16 subnet. This serves as a fast first-pass filter before the more expensive AS number check. Ported from node_discovery.py:296-306.

**Spec reference:** SPEC Section 6.4 (Discovery Loop, item 3)

### DSC-012: IntroducerPeers/VettedPeer Tracking

IntroducerPeers MUST track vetting state per peer: 0=unvetted, negative=failed, positive=success count. Ported from introducer_peers.py:12-28.

**Spec reference:** SPEC Section 10.1 (introducer_peers.rs)

---

## Property Tests

**Property test (address manager):** For any sequence of `add_to_new_table`, `mark_good`, `attempt`, and `select_peer` operations, the AddressManager MUST maintain the invariants: (1) no address appears in both the tried and new tables simultaneously, (2) the total number of addresses in each bucket never exceeds BUCKET_SIZE (64), (3) `select_peer` never returns a banned address, and (4) tried bucket count never exceeds TRIED_BUCKET_COUNT (256) and new bucket count never exceeds NEW_BUCKET_COUNT (1024).
