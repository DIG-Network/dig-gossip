# Priority - Normative Requirements

> **Domain:** priority
> **Prefix:** PRI
> **Spec reference:** [SPEC.md - Sections 8.4, 8.5](../../resources/SPEC.md)

## Requirements

### PRI-001: MessagePriority Enum

MessagePriority enum MUST define three lanes: Critical(0) covering NewPeak, RespondBlock, RespondUnfinishedBlock, attestation, and checkpoint messages; Normal(1) covering NewTransaction, RespondTransaction, NewUnfinishedBlock, request messages, and DIG status messages; Bulk(2) covering RequestBlocks, RespondBlocks, RequestPeers, RespondPeers, RequestMempoolTransactions, introducer messages, and ValidatorAnnounce.

**Spec reference:** SPEC Section 8.4 (Message Priority Lanes - Priority assignment table)

### PRI-002: PriorityOutbound Queue Structure

PriorityOutbound MUST maintain three VecDeque<Message> queues (critical, normal, bulk) per connection. Each outbound message is routed to the queue matching its MessagePriority classification.

**Spec reference:** SPEC Section 8.4 (Outbound queue structure per connection)

### PRI-003: Drain Order

Drain order MUST exhaust all critical messages first, then all normal messages, then one bulk message, then check critical again. Critical messages always take precedence over normal and bulk.

**Spec reference:** SPEC Section 8.4 (Drain order comment)

### PRI-004: Starvation Prevention

Bulk messages MUST be guaranteed at least 1 message per PRIORITY_STARVATION_RATIO (10) critical/normal messages to prevent indefinite starvation during sustained high-priority load.

**Spec reference:** SPEC Section 8.4 (Starvation prevention)

### PRI-005: BackpressureConfig

BackpressureConfig MUST define three thresholds: normal_delay_threshold (default 100), bulk_drop_threshold (default 50), tx_dedup_threshold (default 25). These thresholds govern adaptive backpressure behavior based on outbound queue depth.

**Spec reference:** SPEC Section 8.5 (Adaptive Backpressure - BackpressureConfig)

### PRI-006: Transaction Deduplication Under Backpressure

At queue depth >= tx_dedup_threshold (25), duplicate NewTransaction announcements MUST be suppressed. Only the first announcement per tx_id passes; subsequent duplicates are dropped.

**Spec reference:** SPEC Section 8.5 (Behavior under backpressure - 25-50 range)

### PRI-007: Bulk Drop Under Backpressure

At queue depth >= bulk_drop_threshold (50), Bulk messages MUST be dropped silently. ERLAY reconciliation MUST be paused.

**Spec reference:** SPEC Section 8.5 (Behavior under backpressure - 50-100 range)

### PRI-008: Normal Delay Under Backpressure

At queue depth >= normal_delay_threshold (100), Normal messages MUST be delayed (batched, sent every 500ms). Critical messages MUST remain unaffected at all backpressure levels.

**Spec reference:** SPEC Section 8.5 (Behavior under backpressure - 100+ range)

---

## Property Tests

**Property test (ordering):** For any sequence of messages enqueued with mixed priorities (Critical, Normal, Bulk), the PriorityOutbound drain order MUST satisfy: every Critical message is dequeued before any Normal message, and every Normal message is dequeued before any Bulk message, subject only to the starvation prevention guarantee (1 Bulk per PRIORITY_STARVATION_RATIO Critical/Normal). No message MUST be lost or duplicated during drain.
