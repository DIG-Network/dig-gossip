# Priority - Verification Matrix

> **Domain:** priority
> **Prefix:** PRI
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| PRI-001 | gap    | MessagePriority enum with three lanes        | Unit test that each ProtocolMessageType maps to the correct priority lane              |
| PRI-002 | gap    | PriorityOutbound with three VecDeque queues  | Unit test that enqueue routes messages to the correct internal queue by priority       |
| PRI-003 | gap    | Drain order: critical, normal, one bulk      | Unit test that drain yields critical first, then normal, then one bulk, then rechecks  |
| PRI-004 | gap    | Starvation prevention for bulk messages      | Unit test that after 10 critical/normal messages, 1 bulk is emitted even if non-empty  |
| PRI-005 | gap    | BackpressureConfig with three thresholds     | Unit test that defaults are 100, 50, 25 and custom values are respected               |
| PRI-006 | gap    | Tx dedup at queue depth >= 25               | Unit test that duplicate NewTransaction is suppressed above threshold                  |
| PRI-007 | gap    | Bulk drop at queue depth >= 50              | Unit test that Bulk messages are dropped and ERLAY paused above threshold              |
| PRI-008 | gap    | Normal delay at queue depth >= 100          | Unit test that Normal messages are batched at 500ms; Critical unaffected               |
