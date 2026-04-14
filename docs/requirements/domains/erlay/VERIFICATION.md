# ERLAY Transaction Relay - Verification Matrix

> **Domain:** erlay
> **Prefix:** ERL
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                        | Verification Approach                                                                          |
|---------|--------|------------------------------------------------|------------------------------------------------------------------------------------------------|
| ERL-001 | gap    | Flood set = 8 random connected outbound peers  | Unit test: verify flood set size is ERLAY_FLOOD_PEER_COUNT and all members are outbound peers  |
| ERL-002 | gap    | NewTransaction sent only to flood set           | Unit test: verify NewTransaction reaches only flood-set peers; tx_id added to local sketch     |
| ERL-003 | gap    | Minisketch encode/decode for tx_id sets         | Unit test: encode known set, decode, verify round-trip; verify capacity is ERLAY_SKETCH_CAPACITY |
| ERL-004 | gap    | Set reconciliation every 2000ms per non-flood peer | Integration test: verify reconciliation triggers on interval; sketches exchanged correctly   |
| ERL-005 | gap    | Symmetric difference resolution and convergence | Integration test: two nodes with overlapping mempools converge after one reconciliation round  |
| ERL-006 | gap    | Flood set re-randomized every 60 seconds        | Unit test: verify flood set membership changes after ERLAY_FLOOD_SET_ROTATION_SECS elapses    |
| ERL-007 | gap    | Inbound peers excluded from flood set           | Unit test: verify inbound peers never appear in flood set regardless of peer count             |
| ERL-008 | gap    | ErlayConfig struct with defaults                | Unit test: verify struct fields exist with correct types and defaults (8, 2000, 20)            |
