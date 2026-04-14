# Compact Blocks - Verification Matrix

> **Domain:** compact_blocks
> **Prefix:** CBK
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| CBK-001 | gap    | CompactBlock struct with required fields     | Unit test constructing CompactBlock with all fields; verify prefilled includes coinbase and recent txs |
| CBK-002 | gap    | ShortTxId = SipHash truncated to 6 bytes     | Unit test computing ShortTxId from known inputs; verify 6-byte output matches expected value |
| CBK-003 | gap    | Block reconstruction from mempool matches    | Integration test with mock mempool; verify full block reconstructed from CompactBlock  |
| CBK-004 | gap    | Missing tx request/response protocol         | Integration test with partial mempool; verify RequestBlockTransactions sent for missing indices |
| CBK-005 | gap    | Fallback to full block when >5 missing       | Integration test with >5 missing txs; verify RequestBlock sent instead of RequestBlockTransactions |
| CBK-006 | gap    | Deterministic SipHash key from header hash   | Unit test deriving key from same header twice; verify identical CompactBlock output     |
