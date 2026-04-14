# dig-gossip — Operator Prompt

```mermaid
flowchart TD
    START[start.md] --> SELECT[dt-wf-select.md]
    SELECT --> GATHER[dt-wf-gather-context.md]
    GATHER --> TEST[dt-wf-test.md]
    TEST --> IMPL[dt-wf-implement.md]
    IMPL --> VALIDATE[dt-wf-validate.md]
    VALIDATE --> TRACK[dt-wf-update-tracking.md]
    TRACK --> COMMIT[dt-wf-commit.md]
    COMMIT --> SELECT
```

## CRITICAL: Follow the full cycle for every requirement. No shortcuts.

Every requirement MUST pass through all 7 workflow steps. Skipping any step is a blocking defect. The test step (Step 3) comes BEFORE implementation (Step 4) — this is test-driven development. Tools (Step 2) come BEFORE tests — you cannot write correct tests without understanding context.

## Workflow Cycle

| Step | File | Action | Gate |
|------|------|--------|------|
| 0 | [start.md](start.md) | Sync, check tools, pick work | Tools must be fresh |
| 1 | [dt-wf-select.md](tree/dt-wf-select.md) | Choose requirement from IMPLEMENTATION_ORDER | Must read full spec |
| 2 | [dt-wf-gather-context.md](tree/dt-wf-gather-context.md) | Pack context (Repomix), search (SocratiCode), check impact (GitNexus) | All 3 tools used |
| 3 | [dt-wf-test.md](tree/dt-wf-test.md) | **Write failing test FIRST (TDD)** | Test must fail before impl |
| 4 | [dt-wf-implement.md](tree/dt-wf-implement.md) | Implement — chia crates first, minimal own code | Tests must now pass |
| 5 | [dt-wf-validate.md](tree/dt-wf-validate.md) | Run tests, clippy, fmt, circular dep check | All checks green |
| 6 | [dt-wf-update-tracking.md](tree/dt-wf-update-tracking.md) | Update TRACKING.yaml, VERIFICATION.md, IMPLEMENTATION_ORDER.md | All 3 files updated |
| 7 | [dt-wf-commit.md](tree/dt-wf-commit.md) | Commit, push, update GitNexus index, loop | One requirement per commit |

## Requirement Traceability

```
IMPLEMENTATION_ORDER.md  →  pick [ ] item
        ↓
NORMATIVE.md#PREFIX-NNN  →  read authoritative statement
        ↓
specs/PREFIX-NNN.md      →  read detailed specification + test plan
        ↓
TOOLS: SocratiCode + Repomix + GitNexus  →  gather full context
        ↓
WRITE FAILING TEST FIRST →  test defines the contract
        ↓
implement against spec   →  make test pass (chia crates first)
        ↓
VERIFICATION.md          →  update status
TRACKING.yaml            →  update status, tests, notes
IMPLEMENTATION_ORDER.md  →  check off [x]
```
