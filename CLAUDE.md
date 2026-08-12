# dig-gossip — Project Context

## What This Is

dig-gossip — P2P gossip, relay, and related protocol work for the DIG network (requirements-first; Rust sources to be added).

## Key Documents

| Document | Path | Purpose |
|----------|------|---------|
| Master Spec | `docs/resources/SPEC.md` | Authoritative crate specification |
| Requirements | `docs/requirements/README.md` | Traceable requirements by domain |
| Implementation Order | `docs/requirements/IMPLEMENTATION_ORDER.md` | Phased checklist |

---

## Tests layout (permanent)

- **`tests/` is flat:** one file per requirement ID: `tests/{DOMAIN}_{NNN}_tests.rs` (e.g. `api_009_tests.rs`). No requirement subfolders under `tests/`.
- **Exception:** `tests/common/` only for STR-005 shared harness; requirement suites stay as sibling `*_tests.rs` files.

See `.cursor/rules/dig-gossip-tests-flat.mdc`.

---

## Tool Usage — MANDATORY ON EVERY PROMPT

### GitNexus — Before **any** code change

**Run the GitNexus loop before modifying `src/` or `tests/`** (not only for “public” symbols): `status` → `analyze` if stale → **`gitnexus_impact`** on targets you will edit when MCP/CLI is available. If `npx gitnexus` fails locally, use GitNexus MCP or note the failure for the user.

**ALWAYS run impact analysis before modifying any public symbol** (minimum bar when graph tools work).

```bash
npx gitnexus status          # Check index freshness
npx gitnexus analyze         # Update if stale
```

```
gitnexus_impact({target: "GossipService", direction: "upstream"})
gitnexus_detect_changes({scope: "staged"})
```

**After every commit:** `npx gitnexus analyze` to keep the index current.

### Repomix — Pack context before implementing

**ALWAYS pack relevant scope before starting implementation work.**

```bash
npx repomix@latest src -o .repomix/pack-src.xml
npx repomix@latest tests -o .repomix/pack-tests.xml
npx repomix@latest docs/requirements -o .repomix/pack-requirements.xml
```

---

## Workflow Cycle

| Step | Action | Tool |
|------|--------|------|
| 0 | Sync repo, check tool freshness | `git pull`, `npx gitnexus status` |
| 1 | Pick next `- [ ]` from `IMPLEMENTATION_ORDER.md` | — |
| 2 | Pack context | Repomix |
| 3 | Read requirement spec | `docs/requirements/domains/{domain}/specs/{ID}.md` |
| 4 | Implement / test | TDD where applicable |
| 5 | Run tests, clippy, fmt | `cargo test`, `cargo clippy`, `cargo fmt` |
| 6 | Check impact | `gitnexus_detect_changes` |
| 7 | Update tracking | TRACKING.yaml, VERIFICATION.md, IMPLEMENTATION_ORDER.md |
| 8 | Commit + update index | `git commit`, `npx gitnexus analyze` |

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **dig-gossip** (4463 symbols, 9543 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/dig-gossip/context` | Codebase overview, check index freshness |
| `gitnexus://repo/dig-gossip/clusters` | All functional areas |
| `gitnexus://repo/dig-gossip/processes` | All execution flows |
| `gitnexus://repo/dig-gossip/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
