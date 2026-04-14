# GitNexus — Knowledge Graph Dependency Analyzer

## What

Knowledge graph dependency analyzer. Precomputes every dependency, call chain, and relationship in the codebase into a queryable graph. Indexes symbols, provides impact analysis, and enables safe refactoring with full dependency awareness.

## HARD RULE

**Always run `npx gitnexus analyze` after commits** to keep the index current. **Always check impact before renaming public symbols.**

## Setup

### First-Time Setup

```bash
npx gitnexus analyze
```

This performs a full index of the codebase. It creates context files (AGENTS.md / CLAUDE.md) and registers Git hooks for automatic updates.

### Prerequisites

- **Node.js 18+** — for npx execution
- **Git repository** — GitNexus reads the Git history

## CLI Commands

| Command | Purpose |
|---------|---------|
| `npx gitnexus status` | Check if the index is fresh or stale |
| `npx gitnexus analyze` | Incremental index update (fast, only processes changes) |
| `npx gitnexus analyze --force` | Full re-index from scratch |
| `npx gitnexus list` | List all indexed repositories |
| `npx gitnexus clean` | Delete the index entirely |

## MCP Commands

When GitNexus is available as an MCP server, these commands are also available:

| Command | Purpose |
|---------|---------|
| `gitnexus_impact { symbol: "..." }` | What depends on this symbol? Shows all downstream dependents. |
| `gitnexus_rename { old: "...", new: "..." }` | Safe rename across the entire codebase. Shows all files that need updating. |
| `gitnexus_detect_changes` | What changed since the last `analyze`? Shows modified symbols and affected dependents. |

## Workflow Integration

| Workflow Step | How to Use GitNexus |
|--------------|---------------------|
| **Start of session** | `npx gitnexus status` — if stale, run `npx gitnexus analyze` |
| **Before refactoring** | `gitnexus_impact` to check downstream dependencies of symbols you plan to change |
| **Before renaming** | `gitnexus_rename` for safe cross-codebase rename with full impact report |
| **Before commit** | `gitnexus_detect_changes` to verify the scope of your changes matches expectations |
| **After commit** | `npx gitnexus analyze` to update the index with the new commit |

## Example Usage for dig-gossip

### Check index status at session start

```bash
npx gitnexus status
```

### Update index after making changes

```bash
npx gitnexus analyze
```

### Check impact before renaming a public function

```
gitnexus_impact { symbol: "GossipService" }
```

This shows every file and function that calls `submit`, so you know exactly what will break if you change its signature.

### Safe rename of a type

```
gitnexus_rename { old: "CoreType", new: "NewName" }
```

Returns a list of every file and line that references `CoreType`, so you can update them all.

### Force re-index after large changes

```bash
npx gitnexus analyze --force
```

Use `--force` after large refactors, dependency updates, or when the incremental index seems stale.

## Tips

- Run `status` before `analyze` — if the index is fresh, you can skip the update.
- The incremental `analyze` (without `--force`) is fast. Use it freely after every commit.
- Impact analysis is most valuable for public API symbols in `src/lib.rs` and core structs like `Mempool`, `CoreType`, `MempoolConfig`.
- If you are only adding new files (not modifying existing ones), impact analysis is less critical.
