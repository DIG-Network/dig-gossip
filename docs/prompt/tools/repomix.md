# Repomix — Context Packing for LLMs

## What

Packs your codebase into a single AI-friendly file. Supports token counting, tree-sitter compression, and gitignore-aware file selection. Output formats: XML, Markdown, JSON.

## HARD RULE

**Always pack context before starting implementation.** Fresh context = better code. Pack the scope you are about to modify so the LLM has complete awareness.

## Setup

### Global Install

```bash
npm install -g repomix
```

### Or Use Directly via npx

```bash
npx repomix@latest
```

No additional configuration required. Repomix reads `.gitignore` automatically.

## Common Commands for dig-gossip

### Pack Implementation Scope

```bash
npx repomix@latest src -o .repomix/pack-src.xml
```

### Pack Tests

```bash
npx repomix@latest tests -o .repomix/pack-tests.xml
```

### Pack Requirements for a Domain

```bash
# compact_blocks domain
npx repomix@latest docs/requirements/domains/compact_blocks -o .repomix/pack-compact-blocks-reqs.xml

# concurrency domain
npx repomix@latest docs/requirements/domains/concurrency -o .repomix/pack-concurrency-reqs.xml

# connection domain
npx repomix@latest docs/requirements/domains/connection -o .repomix/pack-connection-reqs.xml

# crate_api domain
npx repomix@latest docs/requirements/domains/crate_api -o .repomix/pack-crate-api-reqs.xml

# crate_structure domain
npx repomix@latest docs/requirements/domains/crate_structure -o .repomix/pack-crate-structure-reqs.xml

# discovery domain
npx repomix@latest docs/requirements/domains/discovery -o .repomix/pack-discovery-reqs.xml

# erlay domain
npx repomix@latest docs/requirements/domains/erlay -o .repomix/pack-erlay-reqs.xml

# performance domain
npx repomix@latest docs/requirements/domains/performance -o .repomix/pack-performance-reqs.xml

# plumtree domain
npx repomix@latest docs/requirements/domains/plumtree -o .repomix/pack-plumtree-reqs.xml

# priority domain
npx repomix@latest docs/requirements/domains/priority -o .repomix/pack-priority-reqs.xml

# privacy domain
npx repomix@latest docs/requirements/domains/privacy -o .repomix/pack-privacy-reqs.xml

# relay domain
npx repomix@latest docs/requirements/domains/relay -o .repomix/pack-relay-reqs.xml

# All requirements
npx repomix@latest docs/requirements -o .repomix/pack-requirements.xml
```

### Pack the Full Spec

```bash
npx repomix@latest docs/resources -o .repomix/pack-spec.xml
```

### Pack with Compression

For larger scopes where token count matters:

```bash
npx repomix@latest src --compress -o .repomix/pack-src-compressed.xml
```

Compression uses tree-sitter to retain structure while reducing token count.

### Pack Multiple Scopes

```bash
# Implementation + tests together
npx repomix@latest src tests -o .repomix/pack-impl-and-tests.xml
```

## Output Directory

All pack files go to `.repomix/` which is gitignored. These are ephemeral working context files — they are regenerated as needed and never committed.

```
.repomix/
├── pack-src.xml
├── pack-tests.xml
├── pack-adm-reqs.xml
├── pack-cfr-reqs.xml
├── pack-spec.xml
└── pack-src-compressed.xml
```

## Workflow Integration

| Workflow Step | How to Use Repomix |
|--------------|-------------------|
| **Gather context** | Pack the scope you are about to work on (implementation + requirements) |
| **Before implementing** | Pack `src/` + `tests` for full implementation context |
| **Before testing** | Pack `tests/` to see existing test patterns and match style |
| **Cross-requirement work** | Pack multiple domains to see relationships between requirements |

## Example Session

When starting work on ADM-001:

```bash
# Pack the implementation scope
npx repomix@latest src -o .repomix/pack-src.xml

# Pack existing tests for pattern reference
npx repomix@latest tests -o .repomix/pack-tests.xml

# Pack the admission domain requirements
npx repomix@latest docs/requirements/domains/admission -o .repomix/pack-adm-reqs.xml
```

Now the LLM has full context of:
- Current implementation state
- Existing test patterns to match
- All admission requirements and their specs

## Tips

- Regenerate packs when switching between requirements — stale context leads to stale code.
- Use `--compress` for large scopes (full `src/`) to keep token count manageable.
- Pack requirements alongside code when you need to verify spec compliance.
- The XML format is default and works well with most LLM contexts. Use `--style markdown` if you prefer Markdown output.
- Check `.gitignore` includes `.repomix/` — these files should never be committed.
