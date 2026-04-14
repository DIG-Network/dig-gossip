# Repomix — Context Packing Skill

## When to Use

Use Repomix **before implementing any requirement**. Pack the relevant scope so the LLM has full awareness of the code being modified.

## HARD RULE

**MUST pack context before writing implementation code.** Fresh context prevents redundant work and missed patterns.

## Commands

### Pack Implementation

```bash
npx repomix@latest src -o .repomix/pack-src.xml
```

### Pack Tests (CRITICAL for TDD)

```bash
npx repomix@latest tests -o .repomix/pack-tests.xml
```

### Pack Requirements by Domain

```bash
# compact_blocks
npx repomix@latest docs/requirements/domains/compact_blocks -o .repomix/pack-compact-blocks-reqs.xml

# concurrency
npx repomix@latest docs/requirements/domains/concurrency -o .repomix/pack-concurrency-reqs.xml

# connection
npx repomix@latest docs/requirements/domains/connection -o .repomix/pack-connection-reqs.xml

# crate_api
npx repomix@latest docs/requirements/domains/crate_api -o .repomix/pack-crate-api-reqs.xml

# crate_structure
npx repomix@latest docs/requirements/domains/crate_structure -o .repomix/pack-crate-structure-reqs.xml

# discovery
npx repomix@latest docs/requirements/domains/discovery -o .repomix/pack-discovery-reqs.xml

# erlay
npx repomix@latest docs/requirements/domains/erlay -o .repomix/pack-erlay-reqs.xml

# performance
npx repomix@latest docs/requirements/domains/performance -o .repomix/pack-performance-reqs.xml

# plumtree
npx repomix@latest docs/requirements/domains/plumtree -o .repomix/pack-plumtree-reqs.xml

# priority
npx repomix@latest docs/requirements/domains/priority -o .repomix/pack-priority-reqs.xml

# privacy
npx repomix@latest docs/requirements/domains/privacy -o .repomix/pack-privacy-reqs.xml

# relay
npx repomix@latest docs/requirements/domains/relay -o .repomix/pack-relay-reqs.xml

# All requirements at once
npx repomix@latest docs/requirements -o .repomix/pack-requirements.xml
```

### Pack the Full Spec

```bash
npx repomix@latest docs/resources -o .repomix/pack-spec.xml
```

### Pack with Compression

```bash
npx repomix@latest src --compress -o .repomix/pack-src-compressed.xml
```

### Pack Multiple Scopes

```bash
npx repomix@latest src tests -o .repomix/pack-impl-and-tests.xml
```

## Workflow Integration

| Step | Pack Command |
|------|-------------|
| Before writing tests | `npx repomix@latest tests -o .repomix/pack-tests.xml` |
| Before implementing | `npx repomix@latest src -o .repomix/pack-src.xml` |
| Cross-domain work | Pack both domains' requirements |

## Notes

- `.repomix/` is gitignored — pack files are never committed
- Regenerate packs when switching requirements
- Use `--compress` for large scopes to manage token count
- Pack requirements alongside code for spec compliance checks

## Full Documentation

See `docs/prompt/tools/repomix.md` for complete reference.
