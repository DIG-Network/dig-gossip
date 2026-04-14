# Start

## Immediate Actions

1. **Sync**
   ```bash
   git fetch origin && git pull origin main
   ```

2. **Check tools — ALL THREE MUST BE FRESH**
   ```bash
   npx gitnexus status          # GitNexus index fresh?
   npx gitnexus analyze         # Update if stale
   # SocratiCode: verify Docker running, index current
   codebase_status {}            # SocratiCode MCP status
   ```
   **Do not proceed until tools are confirmed operational.** Coding without tools leads to redundant work and missed dependencies.

3. **Pick work** — open `docs/requirements/IMPLEMENTATION_ORDER.md`
   - Choose the first `- [ ]` item
   - Every `- [x]` is done on main — skip it
   - Work phases in order: Phase 0 before Phase 1, etc.

4. **Pack context — BEFORE reading any code**
   ```bash
   npx repomix@latest src -o .repomix/pack-src.xml
   npx repomix@latest tests -o .repomix/pack-tests.xml
   ```

5. **Search with SocratiCode — BEFORE reading files**
   ```
   codebase_search { query: "gossip peer connection broadcast plumtree" }
   codebase_graph_query { filePath: "src/gossip/plumtree.rs" }
   ```

6. **Read spec** — follow the full trace:
   - `NORMATIVE.md#PREFIX-NNN` → authoritative requirement
   - `specs/PREFIX-NNN.md` → detailed specification + **test plan**
   - `VERIFICATION.md` → how to verify
   - `TRACKING.yaml` → current status

7. **Continue** → [dt-wf-select.md](tree/dt-wf-select.md)

---

## Hard Requirements

1. **Use chia crate ecosystem first** — never reimplement what `chia-protocol`, `chia-sdk-client`, `chia-ssl`, `chia-traits` provide. The SPEC Section 1.4 lists every type reused from Chia crates.
2. **No custom handshake** — use `chia-protocol::Handshake` with DIG values.
3. **No custom message framing** — use `chia-protocol::Message` and `chia-traits::Streamable`.
4. **No custom rate limiting** — use `chia-sdk-client::RateLimiter` with `V2_RATE_LIMITS`.
5. **No custom TLS** — use `chia-ssl::ChiaCertificate` and `chia-sdk-client` TLS utilities.
6. **No custom DNS resolution** — use `chia-sdk-client::Network::lookup_all()`.
7. **Re-export, don't redefine** — `Peer`, `Message`, `Handshake`, `NodeType`, `ProtocolMessageTypes` from upstream.
8. **No block validation** — this crate transports messages; it never validates block/transaction content.
9. **No CLVM execution** — this crate is payload-agnostic.
10. **TEST FIRST (TDD)** — write the failing test before writing implementation code. The test defines the contract. The spec's Test Plan section tells you exactly what tests to write.
11. **One requirement per commit** — don't batch unrelated work.
12. **Update tracking after each requirement** — VERIFICATION.md, TRACKING.yaml, IMPLEMENTATION_ORDER.md.
13. **Follow the decision tree to completion** — no shortcuts.
14. **AddressManager is the largest new component** — it's a Rust port of Chia's Python `address_manager.py` (itself a port of Bitcoin's CAddrMan). Get this right.

---

## Tech Stack

| Component | Crate | Version |
|-----------|-------|---------|
| Protocol types | `chia-protocol` | 0.26 |
| Peer connections | `chia-sdk-client` | 0.28 |
| TLS certificates | `chia-ssl` | 0.26 |
| Serialization traits | `chia-traits` | 0.26 |
| Async runtime | `tokio` | 1.x |
| WebSocket | `tokio-tungstenite` | 0.24 |
| Serialization | `serde`, `bincode`, `serde_json` | latest |
| Error handling | `thiserror` | 2 |
| Logging | `tracing` | 0.1 |
| Random | `rand` | 0.8 |
| LRU cache | `lru` | 0.12 |
| SipHash | `siphasher` | 1 |
| Minisketch | `minisketch-rs` | 0.2 |
| Testing | `tempfile` | 3 |
