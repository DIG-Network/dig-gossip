# dig-gossip vendor fork: `chia-protocol`

Vendored via `[patch.crates-io]` in the workspace `Cargo.toml`. The tree is an unpacked
**crates.io `chia-protocol` 0.26.0** tarball, so the pristine crate of the same version is the
exact baseline and everything the diff reports is DIG's.

## Regenerate this delta — do not hand-maintain it

```sh
vendor/fork-delta.sh chia-protocol --summary   # the file list
vendor/fork-delta.sh chia-protocol             # the full unified diff
```

A hand-written delta has been wrong twice before (dig_ecosystem#2228): claiming `RegisterPeer` and
`RegisterAck` only (opcodes 218–219), when the fork actually adds 23 opcodes (200–222). **The compiler
and the diff are the record; this file is a summary of them and must be regenerated when either
changes.**

## What the fork changes — one file, 23 opcodes

`--summary` reports exactly one differing file, `src/chia_protocol.rs`:

**`ProtocolMessageTypes` enum adds 23 opcodes** (200–222), in three groups:

1. **DIG L2 consensus band (200–217, 18 opcodes):** `NewAttestation`, `NewCheckpointProposal`,
   `NewCheckpointSignature`, `RequestCheckpointSignatures`, `RespondCheckpointSignatures`,
   `RequestStatus`, `RespondStatus`, `NewCheckpointSubmission`, `ValidatorAnnounce`,
   `RequestBlockTransactions`, `RespondBlockTransactions`, `ReconciliationSketch`,
   `ReconciliationResponse`, `StemTransaction`, `PlumtreeLazyAnnounce`, `PlumtreePrune`,
   `PlumtreeGraft`, `PlumtreeRequestByHash` (#1404). These extend Chia's namespace so a stock
   `Message` can carry a DIG consensus opcode on the wire. Each MUST equal the matching
   `dig_peer_protocol::DigMessageType` discriminant; `frame_dig_message` in dig-gossip converts
   one to the other losslessly. **Additive** (§5.1): no existing opcode moves.

2. **DIG introducer registration (218–219, 2 opcodes):** `RegisterPeer`, `RegisterAck` (DSC-005).
   Required so `Message::from_bytes` accepts replies on the introducer WebSocket; the stock enum
   stops at 107. Additive only.

3. **DIG directed-envelope and broadcast (220–222, 3 opcodes):** `DigMessage` (WU6 / epic #796),
   `StoreMelted` (epic #1316), `HoldingsAnnounce` (#1428). Carry opaque DIG payloads or announce
   store/holdings state to all peers. Additive only.

## Upstream status

All 23 are purely additive — no renumbering or semantic changes to existing opcodes. The fork
exists only because `ProtocolMessageTypes` is upstream-owned; if upstream accepts the opcodes,
this fork retires.

Upstream has **not** claimed any of 200–222: `ProtocolMessageTypes` stops at `RespondCostInfo = 107`
at 0.26.0, 0.36.1 and 0.47.0 alike. There is no collision and no renumber pressure, so the vendored
version can stay where it is indefinitely without risking the wire.

## Rebasing onto a newer upstream — read this first

**The chia version is not choosable in this repo alone.** dig-gossip reaches `chia-protocol` through
`dig-peer-protocol`, which pins `chia-protocol = "0.26"` (and `chia-sdk-client = "0.28"`). A
`[patch.crates-io]` entry substitutes a package only where the patched version SATISFIES the existing
requirement, so bumping this tree to 0.36.1 makes Cargo **drop the patch and resolve pristine upstream
instead** — reported as a *warning*, with `cargo metadata` still exiting 0:

```
warning: patch `chia-protocol v0.36.1 (vendor/chia-protocol)` was not used in the crate graph
```

A rebase is therefore a release-first cascade: `dig-peer-protocol` moves and republishes, then
dig-gossip's own direct `chia-protocol` / `chia_streamable_macro` pins, then this tree. The only
reason the dropped patch is not silent is that `ProtocolMessageTypes::RegisterPeer` stops existing and
the tree stops compiling — including `tests/wire_golden_vectors.rs`. That compile break is a guard.
Never resolve a patch-not-used warning by removing what surfaces it.
