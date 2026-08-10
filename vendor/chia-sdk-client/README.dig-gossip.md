# `chia-sdk-client` — the dig-gossip fork delta

Vendored via `[patch.crates-io]` in the workspace `Cargo.toml`. The tree is an unpacked
**crates.io `chia-sdk-client` 0.28.0** tarball, so the pristine crate of the same version is the
exact baseline and everything the diff reports is DIG's.

## Regenerate this delta — do not hand-maintain it

```sh
vendor/fork-delta.sh chia-sdk-client --summary   # the file list
vendor/fork-delta.sh chia-sdk-client             # the full unified diff
```

A hand-written delta has been wrong twice (dig_ecosystem#2228): this README did not describe the
patch at all, and the rate-limit surface was attributed to the wrong crate. **The compiler and the
diff are the record; this file is a summary of them and must be regenerated when either changes.**

## What the fork changes — one file, three items

`--summary` reports exactly one differing file, `src/peer.rs`:

1. **`Peer::from_server_websocket`** (#1371) — construct a `Peer` from an already-established
   **server-side** WebSocket. `from_websocket` recovers the peer address by inspecting a client
   `MaybeTlsStream`, which a `tokio_rustls::server::TlsStream` cannot inhabit (the enum is
   `#[non_exhaustive]`). Supporting it required type-erasing the split halves behind `BoxedSink` /
   `BoxedStream` so `Peer` itself stays non-generic — which in turn forces a manual `Debug` for
   `PeerInner` and a shared `from_parts` constructor. Needed by dig-gossip's rustls inbound acceptor.
2. **`Peer::send_protocol_message`** — send a fully-formed wire `Message` preserving its `id`, so an
   inbound request can be answered on the same correlation id.
3. **Inbound `RequestPeers` is routed to the application channel** rather than matched against the
   outbound `RequestMap`. A remote's `RequestPeers` id comes from the *sender's* map and may collide
   with one of our in-flight request ids, which would deliver it to an unrelated waiter and surface
   as `ClientError::InvalidResponse`.

Items 2 and 3 are one change: 3 makes the inbound request reachable, 2 answers it.

## Upstream status

All three are additive, carry **no DIG semantics**, and are unimplementable outside the crate only
because `Peer`'s fields are private — so all three are genuine upstream candidates for
[xch-dev/chia-wallet-sdk](https://github.com/xch-dev/chia-wallet-sdk). If upstream takes them, this
fork retires. Note that item 3 is a behavioural fix rather than pure API addition, so it needs to be
argued as such in that PR (dig_ecosystem#2228 S3).

As of upstream **0.34.0** none of the three has landed: there is no `send_protocol_message`, no
`from_server_websocket`, the split halves are still the concrete `SplitSink` / `SplitStream`, and
inbound `RequestPeers` is still matched against the outbound `RequestMap`. So the fork cannot yet
retire on any of the three counts.

## Rebasing onto a newer upstream — read this first

The same cascade constraint as the sibling `chia-protocol` fork applies, for the same reason:
`dig-peer-protocol` pins `chia-sdk-client = "0.28"`, and a `[patch.crates-io]` entry whose version
does not satisfy that requirement is **silently dropped with a warning**, not an error. See
`vendor/chia-protocol/README.dig-gossip.md` for the measured evidence and the ordering.

## What used to be here and no longer is

`RateLimits::dig_wire` and `RateLimiter::check_dig_extension` were removed in dig_ecosystem#2228.
The DIG per-opcode bound is keyed by the raw wire byte, never by `ProtocolMessageTypes`, and its
accounting was already fully parallel to Chia's — so it never needed the fork. It now lives in
dig-gossip as `connection::dig_rate_limiter::DigRateLimiter`, composed with Chia's `RateLimiter` by
`connection::inbound_limits::InboundRateLimiter`. `src/rate_limits.rs` and `src/rate_limiter.rs` are
byte-identical to upstream again.
