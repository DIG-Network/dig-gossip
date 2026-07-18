# dig-gossip — Development Log

Durable, high-signal realizations (not a change diary).

## Relay peer discovery + connect-leg (#870 / #924)

- **`connected_peers` root cause (#870).** dig-gossip's old ephemeral open→register→get_peers→close
  relay discovery reconnected every maintenance pass, so two nodes' sub-second registration windows
  never overlapped and neither appeared in the other's `get_peers` — `connected_peers` stuck at 0.
  Fix: read `dig-nat`'s ONE persistent-reservation `RelayStatus::known_peers()` instead.
- **B1 dialable fold (#924).** The relay OBSERVES each peer's reflexive address on registration but
  the reflexive source port is the outbound WebSocket's ephemeral port, NOT the gossip listener. So
  the node advertises its gossip `listen_addrs` in RLY-001 `Register`; the relay substitutes the
  observed reflexive IP for any unspecified/loopback/private advertised host (keeping the port) and
  returns it as `RelayPeerInfo.addresses`. dig-gossip folds a non-empty `addresses` into a
  `Via::Direct` dialable `PeerRecord` (IPv6-first) so it survives the dialable-only merge and the pool
  direct-dials it. Empty `addresses` = legacy identity-only `Via::Relay`.
- **Self-filter id-form trap (#924 round-3 finding 4).** A relay can echo this node's own `peer_id`
  in a different spelling than `Bytes32::Display` renders it (`hex::encode` = lowercase, no `0x`). A
  byte-exact self-compare then missed the match and counted self, inflating `relay_peer_count` by 1.
  Fix: normalize both sides (strip optional `0x`, lowercase) before comparing.
- **B2 relay-transport = a NatSlot (#924).** `dig-nat`'s `connect()` runs the whole traversal ladder;
  its last tier is the relayed transport (`TraversalKind::Relayed`, tunnelled through the relay's
  RLY-002 forwarder). A peer connected that way arrives as a `NatPeerConnection` and is adopted as a
  `NatSlot` — already counted in `connected_peers`. WU4 records the tier on the slot so it is tallied
  distinctly (`relay_transport_peer_count`) and reported `Via::Relay`.
- **NC-1 at the relay boundary.** The RLY-002 `payload` is an opaque `Vec<u8>` — dig-gossip never
  hands the relay structured plaintext. Directed-gossip payload sealing to the recipient key is NOT
  yet implemented in dig-gossip (the gossip-over-nat message loop lands with dig-node integration);
  the relayed route carries the SAME frame the direct nat path carries, so no plaintext-to-relay path
  exists to leak.
