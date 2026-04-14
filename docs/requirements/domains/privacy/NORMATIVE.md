# Privacy — Normative Requirements

> **Domain:** privacy
> **Prefix:** PRV
> **Spec reference:** [SPEC.md - Section 1.9](../../../resources/SPEC.md)

---

## &sect;1 Dandelion++ Transaction Origin Privacy

<a id="PRV-001"></a>**PRV-001** DandelionConfig MUST define `enabled: bool` (default true), `fluff_probability: f64` (default 0.10), `stem_timeout_secs: u64` (default 30), `epoch_secs: u64` (default 600). The `dandelion` feature flag MUST gate all Dandelion++ functionality.
> **Spec:** [`PRV-001.md`](specs/PRV-001.md)

<a id="PRV-002"></a>**PRV-002** When a node originates or receives a `StemTransaction`, it MUST forward to exactly one randomly selected stem relay peer. The transaction MUST NOT be added to the local mempool during stem phase. The node MUST NOT respond to `RequestTransaction` for stem-only transactions. The stem relay MUST be a single consistent peer per epoch. `StemTransaction` MUST have a corresponding `DigMessageType` ID (`StemTransaction = 213`) for wire transmission (see API-009).
> **Spec:** [`PRV-002.md`](specs/PRV-002.md)

<a id="PRV-003"></a>**PRV-003** At each stem hop, the node MUST flip a weighted coin with probability `DANDELION_FLUFF_PROBABILITY` (default 10%). On fluff: the transaction MUST be added to the local mempool and broadcast via normal Plumtree/ERLAY gossip. On stem: the transaction MUST be forwarded to the node's own stem relay.
> **Spec:** [`PRV-003.md`](specs/PRV-003.md)

<a id="PRV-004"></a>**PRV-004** If a stemmed transaction is not seen via fluff within `DANDELION_STEM_TIMEOUT_SECS` (default 30 seconds), the holding node MUST force-fluff it (add to mempool and broadcast normally). This ensures liveness even if the stem path is broken.
> **Spec:** [`PRV-004.md`](specs/PRV-004.md)

<a id="PRV-005"></a>**PRV-005** The stem relay peer MUST be re-randomized every `DANDELION_EPOCH_SECS` (default 600 seconds / 10 minutes). Using a consistent relay per epoch prevents per-transaction fingerprinting. The epoch timer MUST be independent per node (not synchronized across the network).
> **Spec:** [`PRV-005.md`](specs/PRV-005.md)

---

## &sect;2 Ephemeral PeerId Rotation

<a id="PRV-006"></a>**PRV-006** PeerIdRotationConfig MUST define `enabled: bool` (default true), `rotation_interval_secs: u64` (default 86400 / 24 hours), `reconnect_on_rotation: bool` (default true).
> **Spec:** [`PRV-006.md`](specs/PRV-006.md)

<a id="PRV-007"></a>**PRV-007** Every `rotation_interval_secs`, the node MUST generate a fresh `ChiaCertificate` via `chia-ssl`, giving it a new `PeerId`. If `reconnect_on_rotation` is true, all peers MUST be disconnected and reconnected with the new identity. Network identity (PeerId from TLS cert) MUST be independent of consensus identity (validator BLS keys). The address manager MUST track peers by IP:port, not by PeerId, so rotation does not break discovery.
> **Spec:** [`PRV-007.md`](specs/PRV-007.md)

<a id="PRV-008"></a>**PRV-008** Nodes MUST be able to disable rotation by setting `rotation_interval_secs = 0` (e.g., bootstrap nodes wanting stable identity). When disabled, the existing `chia-ssl` certificate is kept permanently.
> **Spec:** [`PRV-008.md`](specs/PRV-008.md)

---

## &sect;3 Tor/SOCKS5 Proxy Transport

<a id="PRV-009"></a>**PRV-009** TorConfig MUST define `enabled: bool` (default false), `socks5_proxy: String` (default "127.0.0.1:9050"), `onion_address: Option<String>`, `prefer_tor: bool` (default false). The `tor` feature flag MUST gate all Tor functionality.
> **Spec:** [`PRV-009.md`](specs/PRV-009.md)

<a id="PRV-010"></a>**PRV-010** Outbound connections MUST be routable through a SOCKS5 proxy (Tor daemon). Inbound connections MUST be receivable via a `.onion` hidden service address published to the introducer. Hybrid mode MUST allow both direct and Tor connections simultaneously. Transport selection: if `prefer_tor = true`, all outbound via Tor; if `prefer_tor = false`, direct first → relay second → Tor third; `.onion` addresses always via Tor.
> **Spec:** [`PRV-010.md`](specs/PRV-010.md)
