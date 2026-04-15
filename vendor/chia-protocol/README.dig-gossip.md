# dig-gossip vendor fork: `chia-protocol`

Upstream: crates.io **0.26.0**.

## Patch

- **`ProtocolMessageTypes`:** `RegisterPeer = 218`, `RegisterAck = 219` — DIG introducer registration wire IDs (**DSC-005**). Required so `Message::from_bytes` / `Peer::request_infallible` accept replies on the introducer WebSocket; the stock enum stops at **107**, which would reject DIG extension opcodes during decode.

Do not drop this file when refreshing the vendor tree; bump the copy from the registry tarball and re-apply the enum hunk if upgrading `chia-protocol`.
