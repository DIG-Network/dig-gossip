# Privacy — Verification Matrix

> **Domain:** privacy
> **Prefix:** PRV
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                          | Verification Approach                                                                      |
|---------|--------|--------------------------------------------------|--------------------------------------------------------------------------------------------|
| PRV-001 | --     | DandelionConfig struct and feature gate           | Unit test: struct fields, defaults, feature-gate compilation                                |
| PRV-002 | --     | Stem phase forwarding to single relay             | Unit test: stem tx forwarded to exactly one peer, not in mempool, not served on request     |
| PRV-003 | --     | Fluff transition probability                      | Unit test: coin flip at 10%, fluff adds to mempool + broadcasts, stem continues to relay    |
| PRV-004 | --     | Stem timeout force-fluff                          | Integration test: stem tx not fluffed within 30s → force fluff, tx enters mempool           |
| PRV-005 | --     | Stem relay epoch rotation                         | Unit test: relay changes every 600s, consistent within epoch, independent per node          |
| PRV-006 | --     | PeerIdRotationConfig struct                       | Unit test: struct fields, defaults, disabled when interval=0                                |
| PRV-007 | --     | Certificate rotation and reconnection             | Integration test: after interval, new ChiaCertificate generated, peers reconnected, new PeerId |
| PRV-008 | --     | Rotation opt-out                                  | Unit test: rotation_interval_secs=0 disables rotation, cert unchanged                      |
| PRV-009 | --     | TorConfig struct and feature gate                 | Unit test: struct fields, defaults, feature-gate compilation                                |
| PRV-010 | --     | Tor outbound/inbound/hybrid transport             | Integration test: outbound via SOCKS5, inbound via .onion, prefer_tor override, transport selection |

**Status legend:** ✅ verified · ⚠️ partial · -- gap
