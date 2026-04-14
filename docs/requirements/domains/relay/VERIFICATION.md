# Relay - Verification Matrix

> **Domain:** relay
> **Prefix:** RLY
> **Normative:** [NORMATIVE.md](./NORMATIVE.md)
> **Tracking:** [TRACKING.yaml](./TRACKING.yaml)

| ID      | Status | Summary                                      | Verification Approach                                                                 |
|---------|--------|----------------------------------------------|---------------------------------------------------------------------------------------|
| RLY-001 | gap    | Relay client connect and register            | Integration test: connect to mock relay server, verify Register/RegisterAck exchange  |
| RLY-002 | gap    | Relay message forwarding                     | Integration test: send RelayGossipMessage via relay, verify delivery to target peer   |
| RLY-003 | gap    | Relay broadcast                              | Integration test: broadcast via relay, verify all peers (minus exclude) receive it    |
| RLY-004 | gap    | Auto-reconnect on disconnect                 | Integration test: drop relay connection, verify reconnect with configurable delay     |
| RLY-005 | gap    | Relay peer list                              | Integration test: send GetPeers, verify Peers response contains expected RelayPeerInfo|
| RLY-006 | gap    | Relay keepalive                              | Integration test: verify Ping sent at interval, Pong received, timeout triggers reconnect |
| RLY-007 | gap    | NAT traversal hole punching                  | Integration test: simulate hole punch flow, verify migration to direct or retry       |
| RLY-008 | gap    | Transport selection                          | Integration test: verify direct-first fallback behavior and prefer_relay override     |
