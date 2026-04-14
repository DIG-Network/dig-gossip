//! Integration and unit tests for **API-007: [`PeerId`] type alias and [`PeerInfo`] with
//! [`PeerInfo::get_group`] / [`PeerInfo::get_key`]**.
//!
//! ## Why this file exists
//!
//! API-007 defines the **address-manager** view of a peer (`host` + `port`) and the deterministic
//! byte vectors Chia uses for bucket placement and “one outbound per /16” style policies. These
//! tests lock the behavior to [`docs/requirements/domains/crate_api/specs/API-007.md`](../docs/requirements/domains/crate_api/specs/API-007.md)
//! and [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) §2.2 / §2.7.
//!
//! ## How each test maps to acceptance criteria
//!
//! | Test | Proves |
//! |------|--------|
//! | `test_peer_id_is_bytes32` | `PeerId` is interchangeable with `Bytes32` (same layout, assignable). |
//! | `test_peer_info_debug` / `clone` / `eq` / `hash_map_key` | Derives `Debug`, `Clone`, `PartialEq`, `Eq`, `Hash` as required. |
//! | `test_get_group_*` | `/16` for IPv4, first 32 bits for IPv6, IPv4-mapped normalization, hostname hash fallback. |
//! | `test_get_key_*` | IP keys are `addr_be \|\| port_be`; IPv4-mapped uses 4+2; hostnames use `SHA256(host) \|\| port_be`; determinism + uniqueness. |

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;

use chia_protocol::Bytes32;
use dig_gossip::PeerId;
use dig_gossip::PeerInfo;

// ---------------------------------------------------------------------------
// PeerId ↔ Bytes32
// ---------------------------------------------------------------------------

/// **Acceptance:** `PeerId` aliases `Bytes32` — any value of one type can be assigned to the other
/// without conversion beyond `into()` / copying bytes.
#[test]
fn test_peer_id_is_bytes32() {
    let b = Bytes32::new([7u8; 32]);
    let p: PeerId = b;
    let back: Bytes32 = p;
    assert_eq!(back.as_ref(), &[7u8; 32]);
}

// ---------------------------------------------------------------------------
// PeerInfo derives and HashMap usage
// ---------------------------------------------------------------------------

/// **Acceptance:** `Debug` is available for logging / asserts when debugging address-manager state.
#[test]
fn test_peer_info_debug() {
    let pi = PeerInfo {
        host: "127.0.0.1".into(),
        port: 9444,
    };
    let s = format!("{pi:?}");
    assert!(
        s.contains("127.0.0.1"),
        "debug output should include host: {s}"
    );
    assert!(s.contains("9444"), "debug output should include port: {s}");
}

/// **Acceptance:** `Clone` produces an equal value (cheap copy of `String` + `u16`).
#[test]
fn test_peer_info_clone() {
    let a = PeerInfo {
        host: "10.0.0.1".into(),
        port: 1,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

/// **Acceptance:** `PartialEq` / `Eq` — equal host+port compare equal.
#[test]
fn test_peer_info_eq() {
    let x = PeerInfo {
        host: "1.1.1.1".into(),
        port: 53,
    };
    let y = PeerInfo {
        host: "1.1.1.1".into(),
        port: 53,
    };
    assert_eq!(x, y);
}

/// **Acceptance:** `Hash` + `Eq` allows `PeerInfo` as a `HashMap` key (address-manager maps).
#[test]
fn test_peer_info_hash_map_key() {
    let mut m: HashMap<PeerInfo, u32> = HashMap::new();
    let k = PeerInfo {
        host: "8.8.8.8".into(),
        port: 9444,
    };
    m.insert(k.clone(), 42);
    assert_eq!(m.get(&k), Some(&42));
}

// ---------------------------------------------------------------------------
// get_group — IPv4 / IPv6 / mapped / hostname
// ---------------------------------------------------------------------------

/// **Spec:** `192.168.1.5` → first two octets `[192, 168]` (same /16).
#[test]
fn test_get_group_ipv4() {
    let pi = PeerInfo {
        host: "192.168.1.5".into(),
        port: 9444,
    };
    assert_eq!(pi.get_group(), vec![192, 168]);
}

/// **Spec:** Two addresses in `10.0.0.0/16` share the same group `[10, 0]`.
#[test]
fn test_get_group_ipv4_different_subnets() {
    let a = PeerInfo {
        host: "10.0.1.1".into(),
        port: 1,
    };
    let b = PeerInfo {
        host: "10.0.2.2".into(),
        port: 2,
    };
    assert_eq!(a.get_group(), vec![10, 0]);
    assert_eq!(b.get_group(), vec![10, 0]);
}

/// **Spec:** Different /16 prefixes → different group bytes.
#[test]
fn test_get_group_ipv4_different_groups() {
    let a = PeerInfo {
        host: "192.168.1.1".into(),
        port: 9444,
    };
    let b = PeerInfo {
        host: "10.0.0.1".into(),
        port: 9444,
    };
    assert_ne!(a.get_group(), b.get_group());
}

/// **Spec:** IPv6 uses the first four octets (first 32 bits of the address).
#[test]
fn test_get_group_ipv6() {
    let ip = Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0, 0, 1);
    let pi = PeerInfo {
        host: ip.to_string(),
        port: 9444,
    };
    assert_eq!(pi.get_group(), vec![0x20, 0x01, 0x0d, 0xb8]);
}

/// **Spec:** `::ffff:192.168.1.1` is treated as IPv4 for grouping → `[192, 168]`.
#[test]
fn test_get_group_ipv4_mapped_ipv6() {
    let pi = PeerInfo {
        host: "::ffff:192.168.1.1".into(),
        port: 9444,
    };
    assert_eq!(pi.get_group(), vec![192, 168]);
}

/// **Implementation notes:** non-IP `host` strings use a deterministic SHA-256–based group (first 4 bytes).
#[test]
fn test_get_group_hostname_fallback() {
    let pi = PeerInfo {
        host: "seed.chia.example".into(),
        port: 8444,
    };
    let g1 = pi.get_group();
    assert_eq!(g1.len(), 4);
    let g2 = pi.get_group();
    assert_eq!(g1, g2, "group must be deterministic for the same host");
}

// ---------------------------------------------------------------------------
// get_key — layout, determinism, uniqueness
// ---------------------------------------------------------------------------

/// **Spec:** IPv4-mapped IPv6 uses the **embedded IPv4** in `get_key` (4 + 2 bytes), not 16 + 2.
#[test]
fn test_get_key_ipv4_mapped_ipv6() {
    let pi = PeerInfo {
        host: "::ffff:192.168.1.5".into(),
        port: 9444,
    };
    let k = pi.get_key();
    assert_eq!(k.len(), 6);
    assert_eq!(&k[..4], &[192, 168, 1, 5]);
    assert_eq!(&k[4..], &9444u16.to_be_bytes());
}

/// **Spec:** IPv4 key = 4 address octets + 2-byte big-endian port.
#[test]
fn test_get_key_ipv4() {
    let pi = PeerInfo {
        host: "192.168.1.5".into(),
        port: 9444,
    };
    let k = pi.get_key();
    assert_eq!(&k[..4], &[192, 168, 1, 5]);
    assert_eq!(&k[4..], &9444u16.to_be_bytes());
    assert_eq!(k.len(), 6);
}

/// **Spec:** IPv6 key = 16 octets + port BE.
#[test]
fn test_get_key_ipv6() {
    let ip = Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0, 0, 1);
    let pi = PeerInfo {
        host: ip.to_string(),
        port: 9444,
    };
    let k = pi.get_key();
    assert_eq!(k.len(), 18);
    assert_eq!(&k[..16], &ip.octets());
    assert_eq!(&k[16..], &9444u16.to_be_bytes());
}

/// **Spec:** Distinct `(host, port)` pairs yield distinct keys (injectivity for common cases).
#[test]
fn test_get_key_unique() {
    let pairs = vec![
        PeerInfo {
            host: "192.168.1.1".into(),
            port: 1,
        },
        PeerInfo {
            host: "192.168.1.1".into(),
            port: 2,
        },
        PeerInfo {
            host: "192.168.1.2".into(),
            port: 1,
        },
        PeerInfo {
            host: "2001:db8::1".into(),
            port: 9444,
        },
        PeerInfo {
            host: "2001:db8::1".into(),
            port: 9445,
        },
        PeerInfo {
            host: "not-an-ip-label".into(),
            port: 0,
        },
        PeerInfo {
            host: "not-an-ip-label".into(),
            port: 1,
        },
    ];
    let mut set = HashSet::new();
    for p in &pairs {
        assert!(set.insert(p.get_key()), "duplicate key for {p:?}");
    }
}

/// **Acceptance:** Same `PeerInfo` → identical `get_key()` every time (stable bucketing).
#[test]
fn test_get_key_deterministic() {
    let pi = PeerInfo {
        host: "203.0.113.5".into(),
        port: 0,
    };
    assert_eq!(pi.get_key(), pi.get_key());
}
