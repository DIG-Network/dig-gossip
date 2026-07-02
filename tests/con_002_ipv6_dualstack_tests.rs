//! CON-002 extension — the inbound listener binds `[::]` (IPv6 unspecified) DUAL-STACK.
//!
//! ## Ecosystem hard rule
//!
//! dig_ecosystem `CLAUDE.md` §"IPv6-first, IPv4-fallback for peer communication": peer/node
//! listeners bind IPv6 with IPv4 accepted as a fallback off the SAME socket where the OS
//! supports it, rather than requiring two sockets or dropping IPv4 support outright. This repo's
//! [`SPEC.md`](../docs/resources/SPEC.md) §5.2 / §1.10 records the normative behaviour:
//! [`GossipService::start`] binds the configured `listen_addr` (default `[::]:9444` per API-003)
//! and, when that address is IPv6 unspecified/any, explicitly clears the `IPV6_V6ONLY` socket
//! option before `listen()` so IPv4-mapped connections (`::ffff:a.b.c.d`) are still accepted on
//! the one bound socket -- an IPv6-only bind defaults to V6ONLY on most platforms otherwise,
//! which would silently stop accepting IPv4 peers.
//!
//! ## Proof strategy
//!
//! Bind on `[::]:0` (OS-assigned ephemeral port) exactly like production, then connect to the
//! resolved port over BOTH an IPv6 loopback (`[::1]:<port>`) and an IPv4 loopback
//! (`127.0.0.1:<port>`) socket and confirm the raw TCP handshake succeeds on each -- proving one
//! socket serves both families. Skips gracefully (rather than failing) if the CI/sandbox host has
//! no usable IPv6 stack at all (binding `[::1]` fails outright), since that is an environment
//! limitation unrelated to this crate's socket configuration.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use dig_gossip::GossipService;

/// Detect whether the host has a usable IPv6 loopback stack. Some CI sandboxes disable IPv6
/// entirely, in which case dual-stack behaviour cannot be exercised end-to-end; the test skips
/// rather than reporting a false failure unrelated to this crate's own bind logic.
async fn host_has_ipv6_loopback() -> bool {
    tokio::net::TcpListener::bind("[::1]:0").await.is_ok()
}

/// A service configured with the (default-shaped) IPv6 unspecified `listen_addr` accepts BOTH
/// an IPv6 loopback connection and an IPv4 loopback connection on the same bound port.
#[tokio::test]
async fn dual_stack_listener_accepts_both_ipv6_and_ipv4_loopback() {
    if !host_has_ipv6_loopback().await {
        eprintln!("skipping: host has no usable IPv6 loopback stack");
        return;
    }

    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let mut cfg = common::test_gossip_config(dir.path());
    // Override the loopback-only test default with the production-shaped IPv6-unspecified bind
    // (port 0 for OS-assigned ephemeral allocation, same as every other CON-002 test).
    cfg.listen_addr = "[::]:0".parse().expect("parse [::]:0");
    let svc = GossipService::new(cfg).expect("GossipService::new");
    let handle = svc.start().await.expect("start");
    let bound: SocketAddr = handle
        .__listen_bound_addr_for_tests()
        .expect("listen addr after start");
    assert!(
        bound.is_ipv6(),
        "expected an IPv6 bound address, got {bound}"
    );
    let port = bound.port();

    // IPv6 loopback connect (native family match).
    let v6_addr: SocketAddr = format!("[::1]:{port}").parse().expect("parse v6 loopback");
    let v6 = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(v6_addr),
    )
    .await
    .expect("v6 connect timed out")
    .expect("IPv6 loopback connect must succeed against a [::]-bound dual-stack listener");
    drop(v6);

    // IPv4 loopback connect -- only succeeds if IPV6_V6ONLY was cleared on the listening socket.
    let v4_addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .expect("parse v4 loopback");
    let v4 = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(v4_addr),
    )
    .await
    .expect("v4 connect timed out")
    .expect(
        "IPv4 loopback connect must ALSO succeed against the same [::]-bound listener \
             (IPV6_V6ONLY must be disabled for dual-stack IPv4 fallback)",
    );
    drop(v4);

    let _ = svc.stop().await;
}
