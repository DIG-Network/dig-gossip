//! Regression tests for the three broadcast-path defects found while proving node-to-node profile
//! sync (dig_ecosystem#3061, #3062, #3063).
//!
//! ## The defects
//!
//! * **#3061 — a repeat announce of unchanged state was a permanent no-op.** The seen-set key is
//!   `SHA256(msg_type || data)`, so a PROFILE_ROOT_ANNOUNCE for a fixed `(store_id, root)` is
//!   byte-identical every time it is produced. The FIRST announce — often made at ZERO peers, during
//!   startup — recorded the hash, and every later announce of that unchanged root returned `Ok(0)`
//!   before touching the peer map, for the life of the process. A peer that joined afterwards could
//!   therefore never learn the root.
//! * **#3063 — the return value counted peers that received nothing.** `stub + eager + lazy` was
//!   returned while only stub + eager were sent to, so a caller logging "announced to N peers" was
//!   reporting intent, not delivery — which is how #3061 and #3062 stayed invisible under live
//!   testing.
//!
//! ## What is under test here
//!
//! [`GossipHandle::broadcast_local`] — the LOCALLY-ORIGINATED path — must reach the peer set on
//! every call, while [`GossipHandle::broadcast`] — the FORWARDING path — must keep suppressing a
//! message it has already seen, or gossip becomes a broadcast storm. The pair is only correct
//! together, so both directions are asserted, including the cross-property that a local announce
//! still ARMS the suppressor against an echo of itself.

mod common;

use std::net::SocketAddr;

use dig_gossip::{DigMessage, GossipHandle, GossipService, NodeType};

/// Opcode 223 — PROFILE_ROOT_ANNOUNCE, the opcode whose byte-identical repeat announce is the whole
/// point of #3061.
const PROFILE_ROOT_ANNOUNCE: u8 = 223;

async fn running_handle() -> (GossipService, GossipHandle, tempfile::TempDir) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("new");
    let handle = svc.start().await.expect("start");
    (svc, handle, dir)
}

/// A fixed announce frame: the SAME `(store_id, root)` twice produces the SAME bytes, which is
/// exactly the input the seen-set could not distinguish from a duplicate.
fn unchanged_root_announce() -> DigMessage {
    DigMessage::new(PROFILE_ROOT_ANNOUNCE, None, vec![7u8; 64].into())
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// **#3061 core regression.** A node announces an unchanged root while a peer set exists, a SECOND
/// peer joins, and the node re-announces the same root: the re-announce must reach BOTH peers.
///
/// The fixture deliberately keeps an honest control — peer `a` is present for both announces — so the
/// assertion distinguishes "the re-announce reached the whole peer set" from "the re-announce reached
/// only the newcomer". Before the fix the second call returned `Ok(0)`: not a partial delivery, a
/// total one, and the count could not tell the difference without the control.
#[tokio::test]
async fn repeat_local_announce_of_an_unchanged_root_reaches_the_peer_set_again() {
    let (_svc, handle, _dir) = running_handle().await;

    handle
        .__connect_stub_peer_with_direction(addr("127.0.0.1:19001"), NodeType::FullNode, true)
        .await
        .unwrap();

    let first = handle
        .broadcast_local(unchanged_root_announce(), None)
        .await
        .unwrap();
    assert_eq!(first, 1, "the first announce reaches the one peer present");

    // The late joiner — the peer that #3061 made permanently unreachable for this root.
    handle
        .__connect_stub_peer_with_direction(addr("127.0.0.1:19002"), NodeType::FullNode, true)
        .await
        .unwrap();

    let second = handle
        .broadcast_local(unchanged_root_announce(), None)
        .await
        .unwrap();
    assert_eq!(
        second, 2,
        "a re-announce of an UNCHANGED root must reach the whole peer set, \
         including the peer that joined after the first announce"
    );
}

/// **#3061, the startup case measured live.** The first announce happens at ZERO peers, which
/// legitimately delivers to nobody; that must not poison the root for every peer that arrives later.
#[tokio::test]
async fn an_announce_made_at_zero_peers_does_not_poison_later_announces() {
    let (_svc, handle, _dir) = running_handle().await;

    let at_startup = handle
        .broadcast_local(unchanged_root_announce(), None)
        .await
        .unwrap();
    assert_eq!(at_startup, 0, "no peers yet — nobody is reached");

    handle
        .__connect_stub_peer_with_direction(addr("127.0.0.1:19011"), NodeType::FullNode, true)
        .await
        .unwrap();

    let after_peer_joined = handle
        .broadcast_local(unchanged_root_announce(), None)
        .await
        .unwrap();
    assert_eq!(
        after_peer_joined, 1,
        "the zero-peer startup announce must not suppress the announce that can actually be delivered"
    );
}

/// **The guard #3061's fix must NOT remove.** `broadcast` is the FORWARDING path; re-forwarding a
/// message this node has already forwarded is the broadcast storm the seen-set exists to prevent.
#[tokio::test]
async fn forwarded_broadcast_still_suppresses_a_message_already_seen() {
    let (_svc, handle, _dir) = running_handle().await;

    handle
        .__connect_stub_peer_with_direction(addr("127.0.0.1:19021"), NodeType::FullNode, true)
        .await
        .unwrap();

    let msg = unchanged_root_announce();
    let first = handle.broadcast(msg.clone(), None).await.unwrap();
    assert_eq!(first, 1, "the first forward fans out");

    let second = handle.broadcast(msg, None).await.unwrap();
    assert_eq!(
        second, 0,
        "forwarding a message already seen must stay suppressed — this is the loop guard"
    );
}

/// **The cross-property.** A local announce must still ARM the suppressor: when the announce loops
/// back from a peer and is offered to the FORWARDING path, it must be dropped. Without this, the
/// #3061 fix would turn every local announce into the seed of a storm.
#[tokio::test]
async fn a_local_announce_still_arms_the_forwarding_suppressor() {
    let (_svc, handle, _dir) = running_handle().await;

    handle
        .__connect_stub_peer_with_direction(addr("127.0.0.1:19031"), NodeType::FullNode, true)
        .await
        .unwrap();

    let msg = unchanged_root_announce();
    handle.broadcast_local(msg.clone(), None).await.unwrap();

    let echoed_back = handle.broadcast(msg, None).await.unwrap();
    assert_eq!(
        echoed_back, 0,
        "an echo of our own announce, offered to the forwarding path, must be suppressed"
    );
}
