//! **dig_ecosystem#2391** — one anomalous frame must not tear down a peer link.
//!
//! ## What is being proven
//!
//! A peer connection survives a frame it cannot route or cannot understand, and keeps serving
//! correlated requests afterwards. Two frames are anomalous in ways that were separately fatal on
//! the previous transport (`chia-sdk-client`'s receive loop):
//!
//! * a **correlation id nobody is waiting on** — the old loop returned
//!   `ClientError::UnexpectedMessage`, which ended the reader and dropped the whole connection;
//! * an **opcode with no `ProtocolMessageTypes` variant** — the old loop called
//!   `Message::from_bytes(&binary)?`, so the decode error ended the reader the same way.
//!
//! Either gave any peer a one-frame denial primitive against the link.
//!
//! ## Why these tests are shaped this way
//!
//! The assertion is not "the frame was accepted" — a torn-down link accepts a frame just as
//! silently. It is that a **subsequent correlated request is still served**: `connect_to` only
//! returns a peer id after its `RequestPeers` gets a `RespondPeers` back over the *same* link, so
//! the hostile frame must have been survived rather than merely swallowed.
//!
//! Frames are driven over a real TLS websocket by [`common::wss_full_node`], not through a mock
//! link: a symmetric encode/decode double would pass here while the real wire stayed broken.

mod common;

use std::time::Duration;

use dig_gossip::{load_ssl_cert, GossipHandle, GossipService, PeerId};

use common::wss_full_node::{spawn_one_shot_hostile_full_node, HostileFrame};

/// A dial must never take this long; a link killed by the hostile frame leaves `connect_to`
/// waiting on a reply that can no longer arrive, so the bound turns a hang into a failure.
const DIAL_BUDGET: Duration = Duration::from_secs(20);

/// A started client service plus its handle. The temp dir and service are returned so the caller
/// keeps them alive for the duration of the test.
async fn running_client() -> (tempfile::TempDir, GossipService, GossipHandle) {
    let dir = common::test_temp_dir();
    let _ = common::generate_test_certs(dir.path());
    let cfg = common::test_gossip_config(dir.path());
    let svc = GossipService::new(cfg).expect("GossipService::new");
    let h = svc.start().await.expect("start");
    (dir, svc, h)
}

/// Dial a one-shot full node that injects `hostile` after the handshake, and assert the link
/// still completed the `RequestPeers` exchange that follows it.
async fn assert_link_survives(hostile: HostileFrame) {
    let (_client_dir, _svc, handle) = running_client().await;
    let server_dir = common::test_temp_dir();
    let (cert_path, key_path) = common::generate_test_certs(server_dir.path());
    let server_cert = load_ssl_cert(&cert_path, &key_path).expect("server tls");
    let network_id = common::test_network_id().to_string();

    let (addr, server) =
        spawn_one_shot_hostile_full_node(server_cert, network_id, hostile, vec![]).await;

    let peer_id = tokio::time::timeout(DIAL_BUDGET, handle.connect_to(addr))
        .await
        .unwrap_or_else(|_| panic!("dial hung after a {hostile:?} frame — the link was torn down"))
        .unwrap_or_else(|e| panic!("dial failed after a {hostile:?} frame: {e:?}"));

    assert_ne!(peer_id, PeerId::default(), "connected peer has no identity");
    assert!(
        handle.__con001_last_address_batch_for_tests().is_some(),
        "no RequestPeers/RespondPeers exchange completed after the {hostile:?} frame, so the \
         link did not survive it"
    );

    server
        .await
        .expect("server task join")
        .expect("server completed the full sequence");
}

/// A reply correlated to an id nobody is waiting on is routed to the application, not fatal.
#[tokio::test]
async fn unmatched_correlation_id_does_not_drop_the_link() {
    assert_link_survives(HostileFrame::UnmatchedCorrelationId).await;
}

/// A frame carrying an opcode this build does not know costs that frame, not the connection.
#[tokio::test]
async fn unknown_opcode_does_not_drop_the_link() {
    assert_link_survives(HostileFrame::UnknownOpcode).await;
}
