//! **dig_ecosystem#2391** — one anomalous frame must not tear down a peer link.
//!
//! ## What is being proven
//!
//! A peer connection survives a frame it cannot route, cannot interpret, or cannot decode, and
//! keeps serving correlated requests afterwards. Each case was separately fatal on the transport
//! dig-gossip used before the [`dig_peer_protocol::DigLink`] migration (#63):
//!
//! * a **correlation id nobody is waiting on** — the old loop returned
//!   `ClientError::UnexpectedMessage`, which ended the reader and dropped the whole connection;
//! * an **opcode with no `ProtocolMessageTypes` variant** — the old loop decoded through a closed
//!   enum, so the decode error ended the reader the same way;
//! * a **frame that does not decode at all** — same fatal decode path.
//!
//! Each gave any peer a one-frame denial primitive against the link. `DigLink`'s inbound loop
//! removes all three, but nothing in this crate proved it, so a future change could silently
//! restore the kill switch. These tests are that proof.
//!
//! ## Why these tests are shaped this way
//!
//! **The assertion is not "the frame was accepted"** — a torn-down link swallows a frame just as
//! silently. It is that a **subsequent correlated request is still served**: `connect_to` only
//! returns a peer id after its `RequestPeers` gets a `RespondPeers` back over the *same* link, and
//! the server sends that reply only after the hostile frame. Because the stream is ordered, the
//! client cannot have read the reply without first having read and survived the hostile frame.
//!
//! **Frames are driven over a real TLS websocket** by [`common::wss_full_node`], not through a
//! mock link: a symmetric encode/decode double would pass here while the real wire stayed broken.
//!
//! **The survival assertion is shown to have teeth** by
//! [`torn_down_link_fails_the_survival_assertion`], which runs the identical assertion against a
//! server that really does close the link. Without that control, a green survival test would be
//! consistent with an assertion that can never fail.
//!
//! ## What is deliberately not covered here
//!
//! `DigLink` also drops — rather than queues — an inbound frame when the application channel is
//! full, so a flood cannot wedge the reader. Driving that from this harness would mean racing a
//! burst against a service task that drains the channel continuously, which has no deterministic
//! outcome. A flaky test is worse than an absent one, so it is left to a unit test in
//! `dig-peer-protocol`, where the channel can be held without a race.

mod common;

use std::time::Duration;

use dig_gossip::{load_ssl_cert, GossipHandle, GossipService, PeerId};

use common::wss_full_node::{
    spawn_one_shot_hostile_full_node, HostileFrame, PostHandshakeBehaviour,
};

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

/// Outcome of dialling a one-shot node that applies `behaviour` after the handshake.
///
/// `Err` carries a human-readable reason so the negative control can state *how* the dial failed
/// rather than merely that it did.
async fn dial_outcome(behaviour: PostHandshakeBehaviour) -> Result<(), String> {
    let (_client_dir, _svc, handle) = running_client().await;
    let server_dir = common::test_temp_dir();
    let (cert_path, key_path) = common::generate_test_certs(server_dir.path());
    let server_cert = load_ssl_cert(&cert_path, &key_path).expect("server tls");
    let network_id = common::test_network_id().to_string();

    let (addr, _server) =
        spawn_one_shot_hostile_full_node(server_cert, network_id, behaviour, vec![]).await;

    let peer_id = match tokio::time::timeout(DIAL_BUDGET, handle.connect_to(addr)).await {
        Err(_) => return Err("dial hung past the budget".to_string()),
        Ok(Err(e)) => return Err(format!("dial failed: {e:?}")),
        Ok(Ok(peer_id)) => peer_id,
    };

    if peer_id == PeerId::default() {
        return Err("connected peer has no identity".to_string());
    }
    if handle.__con001_last_address_batch_for_tests().is_none() {
        return Err("no RequestPeers/RespondPeers exchange completed".to_string());
    }
    Ok(())
}

/// Dial a one-shot node that injects `hostile` after the handshake, and assert the link still
/// completed the `RequestPeers` exchange that follows it.
async fn assert_link_survives(hostile: HostileFrame) {
    if let Err(why) = dial_outcome(PostHandshakeBehaviour::Inject(hostile)).await {
        panic!("a {hostile:?} frame took down the link: {why}");
    }
}

/// A reply correlated to an id nobody is waiting on is routed to the application, not fatal.
#[tokio::test]
async fn unmatched_correlation_id_does_not_drop_the_link() {
    assert_link_survives(HostileFrame::UnmatchedCorrelationId).await;
}

/// A frame carrying an opcode this build has no meaning for costs that frame, not the connection.
#[tokio::test]
async fn unknown_opcode_does_not_drop_the_link() {
    assert_link_survives(HostileFrame::UnknownOpcode).await;
}

/// A frame that does not decode is skipped; websocket frames are self-delimiting, so it cannot
/// desynchronise the ones after it.
#[tokio::test]
async fn malformed_frame_does_not_drop_the_link() {
    assert_link_survives(HostileFrame::MalformedFrame).await;
}

/// **Negative control for the three tests above.**
///
/// The same dial, against a server that closes the link right after the handshake instead of
/// injecting a frame. It must NOT report success — if it did, the survival assertion would be
/// satisfied by a dead link and the tests above would prove nothing.
#[tokio::test]
async fn torn_down_link_fails_the_survival_assertion() {
    let outcome = dial_outcome(PostHandshakeBehaviour::TearDown).await;
    let why = outcome.expect_err(
        "a link closed immediately after the handshake was reported as a completed dial — the \
         survival assertion used by the #2391 tests cannot detect a torn-down link",
    );
    println!("[control] torn-down link correctly rejected: {why}");
}

/// **Fixture guard.** Each hostile frame must still have the property its case is named for.
///
/// A fixture that quietly stopped being hostile — a "malformed" frame that in fact decodes, an
/// "unknown" opcode this build later allocated — would leave all three tests above green while
/// exercising nothing. This pins the fixtures to the decoder itself.
#[test]
fn hostile_fixtures_still_have_the_property_they_are_named_for() {
    use dig_gossip::{DigMessage, Streamable};
    use dig_peer_protocol::ALL_DIG_OPCODES;

    let malformed = HostileFrame::MalformedFrame.to_wire_bytes();
    assert!(
        DigMessage::from_bytes(&malformed).is_none(),
        "the MalformedFrame fixture decodes, so it no longer exercises the skip-a-bad-frame path"
    );

    let unknown = DigMessage::from_bytes(&HostileFrame::UnknownOpcode.to_wire_bytes())
        .expect("the UnknownOpcode fixture must be a well-formed frame with an unusable opcode");
    let known_dig_opcode = ALL_DIG_OPCODES.contains(&unknown.msg_type);
    let known_chia_opcode =
        dig_gossip::ProtocolMessageTypes::from_bytes(&[unknown.msg_type]).is_ok();
    assert!(
        !known_dig_opcode && !known_chia_opcode,
        "opcode {} is no longer unallocated — pick the next free DIG-band slot",
        unknown.msg_type
    );

    let unmatched = DigMessage::from_bytes(&HostileFrame::UnmatchedCorrelationId.to_wire_bytes())
        .expect("the UnmatchedCorrelationId fixture must be a well-formed frame");
    assert_eq!(
        unmatched.id,
        Some(0xBEEF),
        "the UnmatchedCorrelationId fixture must carry a correlation id nobody is waiting on"
    );
}
