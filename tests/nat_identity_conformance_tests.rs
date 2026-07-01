//! INT-016 — `peer_id` identity conformance between `dig-gossip` and `dig-nat`.
//!
//! The L7 peer-network spec freezes `peer_id = SHA-256(TLS SPKI DER)` as the ONE identity every
//! peer-facing crate must derive identically (docs.dig.net "L7 · DIG Node peer network" §1 +
//! §11 Conformance). `dig-gossip` and `dig-nat` each implement the derivation independently
//! (`dig-nat` deliberately does not depend on the heavy `dig-gossip`/Chia stack), so this suite is
//! the cross-crate guard that the two never drift: given the SAME SPKI DER (and the SAME leaf
//! certificate), both crates MUST produce byte-identical 32-byte ids.
//!
//! If this ever fails, the peer transport would mis-identify peers across the two crates and the
//! network would not interop — so a drift here is a hard bug, not a warning.

use dig_gossip::peer_id_from_tls_spki_der as gossip_peer_id;
use dig_nat::peer_id_from_tls_spki_der as nat_peer_id;
use dig_nat::{peer_id_from_leaf_cert_der as nat_peer_id_from_cert, PeerId as NatPeerId};

/// Both crates hash the SAME SPKI DER to the SAME 32 bytes (the frozen `peer_id` derivation).
#[test]
fn peer_id_from_spki_der_matches_across_crates() {
    // A few representative SPKI-DER-shaped blobs (content is opaque to the hash; we only need the
    // two crates to agree on SHA-256 of identical input).
    let samples: [&[u8]; 3] = [
        b"",
        b"the quick brown fox jumps over the lazy dog",
        &[
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        ],
    ];
    for spki in samples {
        let g = gossip_peer_id(spki); // dig-gossip: Bytes32
        let n = nat_peer_id(spki); // dig-nat: PeerId newtype
        assert_eq!(
            g.as_ref(),
            n.as_bytes(),
            "dig-gossip and dig-nat must derive the same peer_id from identical SPKI DER"
        );
    }
}

/// A real self-signed leaf certificate: `dig-nat`'s cert-level extractor + hash equals
/// `dig-gossip`'s SPKI-level hash of the SAME certificate's SubjectPublicKeyInfo. This proves the
/// two crates lift the SAME bytes from a certificate AND hash them the same way — the end-to-end
/// identity a peer actually presents in the mTLS handshake.
#[test]
fn peer_id_from_leaf_cert_matches_gossip_spki_hash() {
    // Generate an ephemeral self-signed cert (the kind a node generates on first run).
    let cert = rcgen::generate_simple_self_signed(vec!["dig-node.test".to_string()])
        .expect("generate self-signed cert");
    let cert_der = cert.cert.der().to_vec();

    // dig-nat: derive peer_id straight from the leaf certificate DER.
    let nat_id: NatPeerId =
        nat_peer_id_from_cert(&cert_der).expect("dig-nat parses the leaf cert + derives peer_id");

    // dig-gossip: lift the SPKI DER from the same cert (x509-parser, as CON-001 does), then hash.
    let (_, x509) =
        x509_parser::parse_x509_certificate(&cert_der).expect("parse leaf cert with x509-parser");
    let spki_der = x509.tbs_certificate.subject_pki.raw;
    let gossip_id = gossip_peer_id(spki_der);

    assert_eq!(
        gossip_id.as_ref(),
        nat_id.as_bytes(),
        "peer_id lifted from a real leaf cert must match across dig-gossip and dig-nat"
    );
}
