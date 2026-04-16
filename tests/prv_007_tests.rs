//! **PRV-007 — Certificate rotation infrastructure**
//!
//! Normative: [`docs/requirements/domains/privacy/specs/PRV-007.md`](../docs/requirements/domains/privacy/specs/PRV-007.md)
//! Master SPEC: [`docs/resources/SPEC.md`](../docs/resources/SPEC.md) Section 1.9.2 (Ephemeral PeerId)
//!
//! ## What this file proves
//!
//! `ChiaCertificate::generate()` from `chia-ssl` creates a valid certificate,
//! proving the rotation mechanism exists and the fundamental building block
//! (fresh cert generation) works. Full rotation loop tests are deferred to
//! integration tests that require a running `GossipService`.

use dig_gossip::ChiaCertificate;

/// `ChiaCertificate::generate()` succeeds and returns a certificate with
/// non-empty PEM material.
///
/// This is the core primitive for PRV-007 rotation: every rotation cycle
/// calls `generate()` to obtain a fresh key pair and self-signed certificate.
/// If this fails, the entire rotation subsystem is broken.
#[test]
fn test_chia_certificate_generate_succeeds() {
    let cert = ChiaCertificate::generate().expect("ChiaCertificate::generate must succeed");
    assert!(
        !cert.cert_pem.is_empty(),
        "generated certificate PEM must not be empty"
    );
    assert!(
        !cert.key_pem.is_empty(),
        "generated key PEM must not be empty"
    );
}

/// Two consecutive `generate()` calls produce distinct certificates.
///
/// Proves that each call creates a fresh key pair — if the same key were
/// reused, PeerId rotation would be ineffective (the SHA-256 hash would
/// not change).
#[test]
fn test_chia_certificate_generate_produces_distinct_certs() {
    let cert_a = ChiaCertificate::generate().expect("generate cert A");
    let cert_b = ChiaCertificate::generate().expect("generate cert B");
    assert_ne!(
        cert_a.cert_pem, cert_b.cert_pem,
        "two generated certificates must have different PEM content"
    );
    assert_ne!(
        cert_a.key_pem, cert_b.key_pem,
        "two generated keys must have different PEM content"
    );
}

/// Generated certificate PEM starts with the expected PEM header.
///
/// Sanity check that the output is valid PEM encoding, not raw DER or
/// garbage bytes.
#[test]
fn test_chia_certificate_pem_format() {
    let cert = ChiaCertificate::generate().expect("generate");
    let cert_str = std::str::from_utf8(&cert.cert_pem).expect("cert PEM must be valid UTF-8");
    assert!(
        cert_str.starts_with("-----BEGIN CERTIFICATE-----"),
        "certificate PEM must start with BEGIN CERTIFICATE header"
    );
    let key_str = std::str::from_utf8(&cert.key_pem).expect("key PEM must be valid UTF-8");
    // chia-ssl generates RSA keys wrapped in PKCS#8 (BEGIN PRIVATE KEY) or
    // traditional (BEGIN RSA PRIVATE KEY); accept either.
    assert!(
        key_str.contains("PRIVATE KEY"),
        "key PEM must contain a PRIVATE KEY block"
    );
}
