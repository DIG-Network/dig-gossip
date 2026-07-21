//! Inbound rustls acceptor for the CON-009 mutual-TLS handshake (#1371).
//!
//! ## Why rustls (and not `native_tls`) for the inbound server
//!
//! The peer identity is `peer_id = SHA-256(remote TLS SPKI DER)` (SPEC §5.3 / CLAUDE.md §5.2),
//! which requires the server to **request, require, and capture** the peer's client certificate
//! during the TLS handshake. The previous inbound acceptor used `native_tls::TlsAcceptor`, whose
//! "require client cert" behaviour on OpenSSL/Linux lived in a **vendored `native-tls` fork**
//! (`vendor/native-tls`). A `[patch.crates-io]` fork does **not** propagate through a *git*
//! dependency (dig-node consumes dig-gossip by git rev and patches only `chia-protocol` +
//! `chia-sdk-client`, never `native-tls`). So in dig-node's build the stock `native-tls` shipped,
//! the server never asked for the client cert, `peer_certificate()` returned `None` on OpenSSL, and
//! **every inbound gossip connection was dropped** — the #1062 EC2 e2e "strangers cannot connect"
//! failure, masked on Windows/macOS by the `peer_id_for_addr` fallback.
//!
//! rustls sidesteps the root cause entirely: the client-cert request is configured in pure Rust via
//! a [`ClientCertVerifier`], so the behaviour is identical on every platform and needs no patch to
//! propagate.
//!
//! ## CA-agnostic by design (Option A)
//!
//! DIG peers present **self-signed / chia-ssl** certificates — there is no shared CA chain to
//! validate against (validating one would reject every current peer). This verifier therefore
//! **requests and requires** a client certificate and **captures** it, but does **not** validate it
//! against any trust anchor. Authorization stays where it already is: `peer_id` derivation plus the
//! §21.9 signed-request layer downstream. Possession of the certificate's private key is still
//! proven — rustls checks the CertificateVerify signature via [`verify_tls12_signature`] /
//! [`verify_tls13_signature`], so a peer cannot spoof another peer's certificate.
//!
//! The server presents the node's **existing** chia-ssl [`ChiaCertificate`], loaded here as standard
//! X.509 + PKCS#8 into rustls, so the SPKI it advertises — and thus this node's own `peer_id` — is
//! **byte-identical** to the value the previous native-tls acceptor advertised.

// Large `ClientError` payloads propagate upstream `chia_sdk_client` variants verbatim, matching the
// rest of the connection module (see `listener.rs` / `outbound.rs`).
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use dig_protocol::{ChiaCertificate, ClientError};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};
use tokio::net::TcpStream;

use crate::connection::outbound::spki_der_from_leaf_cert_der;

/// A [`ClientCertVerifier`] that **requests + requires + captures** the peer certificate without
/// validating it against any certificate authority (Option A, #1371).
///
/// It still enforces proof-of-possession of the certificate's private key by delegating the
/// TLS handshake-signature checks to the crypto provider, so a peer cannot present a certificate
/// whose key it does not hold. Trust/authorization is layered downstream (`peer_id` + §21.9).
#[derive(Debug)]
struct CaptureAnyClientCert {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for CaptureAnyClientCert {
    /// Advertise a CertificateRequest to the client (so it presents its cert).
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// Require the client certificate — an anonymous client is rejected at the TLS layer.
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    /// No CA hints: we do not constrain which issuer the client may present (CA-agnostic).
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// Accept any well-formed client certificate WITHOUT chain validation.
    ///
    /// The certificate is captured by rustls into the connection's `peer_certificates()`; identity
    /// (`peer_id`) is derived from it afterwards. See the module docs for why no CA check is done.
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build the inbound [`ServerConfig`] that presents `cert` (the node's chia-ssl identity) and
/// requests + captures the peer's client certificate (CA-agnostic mTLS, #1371).
///
/// The presented SPKI is unchanged from the native-tls acceptor (same cert + key), so this node's
/// own `peer_id` stays byte-identical.
///
/// # Errors
///
/// Returns [`ClientError::Io`] if the PEM material cannot be parsed into an X.509 chain + PKCS#8
/// key, or if rustls rejects the certificate/key pair.
pub(crate) fn rustls_server_config(cert: &ChiaCertificate) -> Result<ServerConfig, ClientError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let cert_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert.cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|e| io_err(format!("inbound cert PEM parse: {e}")))?;
    if cert_chain.is_empty() {
        return Err(io_err(
            "inbound cert PEM contained no certificates".to_string(),
        ));
    }

    let key = rustls_pemfile::pkcs8_private_keys(&mut cert.key_pem.as_bytes())
        .next()
        .ok_or_else(|| io_err("inbound key PEM contained no PKCS#8 key".to_string()))?
        .map_err(|e| io_err(format!("inbound key PEM parse: {e}")))?;

    let verifier = Arc::new(CaptureAnyClientCert {
        provider: provider.clone(),
    });

    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io_err(format!("rustls protocol versions: {e}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, PrivateKeyDer::Pkcs8(key))
        .map_err(|e| io_err(format!("rustls server config: {e}")))
}

/// Extract the remote peer's **SPKI DER** from a completed server-side rustls stream (#1371).
///
/// SPEC §5.3 — `PeerId = SHA-256(remote TLS SPKI DER)`. Mirrors the outbound capture in
/// [`crate::connection::outbound`], so the derived `peer_id` is byte-identical regardless of which
/// side initiated or which TLS backend captured the certificate bytes.
///
/// # Errors
///
/// - [`ClientError::MissingHandshake`] — the peer presented no client certificate (should not happen
///   once [`CaptureAnyClientCert`] requires it, but treated as a hard rejection defensively).
/// - [`ClientError::Io`] — the leaf certificate could not be parsed for its SPKI.
pub(crate) fn remote_spki_from_rustls_stream(
    tls: &tokio_rustls::server::TlsStream<TcpStream>,
) -> Result<Vec<u8>, ClientError> {
    let (_tcp, conn) = tls.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or(ClientError::MissingHandshake)?;
    let leaf = certs.first().ok_or(ClientError::MissingHandshake)?;
    spki_der_from_leaf_cert_der(leaf.as_ref())
}

/// Wrap a `format!`ed message as an `InvalidData` [`ClientError::Io`].
fn io_err(msg: String) -> ClientError {
    ClientError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, msg))
}

#[cfg(test)]
mod tests {
    //! #1371 regression: the inbound rustls acceptor MUST request + require + capture the peer's
    //! client certificate on every platform (the OpenSSL/Linux "cert never requested → peer_id
    //! underivable → inbound dropped" bug), and the captured `peer_id` MUST be byte-identical to the
    //! value the shared SPKI-hash helpers derive for the same certificate (custody invariant).

    use super::*;
    use crate::types::peer::peer_id_from_tls_spki_der;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Accept-any server-cert verifier for the TEST client (mirrors the outbound connector).
    #[derive(Debug)]
    struct AcceptAnyServerCert(Arc<CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Build a rustls client config that PRESENTS `client_cert` (client auth) and trusts any server.
    fn client_config_presenting(client_cert: &ChiaCertificate) -> rustls::ClientConfig {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let chain: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut client_cert.cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .expect("client cert PEM");
        let key = rustls_pemfile::pkcs8_private_keys(&mut client_cert.key_pem.as_bytes())
            .next()
            .expect("client key present")
            .expect("client key PEM");
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
            .with_client_auth_cert(chain, PrivateKeyDer::Pkcs8(key))
            .expect("client auth cert")
    }

    /// The expected `peer_id` for `cert`, computed straight from its PEM via the SAME shared helpers
    /// the outbound path uses — the byte-identical reference value.
    fn expected_peer_id_from_pem(cert: &ChiaCertificate) -> crate::types::peer::PeerId {
        let leaf: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert.cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .expect("cert PEM");
        let spki = spki_der_from_leaf_cert_der(leaf[0].as_ref()).expect("spki");
        peer_id_from_tls_spki_der(&spki)
    }

    /// #1371: a stranger's inbound rustls connection presents its client cert, the acceptor captures
    /// it, and the derived `peer_id` equals `SHA-256(client SPKI DER)` byte-for-byte.
    ///
    /// Fails for the right reason on the pre-fix behaviour: if the acceptor did not REQUEST the client
    /// cert, `peer_certificates()` would be `None` → [`remote_spki_from_rustls_stream`] returns
    /// [`ClientError::MissingHandshake`] and the capture `expect` below panics.
    #[tokio::test]
    async fn issue_1371_inbound_rustls_captures_peer_cert_and_derives_byte_identical_peer_id() {
        // Two distinct node certs — the server's identity and the connecting stranger's.
        let server_cert = ChiaCertificate::generate().expect("server cert");
        let client_cert = ChiaCertificate::generate().expect("client cert");
        let expected_peer_id = expected_peer_id_from_pem(&client_cert);

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls_server_config(&server_cert).expect("server config"),
        ));
        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(client_config_presenting(&client_cert)));

        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        // Server task: accept the mTLS handshake and capture the peer SPKI → peer_id.
        let server = tokio::spawn(async move {
            let (tcp, _peer) = listener.accept().await.expect("accept tcp");
            let tls = acceptor.accept(tcp).await.expect("server tls accept");
            // If the acceptor never requested the client cert this returns MissingHandshake.
            let spki = remote_spki_from_rustls_stream(&tls).expect("peer cert captured");
            // Drain the one byte the client sends so the handshake fully completes on both ends.
            let mut buf = [0u8; 1];
            let mut tls = tls;
            let _ = tls.read(&mut buf).await;
            peer_id_from_tls_spki_der(&spki)
        });

        // Client: dial, present cert, send one byte to flush the handshake.
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let domain = rustls::pki_types::ServerName::try_from("dig.local").expect("server name");
        let mut tls = connector
            .connect(domain, tcp)
            .await
            .expect("client tls connect");
        tls.write_all(b"x").await.expect("write");
        tls.flush().await.expect("flush");

        let derived_peer_id = server.await.expect("server task");

        assert_eq!(
            derived_peer_id, expected_peer_id,
            "rustls-captured inbound peer_id must be byte-identical to SHA-256(client SPKI DER)"
        );
    }

    /// Build a rustls client config that does NOT present a client certificate (no client auth).
    fn client_config_no_auth() -> rustls::ClientConfig {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
            .with_no_client_auth()
    }

    /// #1371 hardening: inbound rustls acceptor REQUIRES a client certificate via
    /// `client_auth_mandatory()=true`. A client dialing without a certificate MUST be
    /// rejected at the TLS handshake layer (rustls error, not a downstream DIG layer).
    ///
    /// Proves that `CaptureAnyClientCert` enforces the mandatory requirement.
    #[tokio::test]
    async fn issue_1371_certless_inbound_client_is_rejected() {
        let server_cert = ChiaCertificate::generate().expect("server cert");

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls_server_config(&server_cert).expect("server config"),
        ));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config_no_auth()));

        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        // Server task: attempt to accept the mTLS handshake; it should FAIL because the client
        // presents no certificate and the acceptor requires one.
        let server = tokio::spawn(async move {
            let (tcp, _peer) = listener.accept().await.expect("accept tcp");
            acceptor.accept(tcp).await // Should return Err, not Ok
        });

        // Client: dial WITHOUT presenting a cert. The handshake should fail.
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let domain = rustls::pki_types::ServerName::try_from("dig.local").expect("server name");
        let result = connector.connect(domain, tcp).await;

        // Both client and server handshakes should fail.
        assert!(
            result.is_err(),
            "client-side: rustls must reject handshake when client presents no certificate"
        );

        let server_result = server.await.expect("server task panicked");
        assert!(
            server_result.is_err(),
            "server-side: rustls must reject handshake when client presents no certificate"
        );
    }
}
