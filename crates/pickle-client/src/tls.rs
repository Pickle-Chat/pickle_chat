//! Client-side TLS for the QUIC connection.
//!
//! The certificate verifier accepts any certificate. That looks alarming out of
//! context, so to be precise about what it does and does not mean:
//!
//! TLS here provides the encrypted, integrity-protected channel and nothing
//! else. Server *authentication* happens one layer up, where `ServerHello`
//! carries the server's Ed25519 signature over the hash of the very
//! certificate that TLS just negotiated. A machine in the middle would have to
//! present its own certificate — and could not produce a valid signature over
//! that certificate's hash without the server's identity key.
//!
//! So the connection is authenticated; it is simply authenticated by pinned
//! identity rather than by a certificate authority, which is the only option
//! available to a server reached at a bare IP address. What this does *not*
//! do is protect the very first connection to an unknown server. See
//! [`crate::trust`].

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;
use std::time::Duration;

const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct IdentityPinnedVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for IdentityPinnedVerifier {
    /// Deliberately unconditional — see the module docs. The real check is the
    /// signature over this certificate's hash in `ServerHello`.
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// Still verified properly: this proves the peer holds the private key for
    /// the certificate it presented, which is what binds our identity check to
    /// this TLS session.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
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
        rustls::crypto::verify_tls13_signature(
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

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn quinn_client_config() -> Result<quinn::ClientConfig, rustls::Error> {
    install_crypto_provider();

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(IdentityPinnedVerifier { provider }))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![pickle_proto::ALPN.to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| rustls::Error::General(e.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        MAX_IDLE_TIMEOUT
            .try_into()
            .expect("30s is a representable QUIC idle timeout"),
    ));
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    transport.datagram_receive_buffer_size(Some(pickle_proto::voice::MAX_DATAGRAM_LEN * 256));
    transport.datagram_send_buffer_size(pickle_proto::voice::MAX_DATAGRAM_LEN * 256);
    config.transport_config(Arc::new(transport));

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_config_can_be_built() {
        assert!(quinn_client_config().is_ok());
    }

    #[test]
    fn the_alpn_matches_the_protocol_crate() {
        // A mismatch would fail the TLS handshake with an opaque error, so it
        // is worth catching here rather than at runtime.
        assert_eq!(pickle_proto::ALPN, b"pickle/1");
    }
}
