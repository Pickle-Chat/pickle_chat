//! TLS material for the QUIC endpoint.
//!
//! The server uses a self-signed certificate, generated once and then reused.
//! There is no certificate authority anywhere in Pickle and no domain to
//! validate against — a self-hosted server is usually reached by bare IP, which
//! the public CA system cannot vouch for anyway.
//!
//! Authentication instead rests on the server's Ed25519 identity, which signs
//! the certificate hash inside `ServerHello`. Clients pin the identity on first
//! connection and check it every time after, so the certificate is only a
//! transport-layer key exchange — trust lives one layer up. That also means the
//! certificate can be regenerated without users seeing a scary warning, as long
//! as the identity key survives.

use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Idle time before a connection is considered dead. Long enough to survive a
/// brief network blip, short enough that a vanished client leaves the user list
/// promptly.
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Keep-alives hold NAT bindings open while a user sits silent in a channel.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

const CERT_FILE: &str = "cert.der";
const KEY_FILE: &str = "key.der";

pub struct ServerTls {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    /// SHA-256 of the end-entity certificate DER. Signed by the server identity
    /// and checked by clients, binding the identity to this TLS session.
    pub cert_hash: [u8; 32],
}

/// Install the process-wide rustls crypto provider.
///
/// Safe to call repeatedly; losing the race just means someone else installed
/// the same provider first.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Load the stored certificate, generating and persisting one if absent.
pub fn load_or_create(dir: &Path) -> Result<ServerTls> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);

    let (cert_der, key_der) = match (std::fs::read(&cert_path), std::fs::read(&key_path)) {
        (Ok(cert), Ok(key)) => (cert, key),
        _ => {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating server data directory {}", dir.display()))?;

            // The SAN is a placeholder: nothing verifies hostnames here.
            let generated = rcgen::generate_simple_self_signed(vec!["pickle".to_string()])
                .context("generating a self-signed certificate")?;
            let cert = generated.cert.der().to_vec();
            let key = generated.key_pair.serialize_der();

            std::fs::write(&cert_path, &cert)
                .with_context(|| format!("writing {}", cert_path.display()))?;
            write_private(&key_path, &key)
                .with_context(|| format!("writing {}", key_path.display()))?;

            (cert, key)
        }
    };

    let cert_hash: [u8; 32] = Sha256::digest(&cert_der).into();

    Ok(ServerTls {
        chain: vec![CertificateDer::from(cert_der)],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        cert_hash,
    })
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// Build the QUIC server configuration.
pub fn quinn_server_config(tls: &ServerTls) -> Result<quinn::ServerConfig> {
    install_crypto_provider();

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        // Clients are identified by Ed25519 signature on the control stream,
        // not by a TLS client certificate.
        .with_single_cert(tls.chain.clone(), tls.key.clone_key())
        .context("installing the server certificate")?;
    crypto.alpn_protocols = vec![pickle_proto::ALPN.to_vec()];

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto).context("preparing the QUIC TLS configuration")?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        MAX_IDLE_TIMEOUT
            .try_into()
            .expect("30s is a representable QUIC idle timeout"),
    ));
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    // Voice needs datagrams; without a receive buffer quinn refuses them and
    // the peer's `max_datagram_size` reads as None.
    transport.datagram_receive_buffer_size(Some(pickle_proto::voice::MAX_DATAGRAM_LEN * 256));
    transport.datagram_send_buffer_size(pickle_proto::voice::MAX_DATAGRAM_LEN * 256);
    config.transport_config(Arc::new(transport));

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_is_generated_then_reused() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create(dir.path()).unwrap();
        let second = load_or_create(dir.path()).unwrap();

        // Stability matters: clients pin this hash on first connection.
        assert_eq!(first.cert_hash, second.cert_hash);
        assert!(dir.path().join(CERT_FILE).exists());
        assert!(dir.path().join(KEY_FILE).exists());
    }

    #[test]
    fn separate_servers_get_separate_certificates() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        assert_ne!(
            load_or_create(a.path()).unwrap().cert_hash,
            load_or_create(b.path()).unwrap().cert_hash
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_private_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        load_or_create(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_quinn_config_can_be_built_from_generated_material() {
        let dir = tempfile::tempdir().unwrap();
        let tls = load_or_create(dir.path()).unwrap();
        assert!(quinn_server_config(&tls).is_ok());
    }
}
