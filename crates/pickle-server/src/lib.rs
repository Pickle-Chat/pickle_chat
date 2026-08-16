//! A self-hosted Pickle server.
//!
//! There is no cloud component and nothing to register with. Run the binary,
//! open a UDP port, and share the address. Identity, certificate, and
//! configuration all live in one data directory that can be copied between
//! machines to move a server without users noticing.

pub mod config;
pub mod session;
pub mod state;
pub mod tls;

pub use config::ServerConfig;
pub use state::Shared;

use anyhow::{Context, Result};
use pickle_identity::Keystore;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info};

const IDENTITY_FILE: &str = "identity.json";

pub struct Server {
    endpoint: quinn::Endpoint,
    shared: Arc<Shared>,
}

impl Server {
    /// Bind the QUIC endpoint, loading or creating everything in `data_dir`.
    ///
    /// Binding to port 0 is supported and useful in tests; read the real port
    /// back from [`Server::local_addr`].
    pub async fn bind(config: ServerConfig, data_dir: &Path) -> Result<Self> {
        config.validate()?;

        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("creating data directory {}", data_dir.display()))?;

        // The server's own identity. Clients pin it, so it must outlive
        // certificate rotations — hence a separate file from the TLS key.
        let loaded = Keystore::load_or_create(&data_dir.join(IDENTITY_FILE), &config.name)
            .context("loading the server identity")?;

        let tls = tls::load_or_create(data_dir).context("loading the server certificate")?;
        let quinn_config = tls::quinn_server_config(&tls)?;

        let endpoint = quinn::Endpoint::server(quinn_config, config.bind)
            .with_context(|| format!("binding {}", config.bind))?;

        let shared = Arc::new(Shared::new(config, loaded.identity, tls.cert_hash));

        Ok(Self { endpoint, shared })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("reading the local address")
    }

    pub fn shared(&self) -> Arc<Shared> {
        Arc::clone(&self.shared)
    }

    /// The identity clients will pin. Worth printing at startup so an operator
    /// can share it out of band.
    pub fn fingerprint(&self) -> pickle_identity::Fingerprint {
        self.shared.identity.fingerprint()
    }

    /// Accept connections until `shutdown` resolves.
    pub async fn run_until(self, shutdown: impl std::future::Future<Output = ()>) {
        let shared = Arc::clone(&self.shared);
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        // The endpoint was closed underneath us.
                        break;
                    };
                    tokio::spawn(session::serve(Arc::clone(&shared), incoming));
                }
                _ = &mut shutdown => {
                    info!("shutting down");
                    break;
                }
            }
        }

        shared.disconnect_all(pickle_proto::DisconnectReason::ServerShutdown);
        // Give in-flight close frames a moment to reach clients before the
        // socket goes away.
        self.endpoint.close(0u32.into(), b"server shutting down");
        self.endpoint.wait_idle().await;
    }

    /// Accept connections until Ctrl-C.
    pub async fn run(self) {
        self.run_until(async {
            if let Err(e) = tokio::signal::ctrl_c().await {
                error!(error = %e, "could not listen for ctrl-c; running until killed");
                std::future::pending::<()>().await;
            }
        })
        .await
    }
}
