//! A self-hosted Pickle server.
//!
//! There is no cloud component and nothing to register with. Run the binary,
//! open a UDP port, and share the address. Identity, certificate, and
//! configuration all live in one data directory that can be copied between
//! machines to move a server without users noticing.

mod admin;
pub mod config;
mod moderation;
pub mod session;
pub mod state;
pub mod store;
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
const ROLES_FILE: &str = "roles.json";
const DATABASE_FILE: &str = "pickle.db";

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

        // roles.json is a leftover from the deleted capability model. Never
        // parsed — a malformed file must not affect boot, the exact property
        // the old code fought for — just named, so its owner knows.
        if data_dir.join(ROLES_FILE).exists() {
            tracing::warn!(
                "roles.json is obsolete and no longer read; roles live in the \
                 database now. Recreate them via the admin tools, then delete \
                 the file to silence this warning."
            );
        }

        let url = config
            .database_url
            .clone()
            .unwrap_or_else(|| store::Store::sqlite_url(data_dir, DATABASE_FILE));
        let store = store::Store::open(&url)
            .await
            .context("opening the database")?;

        // Message ids come from an in-memory counter. Without resuming it past
        // what is already stored, the first restart would hand out ids that
        // collide with existing rows.
        let highest = store
            .highest_message_id()
            .await
            .context("reading the highest stored message id")?;

        // Channels and roles live in the database; the config seeds both on
        // first boot and is a template afterwards. Seeding writes before
        // anything reads, so a crash mid-seed re-seeds cleanly next start —
        // every insert is keyed and the table was empty to enter this branch.
        let mut channels = store.load_channels().await.context("loading channels")?;
        if channels.is_empty() {
            channels = state::build_channels(&config);
            for channel in &channels {
                store
                    .insert_channel(channel)
                    .await
                    .context("seeding channels from the config")?;
            }
        }

        let mut roles = store.load_roles().await.context("loading roles")?;
        if roles.is_empty() {
            roles = state::default_roles();
            for role in &roles {
                store
                    .insert_role(role)
                    .await
                    .context("seeding the default roles")?;
            }
        }

        // Overwrites ride on their channels; grants ride beside the roles.
        for (channel_id, overwrite) in store
            .load_overwrites()
            .await
            .context("loading overwrites")?
        {
            if let Some(channel) = channels.iter_mut().find(|c| c.id == channel_id) {
                channel.overwrites.push(overwrite);
            }
        }
        let mut members: std::collections::HashMap<_, Vec<_>> = Default::default();
        for (fingerprint, role) in store
            .load_role_members()
            .await
            .context("loading role grants")?
        {
            members.entry(fingerprint).or_default().push(role);
        }

        let perms = state::PermState { roles, members };
        let shared = Arc::new(Shared::new(
            config,
            loaded.identity,
            tls.cert_hash,
            channels,
            perms,
        ));
        if let Some(highest) = highest {
            shared.resume_message_ids_after(highest);
        }
        shared.attach_store(store);

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
