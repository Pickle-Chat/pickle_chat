//! `pickle-server` — run a Pickle server.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pickle_identity::Keystore;
use pickle_server::{Server, ServerConfig};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

const CONFIG_FILE: &str = "server.toml";

#[derive(Parser)]
#[command(
    name = "pickle-server",
    version,
    about = "Host a Pickle voice and chat server"
)]
struct Cli {
    /// Directory holding the identity, certificate, and configuration.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the server (default).
    Run {
        /// Override the configured listen address.
        #[arg(long)]
        bind: Option<SocketAddr>,
        /// Override the configured server name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Print this server's identity fingerprint, for sharing out of band.
    Identity,
    /// Write a default configuration file and exit.
    Init,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let data_dir = cli.data_dir.unwrap_or_else(default_data_dir);
    let config_path = data_dir.join(CONFIG_FILE);

    match cli.command.unwrap_or(Command::Run {
        bind: None,
        name: None,
    }) {
        Command::Init => {
            let config = ServerConfig::load_or_create(&config_path)?;
            println!("Wrote {}", config_path.display());
            println!("Listening address: {}", config.bind);
            println!("Minimum identity level: {}", config.min_security_level);
            Ok(())
        }

        Command::Identity => {
            let loaded = Keystore::load_or_create(&data_dir.join("identity.json"), "Pickle Server")
                .context("loading the server identity")?;
            println!("{}", loaded.identity.fingerprint());
            Ok(())
        }

        Command::Run { bind, name } => {
            let mut config = ServerConfig::load_or_create(&config_path)
                .with_context(|| format!("loading {}", config_path.display()))?;
            if let Some(bind) = bind {
                config.bind = bind;
            }
            if let Some(name) = name {
                config.name = name;
            }

            let server = Server::bind(config, &data_dir).await?;
            let addr = server.local_addr()?;

            info!(%addr, "listening");
            println!("Pickle server listening on {addr}");
            println!("Identity: {}", server.fingerprint());
            println!(
                "Share the address and identity with anyone who should connect. \
                 Remember to forward UDP {} if they are outside your network.",
                addr.port()
            );

            server.run().await;
            Ok(())
        }
    }
}

/// Platform data directory, falling back to a local folder if the OS does not
/// offer one.
fn default_data_dir() -> PathBuf {
    directories::ProjectDirs::from("dev", "pickle", "pickle-server")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("./pickle-data"))
}
