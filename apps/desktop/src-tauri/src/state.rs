//! Application state: the local identity, and the session when connected.

use parking_lot::Mutex;
use pickle_audio::AudioEngine;
use pickle_client::{Client, TrustStore};
use pickle_identity::{Identity, Keystore};
use std::path::PathBuf;
use std::sync::Arc;

const IDENTITY_FILE: &str = "identity.json";
const TRUST_FILE: &str = "known_servers.json";

/// Everything alive while connected to a server.
pub struct ActiveSession {
    pub client: Arc<Client>,
    pub engine: Arc<AudioEngine>,
    pub event_pump: tokio::task::JoinHandle<()>,
}

impl ActiveSession {
    /// Tear the session down in dependency order.
    pub fn shutdown(self) {
        self.event_pump.abort();
        self.client.disconnect();
        // Dropping the engine stops the audio streams, which closes the frame
        // channel and lets the capture pump thread finish by itself.
    }
}

pub struct AppState {
    /// Shared rather than cloned: `Identity` holds secret key material and is
    /// deliberately not `Clone`.
    pub identity: Arc<Mutex<Identity>>,
    pub nickname: Mutex<String>,
    pub identity_path: PathBuf,
    pub trust_path: PathBuf,
    pub session: Mutex<Option<ActiveSession>>,
}

impl AppState {
    /// Load the stored identity, generating one on first run.
    pub fn load() -> Result<Self, String> {
        let dir = data_dir();
        let identity_path = dir.join(IDENTITY_FILE);

        let default_nickname = default_nickname();
        let loaded = Keystore::load_or_create(&identity_path, &default_nickname)
            .map_err(|e| e.to_string())?;

        Ok(Self {
            identity: Arc::new(Mutex::new(loaded.identity)),
            nickname: Mutex::new(loaded.nickname),
            identity_path,
            trust_path: dir.join(TRUST_FILE),
            session: Mutex::new(None),
        })
    }

    pub fn trust_store(&self) -> Result<TrustStore, String> {
        TrustStore::open(&self.trust_path).map_err(|e| e.to_string())
    }

    /// Write the identity back, preserving whatever nickname is set.
    pub fn persist_identity(&self) -> Result<(), String> {
        let identity = self.identity.lock();
        let nickname = self.nickname.lock().clone();
        Keystore::save(&self.identity_path, &identity, &nickname).map_err(|e| e.to_string())
    }

    /// Close any live session. Safe to call when already disconnected.
    pub fn end_session(&self) {
        if let Some(session) = self.session.lock().take() {
            session.shutdown();
        }
    }
}

/// Per-user application data directory, with a local fallback for platforms
/// that do not provide one.
pub fn data_dir() -> PathBuf {
    directories::ProjectDirs::from("dev", "pickle", "pickle")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("./pickle-data"))
}

/// A first-run nickname that is not simply "user".
fn default_nickname() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "pickle".to_string())
}
