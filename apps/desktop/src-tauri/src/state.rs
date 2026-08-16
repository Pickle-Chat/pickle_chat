//! Application state: the local identity, the audio engine, and the session
//! when connected.

use crate::bookmarks::Bookmarks;
use crate::bridge;
use crate::settings::Settings;
use parking_lot::{Mutex, RwLock};
use pickle_audio::{AudioEngine, EngineConfig};
use pickle_client::{Client, TrustStore};
use pickle_identity::{Identity, Vault};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::debug;

/// The single-identity file this app used to write. Read once, to migrate.
const IDENTITY_FILE: &str = "identity.json";
const VAULT_FILE: &str = "identities.json";
const TRUST_FILE: &str = "known_servers.json";
const SETTINGS_FILE: &str = "settings.json";
const BOOKMARKS_FILE: &str = "bookmarks.json";

/// Everything alive while connected to a server.
///
/// The audio engine is deliberately **not** here. It outlives any single
/// session — the settings dialog runs it while disconnected to drive the input
/// meter — and it is replaced in place when the user changes devices, which a
/// value owned by the session could not survive.
pub struct ActiveSession {
    pub client: Arc<Client>,
    pub event_pump: tokio::task::JoinHandle<()>,
}

impl ActiveSession {
    /// Tear the session down in dependency order.
    pub fn shutdown(self) {
        self.event_pump.abort();
        self.client.disconnect();
    }
}

/// The audio engine, swappable while a session is live.
///
/// Changing a device means building a new [`AudioEngine`], because
/// [`AudioEngine::start`] opens its devices once and offers no way to change
/// them afterwards. Holding it behind a lock lets the event pump reach whichever
/// engine is current without being torn down and respawned alongside it.
///
/// The read guard is taken once per inbound voice packet. That is 50 a second
/// per speaker, uncontended except for the moment a device actually changes.
#[derive(Clone, Default)]
pub struct EngineSlot {
    inner: Arc<RwLock<Option<Arc<AudioEngine>>>>,
}

impl EngineSlot {
    /// The engine currently running, if any.
    pub fn current(&self) -> Option<Arc<AudioEngine>> {
        self.inner.read().clone()
    }

    /// Install an engine, returning whichever it displaced.
    ///
    /// The caller decides when to drop the old one. That matters: dropping it
    /// stops its streams and closes its frame channel, which is what retires the
    /// capture pump feeding from it.
    fn replace(&self, engine: Option<Arc<AudioEngine>>) -> Option<Arc<AudioEngine>> {
        std::mem::replace(&mut self.inner.write(), engine)
    }
}

/// What the UI needs to render the mute and deafen buttons.
///
/// Pushed to the frontend on every change rather than tracked optimistically
/// there, because a global shortcut can change it while the window is not even
/// focused and an optimistic copy would go stale.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct VoiceState {
    pub muted: bool,
    pub deafened: bool,
}

pub struct AppState {
    /// Every identity the user has, one of them active.
    ///
    /// Behind a lock rather than cloned: `Identity` holds secret key material
    /// and is deliberately not `Clone`. Long operations copy the key out instead
    /// of holding this — see `mine_identity`.
    pub vault: Mutex<Vault>,
    pub trust_path: PathBuf,
    pub bookmarks_path: PathBuf,
    pub settings_path: PathBuf,
    pub settings: Mutex<Settings>,
    pub engine: EngineSlot,
    pub session: Mutex<Option<ActiveSession>>,
}

impl AppState {
    /// Open the vault, migrating a single-identity keystore or generating a
    /// first identity as needed.
    pub fn load() -> Result<Self, String> {
        let dir = data_dir();
        let settings_path = dir.join(SETTINGS_FILE);

        let vault = Vault::open(
            &dir.join(VAULT_FILE),
            &dir.join(IDENTITY_FILE),
            &default_nickname(),
        )
        .map_err(|e| e.to_string())?;

        Ok(Self {
            vault: Mutex::new(vault),
            trust_path: dir.join(TRUST_FILE),
            bookmarks_path: dir.join(BOOKMARKS_FILE),
            settings: Mutex::new(Settings::load(&settings_path)),
            settings_path,
            engine: EngineSlot::default(),
            session: Mutex::new(None),
        })
    }

    pub fn trust_store(&self) -> Result<TrustStore, String> {
        TrustStore::open(&self.trust_path).map_err(|e| e.to_string())
    }

    pub fn bookmarks(&self) -> Result<Bookmarks, String> {
        Bookmarks::open(&self.bookmarks_path).map_err(|e| e.to_string())
    }

    pub fn persist_vault(&self) -> Result<(), String> {
        self.vault.lock().save().map_err(|e| e.to_string())
    }

    /// A copy of the active identity, for signing a login.
    ///
    /// Copied rather than borrowed because the guard is `!Send` and could not be
    /// held across the await in `connect`, and because holding the vault lock
    /// for the length of a network handshake would block the settings dialog.
    pub fn active_identity(&self) -> Identity {
        let vault = self.vault.lock();
        let active = vault.active();
        Identity::from_secret_bytes(&active.identity.secret_bytes(), active.identity.counter())
    }

    pub fn active_nickname(&self) -> String {
        self.vault.lock().active().nickname.clone()
    }

    pub fn persist_settings(&self) -> Result<(), String> {
        let settings = self.settings.lock().clone();
        settings
            .save(&self.settings_path)
            .map_err(|e| e.to_string())
    }

    /// Start the audio engine from current settings, replacing any running one.
    ///
    /// With a client, captured frames go to the server. Without one, they are
    /// discarded and only the level meter is useful — which is what the settings
    /// dialog needs to let someone pick a microphone before connecting.
    ///
    /// Mute and deafen carry across a replacement, so changing a device
    /// mid-call cannot silently reopen a muted microphone.
    pub fn start_audio(&self, client: Option<Arc<Client>>) -> Result<Arc<AudioEngine>, String> {
        let audio = self.settings.lock().audio.clone();

        let carried = self
            .engine
            .current()
            .map(|old| (old.is_muted(), old.is_deafened()));

        let engine = AudioEngine::start(EngineConfig {
            input_device: audio.input_device.clone(),
            output_device: audio.output_device.clone(),
            bitrate: audio.bitrate,
            gate_mode: audio.gate_mode.into(),
        })
        .map_err(|e| format!("The audio devices could not be opened: {e}"))?;

        if let Some((muted, deafened)) = carried {
            engine.set_muted(muted);
            engine.set_deafened(deafened);
        }

        let frames = engine
            .take_frames()
            .expect("a freshly started engine still owns its frame stream");

        let engine = Arc::new(engine);
        let previous = self.engine.replace(Some(Arc::clone(&engine)));

        bridge::spawn_capture_pump(client, frames);

        // Only now, so the new engine is already in place and no inbound packet
        // can land on an engine that is being torn down.
        drop(previous);

        Ok(engine)
    }

    /// Set mute, returning the resulting voice state.
    ///
    /// These live here rather than in a command because a global shortcut has to
    /// perform exactly the same action as the button, and two copies of "mute
    /// also implies telling the server" would eventually disagree.
    pub fn set_muted(&self, muted: bool) -> Result<VoiceState, String> {
        let engine = self.running_engine()?;
        engine.set_muted(muted);
        Ok(self.announce_voice_state(&engine))
    }

    pub fn set_deafened(&self, deafened: bool) -> Result<VoiceState, String> {
        let engine = self.running_engine()?;
        engine.set_deafened(deafened);
        // Deafening implies muting, matching what the server enforces.
        if deafened {
            engine.set_muted(true);
        }
        Ok(self.announce_voice_state(&engine))
    }

    pub fn toggle_muted(&self) -> Result<VoiceState, String> {
        let muted = self.running_engine()?.is_muted();
        self.set_muted(!muted)
    }

    pub fn toggle_deafened(&self) -> Result<VoiceState, String> {
        let deafened = self.running_engine()?.is_deafened();
        self.set_deafened(!deafened)
    }

    /// Quiet when no engine is running: a global key gets pressed while
    /// disconnected, and that is not a failure worth reporting.
    pub fn set_push_to_talk_held(&self, held: bool) {
        if let Some(engine) = self.engine.current() {
            engine.set_push_to_talk_held(held);
        }
    }

    pub fn voice_state(&self) -> VoiceState {
        match self.engine.current() {
            Some(engine) => VoiceState {
                muted: engine.is_muted(),
                deafened: engine.is_deafened(),
            },
            None => VoiceState::default(),
        }
    }

    fn running_engine(&self) -> Result<Arc<AudioEngine>, String> {
        self.engine
            .current()
            .ok_or_else(|| "Audio is not running.".to_string())
    }

    /// Tell the server what our voice state is, if we are connected to one.
    ///
    /// Best effort by design — the same controls work while disconnected,
    /// driving only the local engine.
    fn announce_voice_state(&self, engine: &AudioEngine) -> VoiceState {
        let state = VoiceState {
            muted: engine.is_muted(),
            deafened: engine.is_deafened(),
        };
        if let Some(session) = self.session.lock().as_ref() {
            session.client.set_voice_state(state.muted, state.deafened);
        }
        state
    }

    /// Stop the audio engine, releasing the devices.
    pub fn stop_audio(&self) {
        if self.engine.replace(None).is_some() {
            debug!("audio engine stopped");
        }
    }

    /// Close any live session. Safe to call when already disconnected.
    pub fn end_session(&self) {
        if let Some(session) = self.session.lock().take() {
            session.shutdown();
        }
        self.stop_audio();
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
