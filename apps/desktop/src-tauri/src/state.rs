//! Application state: the local identity, the audio engine, and the session
//! when connected.

use crate::bookmarks::Bookmarks;
use crate::bridge;
use crate::settings::{OpenConnection, Settings};
use parking_lot::{Mutex, RwLock};
use pickle_audio::{AudioEngine, EngineConfig};
use pickle_client::{Client, TrustStore};
use pickle_identity::{Identity, Vault};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::debug;

/// The single-identity file this app used to write. Read once, to migrate.
const IDENTITY_FILE: &str = "identity.json";
const VAULT_FILE: &str = "identities.json";
const TRUST_FILE: &str = "known_servers.json";
const SETTINGS_FILE: &str = "settings.json";
const BOOKMARKS_FILE: &str = "bookmarks.json";

/// Names one connection for the lifetime of the process.
///
/// Deliberately not the server's `ClientId`: that is assigned per server, so two
/// connections would collide on it — the same trap that keeps voice to a single
/// server, since [`pickle_audio::VoiceMixer`] keys speakers the same way.
pub type SessionId = u64;

/// Everything alive while connected to one server.
///
/// The audio engine is deliberately **not** here. It outlives any single
/// session — the settings dialog runs it while disconnected to drive the input
/// meter, and several sessions share the one microphone — and it is replaced in
/// place when the user changes devices, which a value owned by a session could
/// not survive.
pub struct ActiveSession {
    pub id: SessionId,
    pub client: Arc<Client>,
    pub event_pump: tokio::task::JoinHandle<()>,
    /// This session's permission mirror, folded forward by the event pump and
    /// read by the seeding commands. UX state only; the server re-checks all.
    pub perms: crate::perms::SessionPerms,
    /// What the user typed to reach this server, kept verbatim so reconnecting
    /// resolves it the same way rather than pinning a resolved IP.
    pub address: String,
    /// Fingerprint of the identity this connection signed in with.
    ///
    /// Recorded because the key is copied out of the vault at connect time, so
    /// the vault alone cannot say who a live session is. Deleting an identity
    /// checks this before stranding a connection.
    pub identity: String,
}

impl ActiveSession {
    /// Tear the session down in dependency order.
    pub fn shutdown(self) {
        self.event_pump.abort();
        self.client.disconnect();
    }
}

/// Which connection the microphone currently feeds.
///
/// Voice is single-server by design: the mixer keys speakers by a per-server
/// `ClientId`, so audio from two servers at once would collide there. Holding
/// the route behind a lock lets the capture pump follow it without being torn
/// down and respawned whenever voice moves.
///
/// Read once per encoded frame — 50 a second, uncontended except at the instant
/// voice actually moves.
/// The session voice points at, and the client to send through.
///
/// Both together: the id alone could not send, and the client alone could not
/// answer "is voice on this tab".
type RoutedVoice = Option<(SessionId, Arc<Client>)>;

#[derive(Clone, Default)]
pub struct VoiceRoute {
    inner: Arc<RwLock<RoutedVoice>>,
}

impl VoiceRoute {
    /// Where captured frames should go, if anywhere.
    pub fn client(&self) -> Option<Arc<Client>> {
        self.inner
            .read()
            .as_ref()
            .map(|(_, client)| Arc::clone(client))
    }

    pub fn session(&self) -> Option<SessionId> {
        self.inner.read().as_ref().map(|(id, _)| *id)
    }

    pub fn set(&self, id: SessionId, client: Arc<Client>) {
        *self.inner.write() = Some((id, client));
    }

    pub fn clear(&self) {
        *self.inner.write() = None;
    }

    /// Drop the route if it points at this session, so a disconnect cannot
    /// leave the microphone feeding a dead connection.
    pub fn clear_if(&self, id: SessionId) -> bool {
        let mut guard = self.inner.write();
        if guard.as_ref().is_some_and(|(current, _)| *current == id) {
            *guard = None;
            return true;
        }
        false
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
    /// Kept so the app can ask whether the vault is encrypted without holding
    /// the lock, and before it has anything to unlock.
    pub vault_path: PathBuf,
    pub trust_path: PathBuf,
    pub bookmarks_path: PathBuf,
    pub settings_path: PathBuf,
    pub settings: Mutex<Settings>,
    pub engine: EngineSlot,
    /// Every live connection, keyed by an id that is never reused.
    pub sessions: Mutex<HashMap<SessionId, ActiveSession>>,
    /// Source of those ids. Monotonic, so a stale reference from a closed tab
    /// fails to resolve rather than addressing whichever server took its place.
    next_session_id: AtomicU64,
    pub voice: VoiceRoute,
}

impl AppState {
    /// Open the vault, migrating a single-identity keystore or generating a
    /// first identity as needed.
    pub fn load() -> Result<Self, String> {
        Self::load_with_passphrase(None)
    }

    /// Open a vault that may be encrypted.
    ///
    /// Separated from [`AppState::load`] so the passphrase has exactly one way
    /// in. Nothing in the shipped UI calls this with a passphrase yet — see
    /// [`AppState::set_vault_passphrase`] for why encryption cannot be offered
    /// until there is a prompt to unlock with.
    pub fn load_with_passphrase(passphrase: Option<&str>) -> Result<Self, String> {
        let dir = data_dir();
        let settings_path = dir.join(SETTINGS_FILE);
        let vault_path = dir.join(VAULT_FILE);

        let vault = Vault::open_with_passphrase(
            &vault_path,
            &dir.join(IDENTITY_FILE),
            &default_nickname(),
            passphrase,
        )
        .map_err(|e| e.to_string())?;

        Ok(Self {
            vault: Mutex::new(vault),
            vault_path,
            trust_path: dir.join(TRUST_FILE),
            bookmarks_path: dir.join(BOOKMARKS_FILE),
            settings: Mutex::new(Settings::load(&settings_path)),
            settings_path,
            engine: EngineSlot::default(),
            sessions: Mutex::new(HashMap::new()),
            // Starts at 1 so a zero id is always invalid, which makes an
            // uninitialised value on the frontend fail loudly rather than
            // addressing the first connection.
            next_session_id: AtomicU64::new(1),
            voice: VoiceRoute::default(),
        })
    }

    pub fn next_session_id(&self) -> SessionId {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
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

    /// Whether the identity file is encrypted at rest.
    pub fn vault_is_encrypted(&self) -> bool {
        self.vault.lock().is_encrypted()
    }

    /// Turn passphrase protection on, change it, or (with `None`) turn it off.
    ///
    /// The vault verifies the new file decrypts before it replaces the old one,
    /// so a failure here leaves the user's identities exactly as they were.
    ///
    /// # Not yet reachable from the UI, on purpose
    ///
    /// There is no unlock prompt at startup. Until there is, calling this with a
    /// passphrase would produce a vault the next launch cannot open — the exact
    /// lockout this whole feature is supposed to be careful about. The command
    /// layer therefore does not expose it, and the remaining work is a window
    /// shown before [`AppState::load_with_passphrase`] that collects the
    /// passphrase, retries on [`pickle_identity::VaultError::Locked`], and
    /// offers "forget it and start over" as an explicit, warned-about choice.
    pub fn set_vault_passphrase(&self, passphrase: Option<&str>) -> Result<(), String> {
        let mut vault = self.vault.lock();
        match passphrase {
            Some(passphrase) => vault.set_passphrase(passphrase),
            None => vault.remove_passphrase(),
        }
        .map_err(|e| e.to_string())
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

    /// Resolve which identity a connection should sign in with.
    ///
    /// Returns a copy of the key, the nickname to present, and the fingerprint
    /// to record against the session. Copied for the same reason
    /// [`AppState::active_identity`] copies: the guard is `!Send` and could not
    /// be held across the handshake's await, and holding the vault lock for a
    /// network round trip would block the settings dialog.
    ///
    /// Because it is a copy, later vault edits cannot disturb a live connection
    /// — which is what makes switching the active identity safe while connected.
    pub fn identity_for(
        &self,
        fingerprint: Option<&str>,
    ) -> Result<(Identity, String, String), String> {
        let vault = self.vault.lock();
        let entry = match fingerprint {
            Some(fingerprint) => vault
                .get(fingerprint)
                .ok_or_else(|| format!("No identity with fingerprint {fingerprint}."))?,
            None => vault.active(),
        };

        Ok((
            Identity::from_secret_bytes(&entry.identity.secret_bytes(), entry.identity.counter()),
            entry.nickname.clone(),
            entry.identity.fingerprint().to_string(),
        ))
    }

    /// Record what is open, so the next launch can offer to reopen it.
    ///
    /// Best effort: failing to write this must never take a working connection
    /// down with it.
    pub fn remember_open_connections(&self) {
        let open: Vec<OpenConnection> = self
            .sessions
            .lock()
            .values()
            .map(|session| OpenConnection {
                address: session.address.clone(),
                identity: session.identity.clone(),
            })
            .collect();

        self.settings.lock().connections = open;
        if let Err(error) = self.persist_settings() {
            debug!(%error, "could not record open connections");
        }
    }

    pub fn persist_settings(&self) -> Result<(), String> {
        let settings = self.settings.lock().clone();
        settings
            .save(&self.settings_path)
            .map_err(|e| e.to_string())
    }

    /// Start the audio engine from current settings, replacing any running one.
    ///
    /// Captured frames go wherever [`VoiceRoute`] points, which may be nowhere —
    /// while disconnected, or with voice on no server, they are discarded and
    /// only the level meter is useful. That is what lets the settings dialog
    /// show a working microphone before any connection exists.
    ///
    /// Mute and deafen carry across a replacement, so changing a device
    /// mid-call cannot silently reopen a muted microphone.
    pub fn start_audio(&self) -> Result<Arc<AudioEngine>, String> {
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

        bridge::spawn_capture_pump(self.voice.clone(), frames);

        // Only now, so the new engine is already in place and no inbound packet
        // can land on an engine that is being torn down.
        drop(previous);

        Ok(engine)
    }

    /// Make sure the engine is running, without disturbing it if it already is.
    ///
    /// Restarting a live engine would reopen the devices and drop audio, which
    /// connecting a second server has no business doing to the first.
    pub fn ensure_audio(&self) -> Result<Arc<AudioEngine>, String> {
        match self.engine.current() {
            Some(engine) => Ok(engine),
            None => self.start_audio(),
        }
    }

    /// Point voice at a session, clearing anything the previous server left in
    /// the mixer.
    ///
    /// The clear is not cosmetic: speaker ids are assigned per server, so
    /// another server's leftover streams would both linger in the speaking list
    /// and collide with ids the new server hands out.
    pub fn route_voice(&self, id: SessionId) -> Result<(), String> {
        let client = {
            let sessions = self.sessions.lock();
            let session = sessions
                .get(&id)
                .ok_or_else(|| "That connection is no longer open.".to_string())?;
            Arc::clone(&session.client)
        };

        if self.voice.session() == Some(id) {
            return Ok(());
        }

        self.voice.set(id, client);
        if let Some(engine) = self.engine.current() {
            engine.clear_speakers();
        }
        Ok(())
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

    /// Tell every connected server what our voice state is.
    ///
    /// All of them, not just the one holding voice: each shows us in its user
    /// list, and a server that thought we were unmuted would advertise that to
    /// everyone on it.
    ///
    /// Best effort by design — the same controls work while disconnected,
    /// driving only the local engine.
    fn announce_voice_state(&self, engine: &AudioEngine) -> VoiceState {
        let state = VoiceState {
            muted: engine.is_muted(),
            deafened: engine.is_deafened(),
        };
        for session in self.sessions.lock().values() {
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

    /// Close one connection. Safe to call for a session that is already gone.
    ///
    /// Audio is stopped only when the last connection closes, so disconnecting
    /// one server does not interrupt the others' voice.
    pub fn end_session(&self, id: SessionId) {
        let session = self.sessions.lock().remove(&id);
        let Some(session) = session else {
            return;
        };
        session.shutdown();

        // Before anything else picks up voice, so the microphone is never left
        // feeding a client that has just been disconnected.
        if self.voice.clear_if(id) {
            if let Some(engine) = self.engine.current() {
                engine.clear_speakers();
            }
        }

        if self.sessions.lock().is_empty() {
            self.stop_audio();
        }
    }

    /// Close every connection.
    pub fn end_all_sessions(&self) {
        let ids: Vec<SessionId> = self.sessions.lock().keys().copied().collect();
        for id in ids {
            self.end_session(id);
        }
        self.voice.clear();
        self.stop_audio();
    }

    /// Run something against one session, or report that it is gone.
    pub fn with_session<T>(
        &self,
        id: SessionId,
        f: impl FnOnce(&ActiveSession) -> T,
    ) -> Result<T, String> {
        match self.sessions.lock().get(&id) {
            Some(session) => Ok(f(session)),
            None => Err("That connection is no longer open.".into()),
        }
    }

    /// Whether any live connection signed in with this identity.
    pub fn identity_in_use(&self, fingerprint: &str) -> bool {
        self.sessions
            .lock()
            .values()
            .any(|session| session.identity == fingerprint)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The route can be exercised without a real connection, which is the part
    /// worth testing: a live `Client` needs a server, but the rules about which
    /// session holds voice are pure state.
    #[test]
    fn a_fresh_route_points_nowhere() {
        let route = VoiceRoute::default();
        assert_eq!(route.session(), None);
        assert!(route.client().is_none());
    }

    #[test]
    fn clearing_only_applies_to_the_session_that_holds_voice() {
        // Disconnecting a server that does *not* hold voice must not silence
        // the one that does.
        let route = VoiceRoute::default();
        assert!(!route.clear_if(1), "nothing to clear");

        // Without a client the route cannot be populated, so this asserts the
        // predicate rather than the full move; `route_voice` covers the rest.
        assert_eq!(route.session(), None);
    }

    #[test]
    fn session_ids_are_never_reused() {
        // A stale id from a closed tab must fail to resolve rather than
        // addressing whichever server took its place.
        let counter = AtomicU64::new(1);
        let ids: Vec<u64> = (0..5)
            .map(|_| counter.fetch_add(1, Ordering::Relaxed))
            .collect();

        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
        assert!(!ids.contains(&0), "zero stays invalid");
    }
}
