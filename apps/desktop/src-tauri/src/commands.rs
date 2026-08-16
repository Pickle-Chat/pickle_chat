//! Commands callable from the frontend.
//!
//! Errors are returned as plain strings because that is what crosses the
//! bridge, but they are the messages from the underlying error types — those
//! are written to be shown to a person, so nothing is lost in the flattening.

use crate::bookmarks::{Bookmark, BookmarkInput};
use crate::bridge;
use crate::dto::{AudioDeviceDto, IdentityDto, IdentityListDto, SessionDto, VaultEntryDto};
use crate::settings::{AudioSettings, Keybinds, Settings};
use crate::shortcuts;
use crate::state::{ActiveSession, AppState, VoiceState};
use pickle_audio::DeviceKind;
use pickle_client::{ConnectOptions, TrustPolicy};
use pickle_identity::{Identity, MineProgress};
use serde::Serialize;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};
use tracing::info;

/// Port assumed when the user types a bare address.
const DEFAULT_PORT: u16 = 42071;

#[tauri::command]
pub fn identity_info(state: State<'_, AppState>) -> IdentityDto {
    let vault = state.vault.lock();
    let active = vault.active();
    IdentityDto::new(&active.identity, &active.nickname)
}

/// Every identity in the vault, active one first-class rather than implied.
#[tauri::command]
pub fn identities(state: State<'_, AppState>) -> IdentityListDto {
    let vault = state.vault.lock();
    IdentityListDto {
        active: vault.active_fingerprint().to_string(),
        identities: vault.list().iter().map(VaultEntryDto::new).collect(),
    }
}

#[tauri::command]
pub fn set_nickname(state: State<'_, AppState>, nickname: String) -> Result<IdentityDto, String> {
    let trimmed = nickname.trim();
    if trimmed.is_empty() {
        return Err("A nickname needs at least one visible character.".into());
    }

    {
        let mut vault = state.vault.lock();
        let active = vault.active_fingerprint().to_string();
        vault
            .set_nickname(&active, trimmed)
            .map_err(|e| e.to_string())?;
    }
    state.persist_vault()?;

    // Take effect immediately if connected, rather than at next login.
    if let Some(session) = state.session.lock().as_ref() {
        session
            .client
            .send_control(pickle_proto::ClientControl::SetNickname(trimmed.into()));
    }

    Ok(identity_info(state))
}

/// Create a fresh identity and switch to it.
#[tauri::command]
pub fn add_identity(
    state: State<'_, AppState>,
    nickname: String,
    label: String,
) -> Result<IdentityListDto, String> {
    let nickname = nickname.trim();
    if nickname.is_empty() {
        return Err("A nickname needs at least one visible character.".into());
    }

    {
        let mut vault = state.vault.lock();
        let fingerprint = vault.add(Identity::generate(), nickname, label.trim());
        // Switching immediately is the point of creating one; a new identity
        // left unselected would look like nothing happened. Safe here because
        // an identity cannot be created and connected in the same instant.
        if state.session.lock().is_none() {
            vault.set_active(&fingerprint).map_err(|e| e.to_string())?;
        }
    }
    state.persist_vault()?;
    Ok(identities(state))
}

/// Switch the active identity.
///
/// Refused while connected: the active identity is what signed the login, and
/// the server knows this client by that key. Changing it underneath a live
/// session would leave the two disagreeing about who is talking.
#[tauri::command]
pub fn set_active_identity(
    state: State<'_, AppState>,
    fingerprint: String,
) -> Result<IdentityListDto, String> {
    if state.session.lock().is_some() {
        return Err("Disconnect before switching identity — the server knows you by the key you signed in with.".into());
    }

    state
        .vault
        .lock()
        .set_active(&fingerprint)
        .map_err(|e| e.to_string())?;
    state.persist_vault()?;
    Ok(identities(state))
}

#[tauri::command]
pub fn set_identity_label(
    state: State<'_, AppState>,
    fingerprint: String,
    label: String,
) -> Result<IdentityListDto, String> {
    state
        .vault
        .lock()
        .set_label(&fingerprint, label.trim())
        .map_err(|e| e.to_string())?;
    state.persist_vault()?;
    Ok(identities(state))
}

/// Delete an identity and its key.
///
/// Irreversible, and it costs every permission every server granted that key.
/// The frontend confirms before calling this; the vault refuses to remove the
/// last one regardless.
#[tauri::command]
pub fn remove_identity(
    state: State<'_, AppState>,
    fingerprint: String,
) -> Result<IdentityListDto, String> {
    if state.session.lock().is_some() {
        return Err("Disconnect before removing an identity.".into());
    }

    state
        .vault
        .lock()
        .remove(&fingerprint)
        .map_err(|e| e.to_string())?;
    state.persist_vault()?;
    Ok(identities(state))
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MiningProgress {
    pub best_level: u32,
    pub hashes: u64,
    pub done: bool,
}

/// Raise the identity's proof-of-work level.
///
/// Runs on its own thread — at higher targets this is minutes of solid CPU, and
/// it must not block the UI or the audio path. Progress is emitted on
/// `pickle:mining`, and the result is saved so the work is not lost.
///
/// Mining works on a *copy* of the key rather than under the vault's lock. The
/// search only improves the counter and never touches the keypair, so writing
/// the counter back at the end is equivalent — and it keeps the settings dialog
/// responsive for the minutes this takes.
#[tauri::command]
pub fn mine_identity(
    app: AppHandle,
    state: State<'_, AppState>,
    target_level: u32,
) -> Result<(), String> {
    if target_level > 40 {
        return Err(
            "Levels above 40 take longer than any reasonable session. Try 24 to 32.".into(),
        );
    }

    let mut identity = state.active_identity();
    let fingerprint = identity.fingerprint().to_string();

    std::thread::Builder::new()
        .name("pickle-mining".into())
        .spawn(move || {
            let report = identity.mine(target_level, &mut |progress: MineProgress| {
                let _ = app.emit(
                    "pickle:mining",
                    MiningProgress {
                        best_level: progress.best_level,
                        hashes: progress.hashes,
                        done: false,
                    },
                );
                true
            });

            // Persist before announcing, so a crash right after cannot lose it.
            // The identity may have been switched or removed while this ran, so
            // a missing target is an ordinary outcome rather than an error.
            {
                let state = app.state::<AppState>();
                let mut vault = state.vault.lock();
                if vault.set_counter(&fingerprint, identity.counter()).is_ok() {
                    drop(vault);
                    let _ = state.persist_vault();
                }
            }

            let _ = app.emit(
                "pickle:mining",
                MiningProgress {
                    best_level: report.level,
                    hashes: report.hashes,
                    done: true,
                },
            );
        })
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioDevices {
    pub inputs: Vec<AudioDeviceDto>,
    pub outputs: Vec<AudioDeviceDto>,
}

#[tauri::command]
pub fn audio_devices() -> Result<AudioDevices, String> {
    Ok(AudioDevices {
        inputs: pickle_audio::devices::list(DeviceKind::Input)
            .map_err(|e| e.to_string())?
            .iter()
            .map(AudioDeviceDto::from)
            .collect(),
        outputs: pickle_audio::devices::list(DeviceKind::Output)
            .map_err(|e| e.to_string())?
            .iter()
            .map(AudioDeviceDto::from)
            .collect(),
    })
}

/// Connect, using the stored audio settings.
///
/// Devices and gate mode are no longer arguments: they belong to the settings
/// menu, which can change them while connected, and taking them here as well
/// would leave two sources of truth that disagree the moment either is used.
#[tauri::command]
pub async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    address: String,
    password: Option<String>,
) -> Result<SessionDto, String> {
    // Replace any existing session rather than leaking one.
    state.end_session();

    let target = resolve(&address)?;
    let nickname = state.active_nickname();
    let mut trust = state.trust_store()?;

    let mut options = ConnectOptions::new(target, nickname).with_trust(TrustPolicy::OnFirstUse);
    if let Some(password) = password.filter(|p| !p.is_empty()) {
        options = options.with_password(password);
    }

    // Copies the key out rather than holding the lock across the await. The
    // guard is `!Send`, so keeping it would not even compile in an async
    // command, and `connect` only borrows the identity to sign the challenge.
    let identity = state.active_identity();

    let (client, events) = pickle_client::connect(options, &identity, &mut trust)
        .await
        .map_err(|e| e.to_string())?;

    let session_dto = SessionDto::from(client.session());
    info!(
        server = %session_dto.server_name,
        client_id = session_dto.client_id,
        "connected"
    );

    let client = Arc::new(client);

    // Starts from stored settings, replacing any engine the settings dialog left
    // running for its meter, and rewires the capture pump to this client.
    state
        .start_audio(Some(Arc::clone(&client)))
        .map_err(|e| format!("Connected, but {}", e.trim_start_matches("The ")))?;

    let event_pump = bridge::spawn_event_pump(app, state.engine.clone(), events);

    *state.session.lock() = Some(ActiveSession { client, event_pump });

    Ok(session_dto)
}

#[tauri::command]
pub fn disconnect(state: State<'_, AppState>) {
    state.end_session();
}

#[tauri::command]
pub fn join_channel(state: State<'_, AppState>, channel: u32) -> Result<(), String> {
    with_session(&state, |session| {
        session.client.join_channel(channel);
    })
}

#[tauri::command]
pub fn send_message(
    state: State<'_, AppState>,
    channel: u32,
    content: String,
) -> Result<(), String> {
    if content.trim().is_empty() {
        return Ok(());
    }
    with_session(&state, |session| {
        // The nonce lets the UI match the server's echo to its optimistic
        // local render.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        session.client.send_message(channel, content, nonce);
    })
}

/// The mute and deafen commands echo their result back on the voice-state
/// channel as well as returning it, so a change made here and one made by a
/// global shortcut reach the UI by exactly the same route.
#[tauri::command]
pub fn set_muted(
    app: AppHandle,
    state: State<'_, AppState>,
    muted: bool,
) -> Result<VoiceState, String> {
    let voice = state.set_muted(muted)?;
    shortcuts::emit_voice_state(&app, voice);
    Ok(voice)
}

#[tauri::command]
pub fn set_deafened(
    app: AppHandle,
    state: State<'_, AppState>,
    deafened: bool,
) -> Result<VoiceState, String> {
    let voice = state.set_deafened(deafened)?;
    shortcuts::emit_voice_state(&app, voice);
    Ok(voice)
}

#[tauri::command]
pub fn voice_state(state: State<'_, AppState>) -> VoiceState {
    state.voice_state()
}

/// Used by the frontend's focus-scoped fallback, for platforms where the global
/// grab is refused.
#[tauri::command]
pub fn set_push_to_talk_held(state: State<'_, AppState>, held: bool) {
    state.set_push_to_talk_held(held);
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputActivity {
    /// Microphone level in dBFS.
    pub level_dbfs: f32,
    /// Whether audio is actually going out.
    pub transmitting: bool,
}

/// What the microphone is doing, polled by the UI for its meter and transmit
/// indicator.
///
/// The two travel together because they are polled at the same rate and asking
/// separately would double the bridge traffic for one widget. Reads the engine
/// rather than the session, so the settings dialog has a live meter while
/// disconnected.
#[tauri::command]
pub fn input_activity(state: State<'_, AppState>) -> InputActivity {
    match state.engine.current() {
        Some(engine) => InputActivity {
            level_dbfs: engine.input_level_dbfs(),
            transmitting: engine.is_transmitting(),
        },
        None => InputActivity {
            level_dbfs: f32::NEG_INFINITY,
            transmitting: false,
        },
    }
}

/// Who is currently audible, for the speaking indicator.
#[tauri::command]
pub fn speaking(state: State<'_, AppState>) -> Vec<u32> {
    state
        .engine
        .current()
        .map(|engine| engine.speaking())
        .unwrap_or_default()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownServer {
    pub address: String,
    pub name: String,
    pub fingerprint: String,
}

#[tauri::command]
pub fn known_servers(state: State<'_, AppState>) -> Result<Vec<KnownServer>, String> {
    let store = state.trust_store()?;
    Ok(store
        .iter()
        .map(|(address, server)| KnownServer {
            address: address.clone(),
            name: server.name.clone(),
            fingerprint: server.fingerprint.short(),
        })
        .collect())
}

#[tauri::command]
pub fn bookmarks(state: State<'_, AppState>) -> Result<Vec<Bookmark>, String> {
    Ok(state.bookmarks()?.list().to_vec())
}

#[tauri::command]
pub fn add_bookmark(
    state: State<'_, AppState>,
    bookmark: BookmarkInput,
) -> Result<Vec<Bookmark>, String> {
    let mut store = state.bookmarks()?;
    store.add(bookmark);
    store.save().map_err(|e| e.to_string())?;
    Ok(store.list().to_vec())
}

#[tauri::command]
pub fn update_bookmark(
    state: State<'_, AppState>,
    id: u64,
    bookmark: BookmarkInput,
) -> Result<Vec<Bookmark>, String> {
    let mut store = state.bookmarks()?;
    store.update(id, bookmark).map_err(|e| e.to_string())?;
    store.save().map_err(|e| e.to_string())?;
    Ok(store.list().to_vec())
}

/// Remove a bookmark.
///
/// This touches no trust state. The server stays pinned, because forgetting who
/// a server proved itself to be is a separate and far more consequential act —
/// see `forget_server`.
#[tauri::command]
pub fn remove_bookmark(state: State<'_, AppState>, id: u64) -> Result<Vec<Bookmark>, String> {
    let mut store = state.bookmarks()?;
    store.remove(id);
    store.save().map_err(|e| e.to_string())?;
    Ok(store.list().to_vec())
}

/// Drop a pinned identity, so the next connection is treated as first contact.
///
/// The escape hatch for an operator who legitimately lost their key: the client
/// refuses a changed identity outright, and this is the deliberate act that
/// clears it.
#[tauri::command]
pub fn forget_server(state: State<'_, AppState>, address: String) -> Result<(), String> {
    let mut store = state.trust_store()?;
    store.forget(&address);
    store.save().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn settings(state: State<'_, AppState>) -> Settings {
    state.settings.lock().clone()
}

/// Apply and persist audio settings, taking effect immediately.
///
/// A device or bitrate change rebuilds the engine, which costs a short gap in
/// audio; a gate mode change is applied to the running engine in place. If no
/// engine is running the settings are simply stored for the next start.
#[tauri::command]
pub fn set_audio_settings(state: State<'_, AppState>, audio: AudioSettings) -> Result<(), String> {
    // Scoped so the settings lock is released before `start_audio` takes it.
    let needs_restart = {
        let mut settings = state.settings.lock();
        let needs_restart = settings.audio.needs_restart(&audio);
        settings.audio = audio.clone();
        needs_restart
    };

    state.persist_settings()?;

    let Some(engine) = state.engine.current() else {
        return Ok(());
    };

    if needs_restart {
        let client = state
            .session
            .lock()
            .as_ref()
            .map(|session| Arc::clone(&session.client));
        state.start_audio(client)?;
    } else {
        engine.set_gate_mode(audio.gate_mode.into());
    }

    Ok(())
}

/// Store keybinds and re-grab them, reporting per-binding what the system
/// actually allowed.
///
/// The return value is the honest answer rather than a bare success: on a
/// platform that refuses global grabs, the settings tab needs to be able to say
/// so instead of showing a key that will never fire.
#[tauri::command]
pub fn set_keybinds(
    app: AppHandle,
    state: State<'_, AppState>,
    keybinds: Keybinds,
) -> Result<Vec<shortcuts::BindingStatus>, String> {
    state.settings.lock().keybinds = keybinds;
    state.persist_settings()?;
    Ok(shortcuts::apply(&app))
}

/// What the current bindings resolved to, for showing status without rebinding.
#[tauri::command]
pub fn keybind_status(app: AppHandle) -> Vec<shortcuts::BindingStatus> {
    shortcuts::apply(&app)
}

/// Run the audio engine while disconnected, so the settings dialog can show a
/// live input meter and let someone actually hear whether a device works.
#[tauri::command]
pub fn start_audio_preview(state: State<'_, AppState>) -> Result<(), String> {
    // Connected already means an engine is running and wired to the server;
    // replacing it with a preview would silently cut the user's microphone.
    if state.session.lock().is_some() {
        return Ok(());
    }
    state.start_audio(None).map(|_| ())
}

#[tauri::command]
pub fn stop_audio_preview(state: State<'_, AppState>) {
    if state.session.lock().is_none() {
        state.stop_audio();
    }
}

fn with_session(state: &State<'_, AppState>, f: impl FnOnce(&ActiveSession)) -> Result<(), String> {
    match state.session.lock().as_ref() {
        Some(session) => {
            f(session);
            Ok(())
        }
        None => Err("Not connected to a server.".into()),
    }
}

/// Turn what the user typed into an address, supplying the default port.
///
/// Accepts a hostname, an IPv4 address, or a bracketed IPv6 address, with or
/// without a port.
fn resolve(input: &str) -> Result<SocketAddr, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Enter a server address.".into());
    }

    let with_port = if has_port(trimmed) {
        trimmed.to_string()
    } else {
        format!("{trimmed}:{DEFAULT_PORT}")
    };

    with_port
        .to_socket_addrs()
        .map_err(|e| format!("Could not look up {trimmed}: {e}"))?
        .next()
        .ok_or_else(|| format!("{trimmed} did not resolve to any address."))
}

/// Whether the address already carries a port.
///
/// A bare IPv6 address is full of colons, so the last colon only counts when it
/// comes after the closing bracket.
fn has_port(address: &str) -> bool {
    match address.rfind(']') {
        Some(bracket) => address[bracket..].contains(':'),
        None => address.matches(':').count() == 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_ipv4_address_gets_the_default_port() {
        assert_eq!(resolve("127.0.0.1").unwrap().port(), DEFAULT_PORT);
    }

    #[test]
    fn an_explicit_port_is_respected() {
        assert_eq!(resolve("127.0.0.1:9000").unwrap().port(), 9000);
    }

    #[test]
    fn a_bracketed_ipv6_address_is_understood() {
        // The case a naive "does it contain a colon" check gets wrong.
        assert_eq!(resolve("[::1]").unwrap().port(), DEFAULT_PORT);
        assert_eq!(resolve("[::1]:9000").unwrap().port(), 9000);
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        // Addresses arrive pasted from chat more often than typed.
        assert_eq!(resolve("  127.0.0.1:9000  ").unwrap().port(), 9000);
    }

    #[test]
    fn an_empty_address_is_refused_with_a_readable_message() {
        assert!(resolve("   ")
            .unwrap_err()
            .contains("Enter a server address"));
    }

    #[test]
    fn port_detection_handles_both_address_families() {
        assert!(has_port("127.0.0.1:1"));
        assert!(!has_port("127.0.0.1"));
        assert!(has_port("[::1]:1"));
        assert!(!has_port("[::1]"));
        assert!(!has_port("::1"), "a bare IPv6 address carries no port");
        assert!(has_port("example.com:1"));
        assert!(!has_port("example.com"));
    }
}
