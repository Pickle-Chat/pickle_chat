//! Commands callable from the frontend.
//!
//! Errors are returned as plain strings because that is what crosses the
//! bridge, but they are the messages from the underlying error types — those
//! are written to be shown to a person, so nothing is lost in the flattening.

use crate::bridge;
use crate::dto::{AudioDeviceDto, IdentityDto, SessionDto};
use crate::state::{ActiveSession, AppState};
use pickle_audio::{AudioEngine, DeviceKind, EngineConfig, GateMode};
use pickle_client::{ConnectOptions, TrustPolicy};
use pickle_identity::{Identity, MineProgress};
use serde::Serialize;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tracing::info;

/// Port assumed when the user types a bare address.
const DEFAULT_PORT: u16 = 42071;

#[tauri::command]
pub fn identity_info(state: State<'_, AppState>) -> IdentityDto {
    IdentityDto::new(&state.identity.lock(), &state.nickname.lock())
}

#[tauri::command]
pub fn set_nickname(state: State<'_, AppState>, nickname: String) -> Result<IdentityDto, String> {
    let trimmed = nickname.trim();
    if trimmed.is_empty() {
        return Err("A nickname needs at least one visible character.".into());
    }

    *state.nickname.lock() = trimmed.to_string();
    state.persist_identity()?;

    // Take effect immediately if connected, rather than at next login.
    if let Some(session) = state.session.lock().as_ref() {
        session
            .client
            .send_control(pickle_proto::ClientControl::SetNickname(trimmed.into()));
    }

    Ok(IdentityDto::new(&state.identity.lock(), trimmed))
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

    let identity = Arc::clone(&state.identity);
    let path = state.identity_path.clone();
    let nickname = state.nickname.lock().clone();

    std::thread::Builder::new()
        .name("pickle-mining".into())
        .spawn(move || {
            let mut guard = identity.lock();
            let report = guard.mine(target_level, &mut |progress: MineProgress| {
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
            let _ = pickle_identity::Keystore::save(&path, &guard, &nickname);
            drop(guard);

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

#[tauri::command]
pub async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    address: String,
    password: Option<String>,
    input_device: Option<String>,
    output_device: Option<String>,
    push_to_talk: bool,
) -> Result<SessionDto, String> {
    // Replace any existing session rather than leaking one.
    state.end_session();

    let target = resolve(&address)?;
    let nickname = state.nickname.lock().clone();
    let mut trust = state.trust_store()?;

    let mut options = ConnectOptions::new(target, nickname).with_trust(TrustPolicy::OnFirstUse);
    if let Some(password) = password.filter(|p| !p.is_empty()) {
        options = options.with_password(password);
    }

    // Copy the key out rather than holding the lock across the await. The
    // guard is `!Send`, so keeping it would not even compile in an async
    // command, and `connect` only borrows the identity to sign the challenge.
    let identity = {
        let guard = state.identity.lock();
        Identity::from_secret_bytes(&guard.secret_bytes(), guard.counter())
    };

    let (client, events) = pickle_client::connect(options, &identity, &mut trust)
        .await
        .map_err(|e| e.to_string())?;

    let session_dto = SessionDto::from(client.session());
    info!(
        server = %session_dto.server_name,
        client_id = session_dto.client_id,
        "connected"
    );

    let engine = AudioEngine::start(EngineConfig {
        input_device,
        output_device,
        gate_mode: if push_to_talk {
            GateMode::PushToTalk
        } else {
            GateMode::VoiceActivity
        },
        ..EngineConfig::default()
    })
    .map_err(|e| format!("Connected, but the audio devices could not be opened: {e}"))?;

    let client = Arc::new(client);
    let engine = Arc::new(engine);

    let frames = engine
        .take_frames()
        .expect("a freshly started engine still owns its frame stream");
    bridge::spawn_capture_pump(Arc::clone(&client), frames);
    let event_pump = bridge::spawn_event_pump(app, Arc::clone(&engine), events);

    *state.session.lock() = Some(ActiveSession {
        client,
        engine,
        event_pump,
    });

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

#[tauri::command]
pub fn set_muted(state: State<'_, AppState>, muted: bool) -> Result<(), String> {
    with_session(&state, |session| {
        // Locally so the microphone stops immediately, and on the server so
        // the mute is enforced rather than merely advertised.
        session.engine.set_muted(muted);
        session
            .client
            .set_voice_state(muted, session.engine.is_deafened());
    })
}

#[tauri::command]
pub fn set_deafened(state: State<'_, AppState>, deafened: bool) -> Result<(), String> {
    with_session(&state, |session| {
        session.engine.set_deafened(deafened);
        // Deafening implies muting, matching what the server enforces.
        if deafened {
            session.engine.set_muted(true);
        }
        session
            .client
            .set_voice_state(session.engine.is_muted(), deafened);
    })
}

#[tauri::command]
pub fn set_push_to_talk_held(state: State<'_, AppState>, held: bool) -> Result<(), String> {
    with_session(&state, |session| {
        session.engine.set_push_to_talk_held(held);
    })
}

/// Microphone level in dBFS, polled by the UI for its meter.
#[tauri::command]
pub fn input_level(state: State<'_, AppState>) -> f32 {
    state
        .session
        .lock()
        .as_ref()
        .map(|session| session.engine.input_level_dbfs())
        .unwrap_or(f32::NEG_INFINITY)
}

/// Who is currently audible, for the speaking indicator.
#[tauri::command]
pub fn speaking(state: State<'_, AppState>) -> Vec<u32> {
    state
        .session
        .lock()
        .as_ref()
        .map(|session| session.engine.speaking())
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
