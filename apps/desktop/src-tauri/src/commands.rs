//! Commands callable from the frontend.
//!
//! Errors are returned as plain strings because that is what crosses the
//! bridge, but they are the messages from the underlying error types — those
//! are written to be shown to a person, so nothing is lost in the flattening.

use crate::bookmarks::{Bookmark, BookmarkInput};
use crate::bridge;
use crate::dto::{
    AudioDeviceDto, ConnectFailureDto, ConnectionDto, IdentityDto, IdentityListDto, SessionDto,
    SessionListDto, SpeakingDto, VaultEntryDto,
};
use crate::mouse_grab;
use crate::settings::{AudioSettings, Keybinds, Settings};
use crate::shortcuts;
use crate::state::{ActiveSession, AppState, SessionId, VoiceState};
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

    let active = {
        let mut vault = state.vault.lock();
        let active = vault.active_fingerprint().to_string();
        vault
            .set_nickname(&active, trimmed)
            .map_err(|e| e.to_string())?;
        active
    };
    state.persist_vault()?;

    // Take effect immediately, rather than at next login. Only on connections
    // that signed in with this identity: another one's nickname belongs to a
    // different key and is not ours to change here.
    for session in state.sessions.lock().values() {
        if session.identity == active {
            session
                .client
                .send_control(pickle_proto::ClientControl::SetNickname(trimmed.into()));
        }
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
        // left unselected would look like nothing happened.
        vault.set_active(&fingerprint).map_err(|e| e.to_string())?;
    }
    state.persist_vault()?;
    Ok(identities(state))
}

/// Switch which identity new connections default to.
///
/// No longer refused while connected. A connection signs in with a *copy* of
/// the key taken at connect time and records which identity that was, so
/// changing the default afterwards cannot disturb a live session — "active"
/// now means only "the one the next connection will use".
#[tauri::command]
pub fn set_active_identity(
    state: State<'_, AppState>,
    fingerprint: String,
) -> Result<IdentityListDto, String> {
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
///
/// Refused while a connection is signed in with it. Unlike switching the active
/// identity, this genuinely would strand a live session: the key it
/// authenticated with would no longer exist to reconnect from.
#[tauri::command]
pub fn remove_identity(
    state: State<'_, AppState>,
    fingerprint: String,
) -> Result<IdentityListDto, String> {
    if state.identity_in_use(&fingerprint) {
        return Err(
            "That identity is signed in to a server. Disconnect it before deleting the key.".into(),
        );
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

/// Open a connection, leaving any existing ones alone.
///
/// Devices and gate mode are not arguments: they belong to the settings menu,
/// which can change them while connected, and taking them here as well would
/// leave two sources of truth that disagree the moment either is used.
///
/// `identity` names which key to sign in with, defaulting to the vault's active
/// one. It is resolved to a copy before the handshake, so the vault can be
/// changed afterwards without disturbing a live connection.
#[tauri::command]
pub async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    address: String,
    password: Option<String>,
    identity: Option<String>,
) -> Result<ConnectionDto, ConnectFailureDto> {
    let target = resolve(&address)?;
    let (identity, nickname, fingerprint) = state.identity_for(identity.as_deref())?;
    let mut trust = state.trust_store()?;

    // Pin against what the user typed, not what it resolved to. Keying on the
    // resolved address would key on a value an attacker can influence: change
    // what the name resolves to and the new address is simply unknown, so
    // trust-on-first-use would pin the impostor silently. It also stops a
    // server with a dynamic IP from looking like a new server every time it
    // moves, which trains people to accept changed fingerprints.
    let mut options = ConnectOptions::new(target, nickname)
        .with_server_key(canonical_address(&address))
        .with_trust(TrustPolicy::OnFirstUse);
    if let Some(password) = password.filter(|p| !p.is_empty()) {
        options = options.with_password(password);
    }

    let (client, events) = pickle_client::connect(options, &identity, &mut trust)
        .await
        .map_err(|e| ConnectFailureDto::from(&e))?;

    let session_dto = SessionDto::from(client.session());
    let id = state.next_session_id();
    info!(
        session = id,
        server = %session_dto.server_name,
        client_id = session_dto.client_id,
        "connected"
    );

    let client = Arc::new(client);
    let perms: crate::perms::SessionPerms = Arc::new(parking_lot::Mutex::new(
        crate::perms::PermMirror::from_session(identity.fingerprint(), client.session()),
    ));

    // Leaves a running engine alone: connecting a second server has no business
    // reopening the devices and cutting the first one's audio.
    state
        .ensure_audio()
        .map_err(|e| format!("Connected, but {}", e.trim_start_matches("The ")))?;

    let event_pump = bridge::spawn_event_pump(
        app,
        id,
        state.engine.clone(),
        state.voice.clone(),
        perms.clone(),
        events,
    );

    state.sessions.lock().insert(
        id,
        ActiveSession {
            id,
            client,
            event_pump,
            perms: perms.clone(),
            address: address.clone(),
            identity: fingerprint,
        },
    );

    // The first connection takes voice, since there is nothing to take it from.
    // Later ones do not: looking at a new server should not cut you out of the
    // conversation you are already in.
    if state.voice.session().is_none() {
        state.route_voice(id)?;
    }

    state.remember_open_connections();

    let (my_permissions, roles) = {
        let mirror = perms.lock();
        (mirror.my_permissions(), mirror.roles_dto())
    };
    Ok(ConnectionDto {
        permissions: my_permissions,
        roles,
        session: id,
        info: session_dto,
        identity: state
            .sessions
            .lock()
            .get(&id)
            .map(|s| s.identity.clone())
            .unwrap_or_default(),
    })
}

#[tauri::command]
pub fn disconnect(state: State<'_, AppState>, session: SessionId) {
    state.end_session(session);
    state.remember_open_connections();
}

/// Every live connection, for rebuilding the tab strip.
#[tauri::command]
pub fn sessions(state: State<'_, AppState>) -> SessionListDto {
    let sessions = state.sessions.lock();
    SessionListDto {
        voice: state.voice.session(),
        sessions: sessions
            .values()
            .map(|session| {
                // One guard, bound: two .lock() calls in a single struct
                // literal keep the first guard's temporary alive into the
                // second, and a parking_lot mutex answers that not with a
                // panic but with a silent self-deadlock — which, taken while
                // the sessions map lock is also held, freezes every command
                // in the app behind it.
                let mirror = session.perms.lock();
                ConnectionDto {
                    permissions: mirror.my_permissions(),
                    roles: mirror.roles_dto(),
                    session: session.id,
                    info: SessionDto::from(session.client.session()),
                    identity: session.identity.clone(),
                }
            })
            .collect(),
    }
}

/// Move the microphone to another connection.
///
/// Not called on tab switch: reading one server should not cut you out of a
/// conversation on another. This is the explicit act.
#[tauri::command]
pub fn set_voice_session(state: State<'_, AppState>, session: SessionId) -> Result<(), String> {
    state.route_voice(session)
}

#[tauri::command]
pub fn join_channel(
    state: State<'_, AppState>,
    session: SessionId,
    channel: u32,
) -> Result<(), String> {
    state.with_session(session, |active| {
        active.client.join_channel(channel);
    })
}

/// Step out of the current channel into no channel at all. Being nowhere is a
/// real state: you are still connected, still listed, and no longer somewhere
/// you can be heard or receive a room's live messages.
#[tauri::command]
pub fn leave_channel(state: State<'_, AppState>, session: SessionId) -> Result<(), String> {
    state.with_session(session, |active| {
        active.client.leave_channel();
    })
}

/// Ask the server for a channel's recent past. The reply arrives as a
/// History event through the same pump as everything else.
#[tauri::command]
pub fn fetch_history(
    state: State<'_, AppState>,
    session: SessionId,
    channel: u32,
) -> Result<(), String> {
    state.with_session(session, |active| {
        // 100 is deliberately under the server's cap, leaving room to raise
        // it here without a protocol conversation.
        active.client.fetch_history(channel, None, 100);
    })
}

/// The mirror's current answer, for re-seeding without a server round trip.
#[tauri::command]
pub fn my_permissions(
    state: State<'_, AppState>,
    session: SessionId,
) -> Result<crate::perms::MyPermissionsDto, String> {
    state.with_session(session, |active| active.perms.lock().my_permissions())
}

// ---- moderation -----------------------------------------------------------
//
// Nonces are minted here from a counter; refusals come back as CommandFailed
// events carrying the same nonce. The mirror answers what to offer; the
// server remains the authority on what happens.

fn admin_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

#[tauri::command]
pub fn kick(
    state: State<'_, AppState>,
    session: SessionId,
    client_id: u32,
    reason: Option<String>,
) -> Result<(), String> {
    state.with_session(session, |active| {
        active
            .client
            .kick(admin_nonce(), client_id, reason.unwrap_or_default());
    })
}

#[tauri::command]
pub fn ban(
    state: State<'_, AppState>,
    session: SessionId,
    fingerprint: String,
    reason: String,
    until_unix_ms: Option<u64>,
) -> Result<(), String> {
    let fingerprint = pickle_identity::Fingerprint::parse(&fingerprint)
        .map_err(|e| format!("that fingerprint is not readable: {e}"))?;
    state.with_session(session, |active| {
        active
            .client
            .ban(admin_nonce(), fingerprint, reason, until_unix_ms);
    })
}

#[tauri::command]
pub fn unban(
    state: State<'_, AppState>,
    session: SessionId,
    fingerprint: String,
) -> Result<(), String> {
    let fingerprint = pickle_identity::Fingerprint::parse(&fingerprint)
        .map_err(|e| format!("that fingerprint is not readable: {e}"))?;
    state.with_session(session, |active| {
        active.client.unban(admin_nonce(), fingerprint);
    })
}

/// Answered by a banList event.
#[tauri::command]
pub fn list_bans(state: State<'_, AppState>, session: SessionId) -> Result<(), String> {
    state.with_session(session, |active| {
        active.client.list_bans(admin_nonce());
    })
}

#[tauri::command]
pub fn set_server_muted(
    state: State<'_, AppState>,
    session: SessionId,
    client_id: u32,
    muted: bool,
) -> Result<(), String> {
    state.with_session(session, |active| {
        active
            .client
            .set_server_mute(admin_nonce(), client_id, muted);
    })
}

#[tauri::command]
pub fn move_user(
    state: State<'_, AppState>,
    session: SessionId,
    client_id: u32,
    channel: Option<u32>,
) -> Result<(), String> {
    state.with_session(session, |active| {
        active.client.move_member(admin_nonce(), client_id, channel);
    })
}

// ---- role & overwrite management ------------------------------------------

#[tauri::command]
pub fn create_role(
    state: State<'_, AppState>,
    session: SessionId,
    name: String,
    permissions: Vec<String>,
) -> Result<(), String> {
    let bits = crate::perms::permissions_from_names(&permissions);
    state.with_session(session, |active| {
        active
            .client
            .send_control(pickle_proto::ClientControl::CreateRole {
                nonce: admin_nonce(),
                name,
                permissions: bits,
            });
    })
}

#[tauri::command]
pub fn update_role(
    state: State<'_, AppState>,
    session: SessionId,
    role_id: u32,
    name: Option<String>,
    color: Option<u32>,
    clear_color: Option<bool>,
    permissions: Option<Vec<String>>,
) -> Result<(), String> {
    let permissions = permissions.map(|names| crate::perms::permissions_from_names(&names));
    // JSON null and absent both deserialize to None, so "clear the color"
    // needs its own flag — the wire's Option<Option<_>> cannot be reached
    // through a single JSON field.
    let color = if clear_color.unwrap_or(false) {
        Some(None)
    } else {
        color.map(Some)
    };
    state.with_session(session, |active| {
        active
            .client
            .send_control(pickle_proto::ClientControl::UpdateRole {
                nonce: admin_nonce(),
                id: role_id,
                name,
                color,
                permissions,
            });
    })
}

#[tauri::command]
pub fn delete_role(
    state: State<'_, AppState>,
    session: SessionId,
    role_id: u32,
) -> Result<(), String> {
    state.with_session(session, |active| {
        active
            .client
            .send_control(pickle_proto::ClientControl::DeleteRole {
                nonce: admin_nonce(),
                id: role_id,
            });
    })
}

#[tauri::command]
pub fn reorder_roles(
    state: State<'_, AppState>,
    session: SessionId,
    positions: Vec<(u32, u32)>,
) -> Result<(), String> {
    state.with_session(session, |active| {
        active
            .client
            .send_control(pickle_proto::ClientControl::ReorderRoles {
                nonce: admin_nonce(),
                positions,
            });
    })
}

#[tauri::command]
pub fn set_member_roles(
    state: State<'_, AppState>,
    session: SessionId,
    fingerprint: String,
    roles: Vec<u32>,
) -> Result<(), String> {
    let fingerprint = pickle_identity::Fingerprint::parse(&fingerprint)
        .map_err(|e| format!("that fingerprint is not readable: {e}"))?;
    state.with_session(session, |active| {
        active
            .client
            .send_control(pickle_proto::ClientControl::SetMemberRoles {
                nonce: admin_nonce(),
                fingerprint,
                roles,
            });
    })
}

fn overwrite_target(
    target: crate::perms::OverwriteTargetDto,
) -> Result<pickle_proto::OverwriteTarget, String> {
    Ok(match target {
        crate::perms::OverwriteTargetDto::Role { id } => pickle_proto::OverwriteTarget::Role(id),
        crate::perms::OverwriteTargetDto::Member { fingerprint } => {
            pickle_proto::OverwriteTarget::Member(
                pickle_identity::Fingerprint::parse(&fingerprint)
                    .map_err(|e| format!("that fingerprint is not readable: {e}"))?,
            )
        }
    })
}

#[tauri::command]
pub fn set_channel_overwrite(
    state: State<'_, AppState>,
    session: SessionId,
    channel: u32,
    target: crate::perms::OverwriteTargetDto,
    allow: Vec<String>,
    deny: Vec<String>,
) -> Result<(), String> {
    let target = overwrite_target(target)?;
    let allow = crate::perms::permissions_from_names(&allow);
    let deny = crate::perms::permissions_from_names(&deny);
    state.with_session(session, |active| {
        active
            .client
            .send_control(pickle_proto::ClientControl::SetChannelOverwrite {
                nonce: admin_nonce(),
                channel,
                target,
                allow,
                deny,
            });
    })
}

#[tauri::command]
pub fn delete_channel_overwrite(
    state: State<'_, AppState>,
    session: SessionId,
    channel: u32,
    target: crate::perms::OverwriteTargetDto,
) -> Result<(), String> {
    let target = overwrite_target(target)?;
    state.with_session(session, |active| {
        active
            .client
            .send_control(pickle_proto::ClientControl::DeleteChannelOverwrite {
                nonce: admin_nonce(),
                channel,
                target,
            });
    })
}

fn parse_kind(kind: &str) -> Result<pickle_proto::ChannelKind, String> {
    Ok(match kind {
        "voice" => pickle_proto::ChannelKind::Voice,
        "text" => pickle_proto::ChannelKind::Text,
        "voice_and_text" => pickle_proto::ChannelKind::VoiceAndText,
        other => return Err(format!("unknown channel kind {other:?}")),
    })
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub fn create_channel(
    state: State<'_, AppState>,
    session: SessionId,
    name: String,
    kind: String,
    parent: Option<u32>,
    topic: Option<String>,
    max_users: Option<u16>,
    order: Option<i32>,
) -> Result<(), String> {
    let kind = parse_kind(&kind)?;
    state.with_session(session, |active| {
        active
            .client
            .send_control(pickle_proto::ClientControl::CreateChannel {
                nonce: admin_nonce(),
                name,
                parent,
                topic: topic.unwrap_or_default(),
                kind,
                max_users,
                order: order.unwrap_or(0),
            });
    })
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub fn update_channel(
    state: State<'_, AppState>,
    session: SessionId,
    channel: u32,
    name: String,
    kind: String,
    parent: Option<u32>,
    topic: String,
    max_users: Option<u16>,
    order: i32,
) -> Result<(), String> {
    let kind = parse_kind(&kind)?;
    state.with_session(session, |active| {
        active
            .client
            .send_control(pickle_proto::ClientControl::UpdateChannel {
                nonce: admin_nonce(),
                id: channel,
                parent,
                name,
                topic,
                kind,
                max_users,
                order,
            });
    })
}

#[tauri::command]
pub fn delete_channel(
    state: State<'_, AppState>,
    session: SessionId,
    channel: u32,
) -> Result<(), String> {
    state.with_session(session, |active| {
        active
            .client
            .send_control(pickle_proto::ClientControl::DeleteChannel {
                nonce: admin_nonce(),
                id: channel,
            });
    })
}

/// The role-by-permission grid for one channel, from the mirror.
#[tauri::command]
pub fn channel_matrix(
    state: State<'_, AppState>,
    session: SessionId,
    channel: u32,
) -> Result<Vec<crate::perms::MatrixRowDto>, String> {
    state.with_session(session, |active| {
        active.perms.lock().channel_matrix(channel)
    })
}

/// One channel's overwrites, from the mirror, for the tri-state editor.
#[tauri::command]
pub fn channel_overwrites(
    state: State<'_, AppState>,
    session: SessionId,
    channel: u32,
) -> Result<Vec<crate::perms::OverwriteDto>, String> {
    state.with_session(session, |active| {
        active.perms.lock().overwrites_dto(channel)
    })
}

/// The mirror's answer for one member — pulled when the menu opens, so it is
/// always fresh without a server round trip.
#[tauri::command]
pub fn moderation_options(
    state: State<'_, AppState>,
    session: SessionId,
    client_id: u32,
) -> Result<crate::perms::ModerationOptionsDto, String> {
    state.with_session(session, |active| {
        active.perms.lock().moderation_options(client_id)
    })
}

#[tauri::command]
pub fn send_message(
    state: State<'_, AppState>,
    session: SessionId,
    channel: u32,
    content: String,
) -> Result<(), String> {
    if content.trim().is_empty() {
        return Ok(());
    }
    state.with_session(session, |active| {
        // The nonce lets the UI match the server's echo to its optimistic
        // local render.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        active.client.send_message(channel, content, nonce);
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

/// Who is currently audible, for the speaking indicator — ourselves included.
///
/// The mixer only knows about voices arriving from the network, and the server
/// relays ours to everyone else rather than back to us, so we would never
/// appear in our own channel list. Folding our transmit state in here rather
/// than special-casing it in the UI keeps this meaning one thing: everyone the
/// channel can currently hear.
/// Scoped to the connection holding voice, and says which that is. Speaker ids
/// are assigned per server, so applying this list to another server's tab would
/// light up whoever happens to share a number with someone talking elsewhere.
#[tauri::command]
pub fn speaking(state: State<'_, AppState>) -> SpeakingDto {
    let Some(voice) = state.voice.session() else {
        return SpeakingDto::default();
    };
    let Some(engine) = state.engine.current() else {
        return SpeakingDto::default();
    };

    let mut speaking = engine.speaking();

    if engine.is_transmitting() {
        if let Ok(client_id) = state.with_session(voice, |s| s.client.session().client_id) {
            speaking.push(client_id);
        }
    }

    SpeakingDto {
        session: Some(voice),
        clients: speaking,
    }
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
        // The capture pump follows the voice route rather than owning a client,
        // so a rebuild does not need to know where voice currently points.
        state.start_audio()?;
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

/// The udev rule needed to read the mice on this machine, or `None` if they can
/// already be read.
///
/// The alternative — telling everyone to run `usermod -aG input` — grants every
/// process the user runs a permanent read on every keyboard attached to the
/// machine. Pickle is already enumerating input devices, so it is in a position
/// to name the one device it actually needs and hand over a rule for exactly
/// that, which is a far smaller thing to ask someone to install as root.
#[tauri::command]
pub fn mouse_udev_rule() -> Option<mouse_grab::UdevAdvice> {
    mouse_grab::udev_advice()
}

/// Run the audio engine while disconnected, so the settings dialog can show a
/// live input meter and let someone actually hear whether a device works.
#[tauri::command]
pub fn start_audio_preview(state: State<'_, AppState>) -> Result<(), String> {
    // Leaves a running engine alone rather than replacing it, which would cut
    // the microphone on whichever connection currently holds voice.
    state.ensure_audio().map(|_| ())
}

#[tauri::command]
pub fn stop_audio_preview(state: State<'_, AppState>) {
    // Only when nothing is connected. With a live connection the engine is not
    // a preview to be stopped — it is carrying someone's voice.
    if state.sessions.lock().is_empty() {
        state.stop_audio();
    }
}

/// Turn what the user typed into an address, supplying the default port.
///
/// Accepts a hostname, an IPv4 address, or a bracketed IPv6 address, with or
/// without a port.
/// The address as typed, with the default port made explicit.
///
/// Used as the trust-store key, so `example.com` and `example.com:42071` are one
/// pin rather than two — otherwise adding the port later would look like an
/// unknown server.
fn canonical_address(input: &str) -> String {
    let trimmed = input.trim();
    if has_port(trimmed) {
        trimmed.to_string()
    } else {
        format!("{trimmed}:{DEFAULT_PORT}")
    }
}

/// Replace the pinned identity for one server — the deliberate act the
/// library insists on and never performs itself.
///
/// Takes the fingerprint the user was shown and agreed to, not "whatever the
/// server presents next". If the server has changed identity again since the
/// warning, the next connection attempt fails with a fresh mismatch instead of
/// silently pinning something the user never saw.
#[tauri::command]
pub fn trust_changed_identity(
    state: State<'_, AppState>,
    address_key: String,
    fingerprint: String,
) -> Result<(), String> {
    let fingerprint = pickle_identity::Fingerprint::parse(&fingerprint)
        .map_err(|e| format!("that fingerprint is not readable: {e}"))?;

    let mut trust = state.trust_store()?;
    // Keep the remembered server name; the pin is what changes, not what the
    // entry is called in the servers-you-have-used list.
    let name = trust
        .get(&address_key)
        .map(|entry| entry.name.clone())
        .unwrap_or_default();

    trust.trust(&address_key, fingerprint, &name);
    // This save *is* the user's decision. A silent failure here would show
    // the same warning again next connect, as though the click never happened.
    trust.save().map_err(|e| e.to_string())?;
    info!(server = %address_key, %fingerprint, "re-pinned a changed server identity");
    Ok(())
}

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
