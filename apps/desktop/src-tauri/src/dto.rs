//! Shapes crossing the Rust/JavaScript boundary.
//!
//! These exist rather than serialising the protocol types directly for two
//! reasons: the frontend should not depend on the wire format's stability, and
//! several protocol types carry things JavaScript has no use for — raw
//! signatures, `Bytes` payloads, opaque key material.

use crate::state::SessionId;
use pickle_audio::DeviceInfo;
use pickle_client::{ClientEvent, SessionInfo};
use pickle_identity::{Identity, VaultEntry};
use pickle_proto::{Channel, ChatMessage, UserInfo};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityDto {
    /// Full fingerprint, for comparing out of band.
    pub fingerprint: String,
    /// Abbreviated form for lists and headers.
    pub short: String,
    pub security_level: u32,
    pub nickname: String,
}

impl IdentityDto {
    pub fn new(identity: &Identity, nickname: &str) -> Self {
        Self {
            fingerprint: identity.fingerprint().to_string(),
            short: identity.fingerprint().short(),
            security_level: identity.security_level(),
            nickname: nickname.to_string(),
        }
    }
}

/// One entry in the identity picker.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntryDto {
    pub fingerprint: String,
    pub short: String,
    pub security_level: u32,
    pub nickname: String,
    /// Private note, never sent to a server.
    pub label: String,
}

impl VaultEntryDto {
    pub fn new(entry: &VaultEntry) -> Self {
        Self {
            fingerprint: entry.identity.fingerprint().to_string(),
            short: entry.identity.fingerprint().short(),
            security_level: entry.identity.security_level(),
            nickname: entry.nickname.clone(),
            label: entry.label.clone(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityListDto {
    /// Fingerprint of the active identity.
    pub active: String,
    pub identities: Vec<VaultEntryDto>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChannelDto {
    pub id: u32,
    pub parent: Option<u32>,
    pub name: String,
    pub topic: String,
    pub has_voice: bool,
    pub has_text: bool,
    pub order: i32,
    pub max_users: Option<u16>,
}

impl From<&Channel> for ChannelDto {
    fn from(channel: &Channel) -> Self {
        Self {
            id: channel.id,
            parent: channel.parent,
            name: channel.name.clone(),
            topic: channel.topic.clone(),
            has_voice: channel.kind.has_voice(),
            has_text: channel.kind.has_text(),
            order: channel.order,
            max_users: channel.max_users,
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserDto {
    pub client_id: u32,
    pub nickname: String,
    /// The full fingerprint: the stable key for anything that acts on a user
    /// across sessions — role grants, bans, copy-to-verify.
    pub fingerprint: String,
    /// Abbreviated form for lists, the only reliable way to tell apart two
    /// users who chose the same nickname.
    pub short: String,
    pub security_level: u32,
    pub channel: Option<u32>,
    pub self_muted: bool,
    pub self_deafened: bool,
    /// Muted by a moderator, not by choice — rendered distinctly.
    pub server_muted: bool,
    /// Role grants, @everyone implicit — what the members editor seeds from.
    pub roles: Vec<u32>,
}

impl From<&UserInfo> for UserDto {
    fn from(user: &UserInfo) -> Self {
        Self {
            client_id: user.client_id,
            nickname: user.nickname.clone(),
            fingerprint: user.identity.fingerprint().to_string(),
            short: user.identity.fingerprint().short(),
            security_level: user.identity.security_level(),
            channel: user.channel,
            self_muted: user.voice.self_muted,
            self_deafened: user.voice.self_deafened,
            server_muted: user.voice.server_muted,
            roles: user.roles.clone(),
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BanDto {
    pub fingerprint: String,
    pub short: String,
    pub reason: String,
    pub until_unix_ms: Option<u64>,
    pub issued_by_short: String,
    pub issued_at_unix_ms: u64,
}

impl From<&pickle_proto::BanEntry> for BanDto {
    fn from(ban: &pickle_proto::BanEntry) -> Self {
        Self {
            fingerprint: ban.fingerprint.to_string(),
            short: ban.fingerprint.short(),
            reason: ban.reason.clone(),
            until_unix_ms: ban.until_unix_ms,
            issued_by_short: ban.issued_by.short(),
            issued_at_unix_ms: ban.issued_at_unix_ms,
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MessageDto {
    pub id: u64,
    pub channel: u32,
    pub author_nickname: String,
    pub author_fingerprint: String,
    pub content: String,
    pub sent_at_unix_ms: u64,
}

impl From<&ChatMessage> for MessageDto {
    fn from(message: &ChatMessage) -> Self {
        Self {
            id: message.id,
            channel: message.channel,
            author_nickname: message.author_nickname.clone(),
            author_fingerprint: message.author_fingerprint.short(),
            content: message.content.clone(),
            sent_at_unix_ms: message.sent_at_unix_ms,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDto {
    pub client_id: u32,
    pub server_name: String,
    pub server_fingerprint: String,
    pub default_channel: Option<u32>,
    pub channels: Vec<ChannelDto>,
    pub users: Vec<UserDto>,
}

impl From<&SessionInfo> for SessionDto {
    fn from(session: &SessionInfo) -> Self {
        Self {
            client_id: session.client_id,
            server_name: session.server_name.clone(),
            server_fingerprint: session.server_identity.fingerprint().to_string(),
            default_channel: session.default_channel,
            channels: session.channels.iter().map(ChannelDto::from).collect(),
            users: session.users.iter().map(UserDto::from).collect(),
        }
    }
}

/// One live connection: its id, what the server told us, and who we are on it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDto {
    pub permissions: crate::perms::MyPermissionsDto,
    pub roles: Vec<crate::perms::RoleDto>,
    pub session: SessionId,
    pub info: SessionDto,
    /// Fingerprint of the identity this connection signed in with, which need
    /// not be the vault's currently active one.
    pub identity: String,
}

/// Who is audible, and on which connection.
///
/// The session is part of the answer rather than assumed: speaker ids only mean
/// something within one server, so the UI must know where to apply them.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SpeakingDto {
    pub session: Option<SessionId>,
    pub clients: Vec<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionListDto {
    pub sessions: Vec<ConnectionDto>,
    /// Which connection the microphone feeds, if any.
    pub voice: Option<SessionId>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioDeviceDto {
    pub name: String,
    pub is_default: bool,
    /// False only for a device offering no sample format Pickle can read. A
    /// device at some rate other than 48 kHz is converted rather than refused,
    /// so it is perfectly usable.
    pub usable: bool,
    /// The rate the device would be opened at, or `None` when it could not be
    /// queried. Anything other than 48 kHz means a conversion is in the path,
    /// which the UI says out loud rather than hiding.
    pub sample_rate: Option<u32>,
}

impl From<&DeviceInfo> for AudioDeviceDto {
    fn from(device: &DeviceInfo) -> Self {
        Self {
            name: device.name.clone(),
            is_default: device.is_default,
            usable: device.usable,
            sample_rate: device.sample_rate,
        }
    }
}

/// Events pushed to the frontend on the `pickle:event` channel.
///
/// Voice frames are deliberately absent: they go straight to the mixer on the
/// Rust side. Marshalling 50 audio packets a second per speaker through the
/// JavaScript bridge would be pure waste.
#[derive(Serialize, Clone)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum EventDto {
    UserJoined {
        user: UserDto,
    },
    UserLeft {
        client_id: u32,
        /// "left", "kicked" or "banned" — the occupant disappears either way,
        /// but moderation is public and reads differently.
        reason: &'static str,
    },
    UserMoved {
        client_id: u32,
        channel: Option<u32>,
    },
    UserUpdated {
        user: UserDto,
    },
    Message {
        message: MessageDto,
    },
    History {
        channel: u32,
        messages: Vec<MessageDto>,
        reached_start: bool,
    },
    Typing {
        client_id: u32,
        channel: u32,
    },
    ChannelCreated {
        channel: ChannelDto,
    },
    ChannelUpdated {
        channel: ChannelDto,
    },
    ChannelRemoved {
        channel_id: u32,
    },
    ServerError {
        code: &'static str,
        detail: String,
    },
    BanList {
        bans: Vec<BanDto>,
    },
    CommandFailed {
        nonce: u64,
        code: &'static str,
        detail: String,
    },
    RolesChanged {
        roles: Vec<crate::perms::RoleDto>,
    },
    /// Derived by the Rust-side permission mirror, not translated from the
    /// wire: a complete snapshot, replaced wholesale, so the frontend never
    /// merges permission state.
    PermissionsChanged {
        permissions: crate::perms::MyPermissionsDto,
    },
    Disconnected {
        reason: String,
    },
}

impl EventDto {
    /// Convert an event for the UI, or `None` if it has no UI meaning.
    pub fn from_event(event: &ClientEvent) -> Option<Self> {
        Some(match event {
            ClientEvent::UserJoined(user) => Self::UserJoined {
                user: UserDto::from(user),
            },
            ClientEvent::UserLeft { client, reason } => Self::UserLeft {
                client_id: *client,
                reason: match reason {
                    pickle_proto::DisconnectReason::Kicked => "kicked",
                    pickle_proto::DisconnectReason::Banned => "banned",
                    _ => "left",
                },
            },
            ClientEvent::UserMoved { client, to, .. } => Self::UserMoved {
                client_id: *client,
                channel: *to,
            },
            ClientEvent::UserUpdated(user) => Self::UserUpdated {
                user: UserDto::from(user),
            },
            ClientEvent::MessagePosted { message, .. } => Self::Message {
                message: MessageDto::from(message),
            },
            ClientEvent::History {
                channel,
                messages,
                reached_start,
            } => Self::History {
                channel: *channel,
                messages: messages.iter().map(MessageDto::from).collect(),
                reached_start: *reached_start,
            },
            ClientEvent::Typing { client, channel } => Self::Typing {
                client_id: *client,
                channel: *channel,
            },
            ClientEvent::ChannelCreated(channel) => Self::ChannelCreated {
                channel: ChannelDto::from(channel),
            },
            ClientEvent::ChannelUpdated(channel) => Self::ChannelUpdated {
                channel: ChannelDto::from(channel),
            },
            ClientEvent::ChannelRemoved(id) => Self::ChannelRemoved { channel_id: *id },
            ClientEvent::ServerError { code, detail } => Self::ServerError {
                code: error_code_str(*code),
                detail: detail.clone(),
            },
            ClientEvent::Disconnected { reason } => Self::Disconnected {
                reason: reason.clone(),
            },

            // Handled on the Rust side or not yet surfaced in the UI.
            ClientEvent::BanList { bans } => Self::BanList {
                bans: bans.iter().map(BanDto::from).collect(),
            },
            ClientEvent::CommandFailed {
                nonce,
                code,
                detail,
            } => Self::CommandFailed {
                nonce: *nonce,
                code: error_code_str(*code),
                detail: detail.clone(),
            },

            // The role events feed the Rust-side permission mirror, which
            // emits derived snapshot events the frontend consumes whole; the
            // raw frames stay on this side of the bridge. Ack is silent —
            // success shows as the broadcast it caused.
            ClientEvent::RoleCreated(_)
            | ClientEvent::RoleUpdated(_)
            | ClientEvent::RoleDeleted { .. }
            | ClientEvent::RolesReordered { .. }
            | ClientEvent::Ack { .. }
            | ClientEvent::Voice(_)
            | ClientEvent::VoiceActivity { .. }
            | ClientEvent::Pong { .. }
            | ClientEvent::MessageEdited { .. }
            | ClientEvent::MessageDeleted { .. } => return None,
        })
    }
}

/// Why a connection could not be made, in a shape the frontend can act on.
///
/// Almost every failure is just a sentence to show. The identity change is
/// the exception: the library refuses to resolve it automatically — re-pinning
/// must be a deliberate act by the user — so the frontend needs the parts,
/// not the prose, to offer that act.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConnectFailureDto {
    pub message: String,
    pub identity_changed: Option<IdentityChangedDto>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IdentityChangedDto {
    /// The key the pin is filed under — what the user typed, canonicalised —
    /// which is what a re-pin must be filed under too.
    pub address_key: String,
    pub previous: String,
    pub current: String,
}

impl From<String> for ConnectFailureDto {
    fn from(message: String) -> Self {
        Self {
            message,
            identity_changed: None,
        }
    }
}

impl From<&pickle_client::ConnectError> for ConnectFailureDto {
    fn from(error: &pickle_client::ConnectError) -> Self {
        let identity_changed = match error {
            pickle_client::ConnectError::IdentityChanged {
                address,
                expected,
                actual,
            } => Some(IdentityChangedDto {
                address_key: address.clone(),
                previous: expected.to_string(),
                current: actual.to_string(),
            }),
            _ => None,
        };
        Self {
            message: error.to_string(),
            identity_changed,
        }
    }
}

/// Stable camelCase names for the frontend. Deliberately a hand-written
/// exhaustive match rather than serde on the proto enum: the frontend should
/// not depend on the wire format's spelling, and a new `ErrorCode` variant
/// must fail compilation here instead of leaking an unknown string.
fn error_code_str(code: pickle_proto::ErrorCode) -> &'static str {
    use pickle_proto::ErrorCode;
    match code {
        ErrorCode::NotAuthenticated => "notAuthenticated",
        ErrorCode::NoSuchChannel => "noSuchChannel",
        ErrorCode::NoSuchMessage => "noSuchMessage",
        ErrorCode::ChannelFull => "channelFull",
        ErrorCode::ChannelPasswordRequired => "channelPasswordRequired",
        ErrorCode::NotPermitted => "notPermitted",
        ErrorCode::RateLimited => "rateLimited",
        ErrorCode::MessageTooLong => "messageTooLong",
        ErrorCode::Malformed => "malformed",
        ErrorCode::Internal => "internal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The JSON contract with api.ts, pinned where TypeScript cannot pin it:
    /// the tag, the camelCase field names, and the code strings must match the
    /// ServerEvent union by hand, so a drift here is a silent UI breakage.
    #[test]
    fn server_error_serializes_with_a_code_the_frontend_knows() {
        let dto = EventDto::ServerError {
            code: error_code_str(pickle_proto::ErrorCode::NotPermitted),
            detail: "no".into(),
        };
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["type"], "serverError");
        assert_eq!(json["code"], "notPermitted");
        assert_eq!(json["detail"], "no");
    }

    #[test]
    fn channel_removed_names_its_field_in_camel_case() {
        let dto = EventDto::ChannelRemoved { channel_id: 7 };
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["type"], "channelRemoved");
        assert_eq!(json["channelId"], 7);
    }

    #[test]
    fn a_user_dto_carries_both_fingerprint_forms() {
        let identity = pickle_identity::Identity::generate();
        let user = pickle_proto::UserInfo {
            client_id: 1,
            identity: identity.public(),
            nickname: "randy".into(),
            channel: None,
            voice: Default::default(),
            connected_at_unix_ms: 0,
            roles: Vec::new(),
            owner: false,
        };
        let dto = UserDto::from(&user);
        assert_eq!(dto.fingerprint, identity.fingerprint().to_string());
        assert_eq!(dto.short, identity.fingerprint().short());
        assert_ne!(dto.fingerprint, dto.short, "short must actually abbreviate");
    }
}
