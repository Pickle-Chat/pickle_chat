//! Shapes crossing the Rust/JavaScript boundary.
//!
//! These exist rather than serialising the protocol types directly for two
//! reasons: the frontend should not depend on the wire format's stability, and
//! several protocol types carry things JavaScript has no use for — raw
//! signatures, `Bytes` payloads, opaque key material.

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelDto {
    pub id: u32,
    pub parent: Option<u32>,
    pub name: String,
    pub topic: String,
    pub has_voice: bool,
    pub has_text: bool,
    pub order: i32,
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
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserDto {
    pub client_id: u32,
    pub nickname: String,
    /// Abbreviated fingerprint — the only reliable way to tell apart two users
    /// who chose the same nickname.
    pub fingerprint: String,
    pub security_level: u32,
    pub channel: Option<u32>,
    pub self_muted: bool,
    pub self_deafened: bool,
}

impl From<&UserInfo> for UserDto {
    fn from(user: &UserInfo) -> Self {
        Self {
            client_id: user.client_id,
            nickname: user.nickname.clone(),
            fingerprint: user.identity.fingerprint().short(),
            security_level: user.identity.security_level(),
            channel: user.channel,
            self_muted: user.voice.self_muted,
            self_deafened: user.voice.self_deafened,
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
    pub default_channel: u32,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioDeviceDto {
    pub name: String,
    pub is_default: bool,
    pub usable: bool,
}

impl From<&DeviceInfo> for AudioDeviceDto {
    fn from(device: &DeviceInfo) -> Self {
        Self {
            name: device.name.clone(),
            is_default: device.is_default,
            usable: device.supports_native_rate,
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
    Typing {
        client_id: u32,
        channel: u32,
    },
    ServerError {
        detail: String,
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
            ClientEvent::UserLeft { client, .. } => Self::UserLeft { client_id: *client },
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
            ClientEvent::Typing { client, channel } => Self::Typing {
                client_id: *client,
                channel: *channel,
            },
            ClientEvent::ServerError { detail, .. } => Self::ServerError {
                detail: detail.clone(),
            },
            ClientEvent::Disconnected { reason } => Self::Disconnected {
                reason: reason.clone(),
            },

            // Handled on the Rust side or not yet surfaced in the UI.
            ClientEvent::Voice(_)
            | ClientEvent::VoiceActivity { .. }
            | ClientEvent::Pong { .. }
            | ClientEvent::ChannelCreated(_)
            | ClientEvent::ChannelUpdated(_)
            | ClientEvent::ChannelRemoved(_)
            | ClientEvent::MessageEdited { .. }
            | ClientEvent::MessageDeleted { .. }
            | ClientEvent::History { .. } => return None,
        })
    }
}
