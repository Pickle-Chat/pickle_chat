//! The Pickle wire protocol.
//!
//! Every connection is a single QUIC connection carrying two kinds of traffic:
//!
//! * **Control** — a reliable, ordered bidirectional stream. Authentication,
//!   channel and user state, and text chat. Length-prefixed [`postcard`] frames;
//!   see [`codec`].
//! * **Voice** — QUIC datagrams, which are unreliable and unordered. A late
//!   audio frame is worthless, so retransmitting one would only add latency and
//!   head-of-line blocking to everything behind it. See [`voice`].
//!
//! Both live on one connection, so voice and text share congestion control and
//! a single hole in the host's firewall.

pub mod codec;
pub mod voice;

use pickle_identity::{Fingerprint, PublicIdentity};
use serde::{Deserialize, Serialize};

/// Bumped on any breaking change to the message types below.
///
/// Pre-1.0 this is checked for exact equality: a mismatch is refused outright
/// rather than negotiated down.
pub const PROTOCOL_VERSION: u16 = 1;

/// TLS ALPN identifier. Also carries the version, so an incompatible client is
/// rejected during the TLS handshake rather than after it.
pub const ALPN: &[u8] = b"pickle/1";

/// Server-assigned, unique for the lifetime of a connection and reused
/// afterwards. Not an identity — use [`Fingerprint`] to recognise a person.
pub type ClientId = u32;
pub type ChannelId = u32;
/// Monotonic per server, assigned on persist so history can be paged.
pub type MessageId = u64;

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// First frame on the control stream, sent by the server.
///
/// `signature` covers `nonce`, the server's TLS certificate hash, and
/// `server_name`, proving the holder of `server_identity` is on the other end
/// of *this* TLS session. That is what lets a client keep trusting a server
/// after its certificate rotates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub protocol_version: u16,
    pub server_name: String,
    pub server_identity: PublicIdentity,
    /// Fresh per connection; the client signs it to prove key possession.
    pub nonce: [u8; 32],
    pub min_security_level: u32,
    pub requires_password: bool,
    pub signature: SignatureBytes,
}

/// The client's reply, proving control of its private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuth {
    pub protocol_version: u16,
    pub identity: PublicIdentity,
    /// Cosmetic and unverified. Servers may rewrite or reject it.
    pub nickname: String,
    /// Optional shared secret for private servers, distinct from identity.
    pub password: Option<String>,
    pub client_version: String,
    /// Over `ServerHello::nonce` and the server's certificate hash.
    pub signature: SignatureBytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthOk {
    pub client_id: ClientId,
    pub channels: Vec<Channel>,
    pub users: Vec<UserInfo>,
    /// Where the server placed this client, if anywhere. Admission never puts
    /// anyone in a channel that carries voice — connecting to a server should
    /// not mean walking into a room where you can be heard — so on a server
    /// with no text-only channel there is nowhere safe to land, and this is
    /// `None`.
    pub default_channel: Option<ChannelId>,
    pub limits: ServerLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthFailure {
    ProtocolMismatch {
        server_version: u16,
    },
    SecurityLevelTooLow {
        required: u32,
        provided: u32,
    },
    BadSignature,
    PasswordRequired,
    BadPassword,
    Banned {
        reason: String,
        until_unix_ms: Option<u64>,
    },
    ServerFull,
    NicknameRejected {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerLimits {
    pub max_message_len: u32,
    pub max_nickname_len: u32,
    pub max_users: u32,
    pub history_enabled: bool,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_message_len: 4000,
            max_nickname_len: 32,
            max_users: 64,
            history_enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Channels and users
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Voice,
    Text,
    /// A voice channel with an attached text log, as Discord does it.
    VoiceAndText,
}

impl ChannelKind {
    pub fn has_voice(self) -> bool {
        matches!(self, Self::Voice | Self::VoiceAndText)
    }
    pub fn has_text(self) -> bool {
        matches!(self, Self::Text | Self::VoiceAndText)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: ChannelId,
    /// `None` for a top-level channel. Nesting gives TeamSpeak-style trees.
    pub parent: Option<ChannelId>,
    pub name: String,
    pub topic: String,
    pub kind: ChannelKind,
    pub max_users: Option<u16>,
    pub password_protected: bool,
    /// Sort key within the parent; ties broken by name.
    pub order: i32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoiceState {
    pub self_muted: bool,
    pub self_deafened: bool,
    pub server_muted: bool,
    /// Transient; driven by the sender's voice activity detection.
    pub speaking: bool,
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/// One thing a user may be allowed to do.
///
/// Explicit rather than implied by rank, so "may mute but not kick" is
/// expressible. Rank answers a different question — see [`Role::rank`].
///
/// New variants must be **appended**. postcard encodes an enum by variant
/// index, so inserting one silently reinterprets every message a older peer
/// sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Capability {
    KickUsers,
    BanUsers,
    /// Silence someone without disconnecting them.
    MuteUsers,
    MoveUsers,
    ManageChannels,
    /// Grant and revoke roles.
    ManageRoles,
    /// Change server-wide settings.
    ManageServer,
}

impl Capability {
    /// Every capability, for granting a role everything short of ownership.
    pub const ALL: [Capability; 7] = [
        Capability::KickUsers,
        Capability::BanUsers,
        Capability::MuteUsers,
        Capability::MoveUsers,
        Capability::ManageChannels,
        Capability::ManageRoles,
        Capability::ManageServer,
    ];
}

/// A named bundle of capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    /// Governs who may act on whom, and nothing else.
    ///
    /// Capabilities say what an action *is*; rank says whether the target is
    /// above you. Acting on an equal or higher rank is refused however many
    /// capabilities you hold, so two moderators cannot kick each other and an
    /// admin cannot kick the owner.
    pub rank: u32,
    pub capabilities: Vec<Capability>,
}

impl Role {
    pub fn allows(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// What a user may do here, as resolved by the server.
///
/// Sent with [`UserInfo`] so a client can enable and disable its own controls
/// without a second round trip. It is a courtesy for rendering only: the server
/// checks every action regardless of what the client believed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions {
    /// `None` for a user with no role assigned.
    pub role: Option<String>,
    pub rank: u32,
    pub capabilities: Vec<Capability>,
    /// The server operator, who passes every check regardless of role.
    pub owner: bool,
}

impl Permissions {
    /// A user with no role: may do nothing administrative.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn allows(&self, capability: Capability) -> bool {
        self.owner || self.capabilities.contains(&capability)
    }

    /// Whether this user may act on `target`.
    ///
    /// Rank alone; the caller still has to hold the capability for whatever it
    /// is doing. The owner outranks everyone, and is never outranked — losing
    /// control of your own server to someone you promoted would be a poor
    /// reward for promoting them.
    pub fn outranks(&self, target: &Permissions) -> bool {
        if target.owner {
            return false;
        }
        self.owner || self.rank > target.rank
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub client_id: ClientId,
    pub identity: PublicIdentity,
    pub nickname: String,
    pub channel: Option<ChannelId>,
    pub voice: VoiceState,
    pub connected_at_unix_ms: u64,
    pub permissions: Permissions,
}

impl UserInfo {
    pub fn fingerprint(&self) -> Fingerprint {
        self.identity.fingerprint()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisconnectReason {
    Quit,
    TimedOut,
    Kicked,
    Banned,
    ServerShutdown,
}

// ---------------------------------------------------------------------------
// Text chat
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: MessageId,
    pub channel: ChannelId,
    /// `None` once the author has disconnected — the fingerprint outlives it.
    pub author: Option<ClientId>,
    pub author_fingerprint: Fingerprint,
    /// Snapshot at send time, so history renders correctly after a rename.
    pub author_nickname: String,
    pub sent_at_unix_ms: u64,
    pub edited_at_unix_ms: Option<u64>,
    /// Markdown source. Rendering is the client's business; the server never
    /// interprets it.
    pub content: String,
    pub reply_to: Option<MessageId>,
    pub attachments: Vec<Attachment>,
    pub reactions: Vec<Reaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: u64,
    pub filename: String,
    pub byte_len: u64,
    pub mime: String,
    /// BLAKE3-style content hash for dedupe and integrity on download.
    pub content_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub emoji: String,
    /// Fingerprints rather than client ids, so reactions survive reconnects.
    pub reactors: Vec<Fingerprint>,
}

// ---------------------------------------------------------------------------
// Control messages
// ---------------------------------------------------------------------------

/// Client to server. The first frame must be [`ClientControl::Auth`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientControl {
    Auth(Box<ClientAuth>),
    JoinChannel {
        channel: ChannelId,
        password: Option<String>,
    },
    LeaveChannel,
    SetVoiceState {
        self_muted: bool,
        self_deafened: bool,
    },
    SetNickname(String),
    SendMessage {
        channel: ChannelId,
        content: String,
        reply_to: Option<MessageId>,
        /// Client-chosen; echoed back so an optimistic local render can be
        /// reconciled with the server's authoritative copy.
        nonce: u64,
    },
    EditMessage {
        id: MessageId,
        content: String,
    },
    DeleteMessage {
        id: MessageId,
    },
    React {
        message: MessageId,
        emoji: String,
        add: bool,
    },
    FetchHistory {
        channel: ChannelId,
        before: Option<MessageId>,
        limit: u16,
    },
    Typing {
        channel: ChannelId,
    },
    Ping {
        nonce: u64,
    },
}

/// Server to client. The first frame is always [`ServerControl::Hello`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerControl {
    Hello(Box<ServerHello>),
    AuthOk(Box<AuthOk>),
    AuthFailed(AuthFailure),

    UserJoined(Box<UserInfo>),
    UserLeft {
        client: ClientId,
        reason: DisconnectReason,
    },
    UserMoved {
        client: ClientId,
        from: Option<ChannelId>,
        to: Option<ChannelId>,
    },
    UserUpdated(Box<UserInfo>),
    VoiceActivity {
        client: ClientId,
        speaking: bool,
    },

    ChannelCreated(Channel),
    ChannelUpdated(Channel),
    ChannelRemoved(ChannelId),

    MessagePosted {
        message: Box<ChatMessage>,
        nonce: Option<u64>,
    },
    MessageEdited {
        id: MessageId,
        content: String,
        edited_at_unix_ms: u64,
    },
    MessageDeleted {
        id: MessageId,
    },
    ReactionUpdated {
        message: MessageId,
        reaction: Reaction,
    },
    History {
        channel: ChannelId,
        messages: Vec<ChatMessage>,
        reached_start: bool,
    },
    Typing {
        client: ClientId,
        channel: ChannelId,
    },

    Pong {
        nonce: u64,
    },
    Error {
        code: ErrorCode,
        detail: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    NotAuthenticated,
    NoSuchChannel,
    NoSuchMessage,
    ChannelFull,
    ChannelPasswordRequired,
    NotPermitted,
    RateLimited,
    MessageTooLong,
    Malformed,
    Internal,
}

// ---------------------------------------------------------------------------
// Signature bytes
// ---------------------------------------------------------------------------

/// A raw Ed25519 signature.
///
/// serde only derives array impls up to length 32, so a 64-byte signature needs
/// its own impl. Serialised as an opaque byte string, which postcard encodes as
/// a length prefix plus the bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignatureBytes(pub [u8; 64]);

impl From<[u8; 64]> for SignatureBytes {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignatureBytes(..)")
    }
}

impl Serialize for SignatureBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct SigVisitor;

        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = SignatureBytes;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a 64-byte Ed25519 signature")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                <[u8; 64]>::try_from(v)
                    .map(SignatureBytes)
                    .map_err(|_| E::invalid_length(v.len(), &self))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(SignatureBytes(out))
            }
        }

        d.deserialize_bytes(SigVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pickle_identity::Identity;

    fn sample_hello() -> ServerHello {
        let identity = Identity::generate();
        let nonce = [3u8; 32];
        let cert = [4u8; 32];
        let signature = identity.sign_server_hello(&nonce, &cert, "Andy's Server");
        ServerHello {
            protocol_version: PROTOCOL_VERSION,
            server_name: "Andy's Server".into(),
            server_identity: identity.public(),
            nonce,
            min_security_level: 8,
            requires_password: false,
            signature: signature.into(),
        }
    }

    #[test]
    fn signature_bytes_roundtrip_through_postcard() {
        let sig = SignatureBytes([0xab; 64]);
        let bytes = postcard::to_stdvec(&sig).unwrap();
        let back: SignatureBytes = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, sig);
    }

    #[test]
    fn server_hello_survives_a_round_trip_with_its_signature_intact() {
        let hello = sample_hello();
        let bytes = postcard::to_stdvec(&ServerControl::Hello(Box::new(hello.clone()))).unwrap();
        let ServerControl::Hello(back) = postcard::from_bytes(&bytes).unwrap() else {
            panic!("wrong variant");
        };

        // The signature must still verify after transit, which is the whole
        // point of the encoding being exact.
        assert!(back
            .server_identity
            .verify_server_hello(
                &hello.nonce,
                &[4u8; 32],
                &hello.server_name,
                &back.signature.0
            )
            .is_ok());
    }

    #[test]
    fn client_control_variants_roundtrip() {
        let cases = vec![
            ClientControl::LeaveChannel,
            ClientControl::JoinChannel {
                channel: 7,
                password: Some("hunter2".into()),
            },
            ClientControl::SendMessage {
                channel: 1,
                content: "hello **world**".into(),
                reply_to: Some(42),
                nonce: 99,
            },
            ClientControl::SetVoiceState {
                self_muted: true,
                self_deafened: false,
            },
            ClientControl::Ping { nonce: u64::MAX },
        ];
        for case in cases {
            let bytes = postcard::to_stdvec(&case).unwrap();
            let back: ClientControl = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(format!("{case:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn channel_kind_capabilities() {
        assert!(ChannelKind::Voice.has_voice() && !ChannelKind::Voice.has_text());
        assert!(ChannelKind::Text.has_text() && !ChannelKind::Text.has_voice());
        assert!(ChannelKind::VoiceAndText.has_voice() && ChannelKind::VoiceAndText.has_text());
    }

    fn role_at(rank: u32, capabilities: Vec<Capability>) -> Permissions {
        Permissions {
            role: Some("test".into()),
            rank,
            capabilities,
            owner: false,
        }
    }

    #[test]
    fn capabilities_are_explicit_not_implied_by_rank() {
        // The reason capabilities exist separately from rank: "may mute but not
        // kick" has to be expressible.
        let muter = role_at(50, vec![Capability::MuteUsers]);
        assert!(muter.allows(Capability::MuteUsers));
        assert!(!muter.allows(Capability::KickUsers));
    }

    #[test]
    fn an_equal_rank_cannot_be_acted_on() {
        // Two moderators must not be able to kick each other.
        let one = role_at(50, Capability::ALL.to_vec());
        let two = role_at(50, Capability::ALL.to_vec());
        assert!(!one.outranks(&two));
        assert!(!two.outranks(&one));
    }

    #[test]
    fn a_higher_rank_may_act_on_a_lower_one_but_not_the_reverse() {
        let admin = role_at(100, Capability::ALL.to_vec());
        let moderator = role_at(50, Capability::ALL.to_vec());
        assert!(admin.outranks(&moderator));
        assert!(!moderator.outranks(&admin));
    }

    #[test]
    fn the_owner_outranks_everyone_and_is_never_outranked() {
        // Promoting someone must not be a way to lose your own server.
        let owner = Permissions {
            role: None,
            rank: 0,
            capabilities: Vec::new(),
            owner: true,
        };
        let admin = role_at(u32::MAX, Capability::ALL.to_vec());

        assert!(owner.outranks(&admin), "despite holding rank 0");
        assert!(!admin.outranks(&owner), "despite holding the highest rank");
        for capability in Capability::ALL {
            assert!(owner.allows(capability), "{capability:?}");
        }
    }

    #[test]
    fn a_user_without_a_role_may_do_nothing() {
        let nobody = Permissions::none();
        for capability in Capability::ALL {
            assert!(!nobody.allows(capability), "{capability:?}");
        }
        assert!(!nobody.outranks(&Permissions::none()));
    }

    #[test]
    fn control_message_variants_keep_their_wire_positions() {
        // postcard encodes an enum by variant index, so inserting a variant
        // rather than appending would silently reinterpret every message an
        // older peer sends. This pins the first byte of a few known messages.
        let encoded = postcard::to_stdvec(&ClientControl::LeaveChannel).unwrap();
        assert_eq!(encoded[0], 2, "LeaveChannel must stay at index 2");

        let encoded = postcard::to_stdvec(&ClientControl::Ping { nonce: 0 }).unwrap();
        assert_eq!(encoded[0], 11, "Ping must stay at index 11");
    }
}
