//! Client core for Pickle.
//!
//! Transport, handshake, and state — no audio and no UI. Both the Tauri desktop
//! app and headless test clients drive this same crate, which keeps the
//! protocol logic in one place and testable without a window or a microphone.
//!
//! A connection produces a [`Client`] handle for sending, and a stream of
//! [`ClientEvent`] for everything arriving.

pub mod tls;
pub mod trust;

pub use trust::{TrustDecision, TrustError, TrustStore, TrustedServer};

use bytes::Bytes;
use pickle_identity::{Fingerprint, Identity, PublicIdentity};
use pickle_proto::codec::{self, CodecError};
use pickle_proto::voice::{VoiceDownstream, VoiceUpstream};
use pickle_proto::{
    AuthFailure, BanEntry, Channel, ChannelId, ChatMessage, ClientAuth, ClientControl, ClientId,
    DisconnectReason, ErrorCode, MessageId, Role, RoleId, ServerControl, ServerLimits, UserInfo,
    PROTOCOL_VERSION,
};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::debug;

/// How long to wait for the server's greeting and its verdict on our login.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the QUIC handshake itself.
///
/// Without this the attempt runs until the idle timeout, so a mistyped address
/// leaves the user staring at a spinner for half a minute. Ten seconds is
/// plenty for any reachable host and fails fast for the rest.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("could not set up TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("could not reach {address}: {source}")]
    Transport {
        address: SocketAddr,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("control stream: {0}")]
    Codec(#[from] CodecError),
    #[error("the server closed the connection during the handshake")]
    ClosedDuringHandshake,
    #[error("the server did not respond within {}s", HANDSHAKE_TIMEOUT.as_secs())]
    TimedOut,
    #[error(
        "no server answered at {address} within {}s — check the address, \
         the port, and that the host's firewall allows UDP",
        CONNECT_TIMEOUT.as_secs()
    )]
    Unreachable { address: SocketAddr },
    #[error("the server sent {0} instead of a greeting")]
    UnexpectedGreeting(&'static str),
    #[error("the server speaks protocol version {theirs}, this client speaks {ours}")]
    ProtocolMismatch { ours: u16, theirs: u16 },
    #[error("the server presented no certificate")]
    NoPeerCertificate,
    #[error(
        "the server's greeting was not signed by the identity it claims \
         ({fingerprint}) — something is intercepting this connection"
    )]
    ForgedGreeting { fingerprint: Fingerprint },
    #[error(
        "the server at {address} now identifies as {actual}, but was previously \
         {expected}. Verify the new fingerprint with the operator before trusting it."
    )]
    IdentityChanged {
        address: String,
        expected: Fingerprint,
        actual: Fingerprint,
    },
    #[error("the server at {address} is not yet trusted (identity {fingerprint})")]
    NotTrusted {
        address: String,
        fingerprint: Fingerprint,
    },
    #[error("the server refused the connection: {0}")]
    Rejected(#[from] RejectionReason),
}

/// A server's stated reason for refusing a login, phrased for a user.
#[derive(Debug, thiserror::Error)]
pub enum RejectionReason {
    #[error("this client is too old or too new for the server (server speaks version {0})")]
    ProtocolMismatch(u16),
    #[error(
        "your identity is at security level {provided}, but this server requires {required}. \
         Mine your identity to a higher level and try again."
    )]
    SecurityLevelTooLow { required: u32, provided: u32 },
    #[error("the server rejected the identity signature")]
    BadSignature,
    #[error("this server requires a password")]
    PasswordRequired,
    #[error("incorrect server password")]
    BadPassword,
    #[error("you are banned from this server: {reason}")]
    Banned { reason: String },
    #[error("the server is full")]
    ServerFull,
    #[error("the server rejected your nickname: {reason}")]
    NicknameRejected { reason: String },
}

impl From<AuthFailure> for RejectionReason {
    fn from(failure: AuthFailure) -> Self {
        match failure {
            AuthFailure::ProtocolMismatch { server_version } => {
                Self::ProtocolMismatch(server_version)
            }
            AuthFailure::SecurityLevelTooLow { required, provided } => {
                Self::SecurityLevelTooLow { required, provided }
            }
            AuthFailure::BadSignature => Self::BadSignature,
            AuthFailure::PasswordRequired => Self::PasswordRequired,
            AuthFailure::BadPassword => Self::BadPassword,
            AuthFailure::Banned { reason, .. } => Self::Banned { reason },
            AuthFailure::ServerFull => Self::ServerFull,
            AuthFailure::NicknameRejected { reason } => Self::NicknameRejected { reason },
        }
    }
}

/// How much to insist on a known server identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustPolicy {
    /// Pin an unknown server automatically; refuse one whose identity changed.
    /// The SSH default, and the right one for most users.
    #[default]
    OnFirstUse,
    /// Refuse anything not already pinned. The user must add the server
    /// deliberately, having checked the fingerprint out of band.
    Strict,
    /// Accept anything, pin nothing. Tests only — this gives up detection of
    /// an interceptor entirely.
    Insecure,
}

pub struct ConnectOptions {
    pub address: SocketAddr,
    pub nickname: String,
    pub password: Option<String>,
    pub trust: TrustPolicy,
    /// What to file the server's identity under, normally the address the user
    /// typed.
    ///
    /// Kept separate from `address` because pinning an identity to a resolved
    /// `SocketAddr` pins it to a value an attacker can influence: change what
    /// the name resolves to and the new address is simply unknown, so
    /// trust-on-first-use pins the impostor without a word. Keying on what the
    /// user asked for means a substituted address still has to present the
    /// identity already recorded for that name.
    ///
    /// Defaults to the address, which keeps a caller that passes a literal IP
    /// behaving exactly as before.
    pub server_key: Option<String>,
}

impl ConnectOptions {
    pub fn new(address: SocketAddr, nickname: impl Into<String>) -> Self {
        Self {
            address,
            nickname: nickname.into(),
            password: None,
            trust: TrustPolicy::default(),
            server_key: None,
        }
    }

    /// File the server's identity under the address the user typed, rather than
    /// whatever it resolved to.
    pub fn with_server_key(mut self, key: impl Into<String>) -> Self {
        self.server_key = Some(normalise_server_key(&key.into()));
        self
    }

    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    pub fn with_trust(mut self, trust: TrustPolicy) -> Self {
        self.trust = trust;
        self
    }
}

/// Everything the server told us at login.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub client_id: ClientId,
    pub server_name: String,
    pub server_identity: PublicIdentity,
    /// Only the channels this member may view; the channel events keep the
    /// caller's copy true as permissions change.
    pub channels: Vec<Channel>,
    pub users: Vec<UserInfo>,
    /// Every role on the server, ordered by position.
    pub roles: Vec<Role>,
    /// The channel to read first — a suggestion, not a placement. `None`
    /// when no text-capable channel is visible to this member.
    pub default_channel: Option<ChannelId>,
    pub limits: ServerLimits,
}

/// Everything arriving from the server.
#[derive(Debug)]
pub enum ClientEvent {
    UserJoined(UserInfo),
    UserLeft {
        client: ClientId,
        reason: DisconnectReason,
    },
    UserMoved {
        client: ClientId,
        from: Option<ChannelId>,
        to: Option<ChannelId>,
    },
    UserUpdated(UserInfo),
    VoiceActivity {
        client: ClientId,
        speaking: bool,
    },

    ChannelCreated(Channel),
    ChannelUpdated(Channel),
    ChannelRemoved(ChannelId),

    MessagePosted {
        message: ChatMessage,
        /// Set when this echoes back our own send, matching the nonce we chose.
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
    History {
        channel: ChannelId,
        messages: Vec<ChatMessage>,
        reached_start: bool,
    },
    Typing {
        client: ClientId,
        channel: ChannelId,
    },

    /// One decoded voice frame. The audio layer owns jitter buffering and
    /// decoding; the client core only demultiplexes.
    RoleCreated(Role),
    RoleUpdated(Role),
    RoleDeleted {
        id: RoleId,
    },
    RolesReordered {
        positions: Vec<(RoleId, u32)>,
    },
    BanList {
        bans: Vec<BanEntry>,
    },
    /// A mutating admin command succeeded, by nonce.
    Ack {
        nonce: u64,
    },
    /// A mutating admin command was refused or failed, by nonce.
    CommandFailed {
        nonce: u64,
        code: ErrorCode,
        detail: String,
    },

    Voice(VoiceDownstream),

    Pong {
        nonce: u64,
    },
    ServerError {
        code: ErrorCode,
        detail: String,
    },
    /// Terminal. Nothing further arrives on this receiver.
    Disconnected {
        reason: String,
    },
}

/// A live connection. Dropping this closes the connection.
pub struct Client {
    connection: quinn::Connection,
    control: mpsc::UnboundedSender<ClientControl>,
    session: SessionInfo,
    // Held so the endpoint outlives the connection; dropping it would tear
    // down the UDP socket underneath us.
    _endpoint: quinn::Endpoint,
}

impl Client {
    pub fn session(&self) -> &SessionInfo {
        &self.session
    }

    pub fn client_id(&self) -> ClientId {
        self.session.client_id
    }

    /// Largest Opus payload that fits in one datagram on this path, or `None`
    /// if the peer refuses datagrams. Encoders should cap their bitrate to fit.
    pub fn max_voice_payload(&self) -> Option<usize> {
        self.connection
            .max_datagram_size()
            .map(|max| max.saturating_sub(pickle_proto::voice::UPSTREAM_HEADER_LEN))
    }

    /// Queue a control message. Returns `false` once the connection is gone.
    pub fn send_control(&self, message: ClientControl) -> bool {
        self.control.send(message).is_ok()
    }

    pub fn join_channel(&self, channel: ChannelId) -> bool {
        self.send_control(ClientControl::JoinChannel { channel })
    }

    pub fn leave_channel(&self) -> bool {
        self.send_control(ClientControl::LeaveChannel)
    }

    pub fn set_voice_state(&self, self_muted: bool, self_deafened: bool) -> bool {
        self.send_control(ClientControl::SetVoiceState {
            self_muted,
            self_deafened,
        })
    }

    pub fn send_message(&self, channel: ChannelId, content: impl Into<String>, nonce: u64) -> bool {
        self.send_control(ClientControl::SendMessage {
            channel,
            content: content.into(),
            reply_to: None,
            nonce,
        })
    }

    /// Ask for past messages, answered by a [`ClientEvent::History`].
    ///
    /// `before` pages backwards: pass the oldest id already held to get the
    /// page before it, or `None` for the most recent. The server caps `limit`,
    /// so asking for more than it allows returns what it allows rather than an
    /// error.
    pub fn fetch_history(&self, channel: ChannelId, before: Option<MessageId>, limit: u16) -> bool {
        self.send_control(ClientControl::FetchHistory {
            channel,
            before,
            limit,
        })
    }

    /// Send one encoded audio frame.
    ///
    /// Best effort and non-blocking: if the datagram cannot be queued the frame
    /// is dropped rather than delaying the next one. Late audio is worse than
    /// missing audio.
    pub fn send_voice(&self, seq: u32, flags: u8, payload: Bytes) {
        let datagram = VoiceUpstream {
            seq,
            flags,
            payload,
        }
        .encode();
        if let Err(e) = self.connection.send_datagram(datagram) {
            debug!(error = %e, "dropped an outbound voice frame");
        }
    }

    pub fn disconnect(&self) {
        self.connection.close(0u32.into(), b"bye");
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"bye");
    }
}

/// Connect, authenticate, and start the session.
///
/// `identity` is borrowed only for the handshake signature; it is not retained.
pub async fn connect(
    options: ConnectOptions,
    identity: &Identity,
    trust_store: &mut TrustStore,
) -> Result<(Client, mpsc::UnboundedReceiver<ClientEvent>), ConnectError> {
    let address = options.address;
    let transport_err = |source: Box<dyn std::error::Error + Send + Sync>| {
        ConnectError::Transport { address, source }
    };

    // Match the socket family to the target, or an IPv4 server is unreachable
    // from an IPv6-bound socket on some platforms.
    let bind: SocketAddr = if address.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };

    let mut endpoint = quinn::Endpoint::client(bind).map_err(|e| transport_err(Box::new(e)))?;
    endpoint.set_default_client_config(tls::quinn_client_config()?);

    // The name is a formality — the verifier ignores it, and a bare IP has none.
    let connecting = endpoint
        .connect(address, "pickle")
        .map_err(|e| transport_err(Box::new(e)))?;

    let connection = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| ConnectError::Unreachable { address })?
        .map_err(|e| transport_err(Box::new(e)))?;

    let cert_hash = peer_certificate_hash(&connection)?;

    // The server opens the control stream and speaks first.
    let (mut send, mut recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, connection.accept_bi())
        .await
        .map_err(|_| ConnectError::TimedOut)?
        .map_err(|_| ConnectError::ClosedDuringHandshake)?;

    let greeting: ServerControl =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, codec::read_frame(&mut recv))
            .await
            .map_err(|_| ConnectError::TimedOut)??;

    let ServerControl::Hello(hello) = greeting else {
        return Err(ConnectError::UnexpectedGreeting(describe(&greeting)));
    };

    if hello.protocol_version != PROTOCOL_VERSION {
        return Err(ConnectError::ProtocolMismatch {
            ours: PROTOCOL_VERSION,
            theirs: hello.protocol_version,
        });
    }

    // Proves the peer holds the identity key it claims, and that the claim is
    // bound to this TLS session rather than replayed from another one.
    hello
        .server_identity
        .verify_server_hello(
            &hello.nonce,
            &cert_hash,
            &hello.server_name,
            &hello.signature.0,
        )
        .map_err(|_| ConnectError::ForgedGreeting {
            fingerprint: hello.server_identity.fingerprint(),
        })?;

    let fingerprint = hello.server_identity.fingerprint();
    let address_key = options
        .server_key
        .clone()
        .unwrap_or_else(|| address.to_string());
    apply_trust_policy(
        trust_store,
        options.trust,
        &address_key,
        &address.to_string(),
        fingerprint,
        &hello.server_name,
    )?;

    let auth = ClientAuth {
        protocol_version: PROTOCOL_VERSION,
        identity: identity.public(),
        nickname: options.nickname.clone(),
        password: options.password.clone(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        signature: identity.sign_auth(&hello.nonce, &cert_hash).into(),
    };
    codec::write_frame(&mut send, &ClientControl::Auth(Box::new(auth))).await?;

    let verdict: ServerControl =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, codec::read_frame(&mut recv))
            .await
            .map_err(|_| ConnectError::TimedOut)??;

    let ok = match verdict {
        ServerControl::AuthOk(ok) => ok,
        ServerControl::AuthFailed(failure) => return Err(ConnectError::Rejected(failure.into())),
        other => return Err(ConnectError::UnexpectedGreeting(describe(&other))),
    };

    let session = SessionInfo {
        client_id: ok.client_id,
        server_name: hello.server_name.clone(),
        server_identity: hello.server_identity,
        channels: ok.channels,
        users: ok.users,
        roles: ok.roles,
        default_channel: ok.default_channel,
        limits: ok.limits,
    };

    let (control_tx, mut control_rx) = mpsc::unbounded_channel::<ClientControl>();
    let (event_tx, event_rx) = mpsc::unbounded_channel::<ClientEvent>();

    // Outbound control frames, serialised through one owner of the stream.
    tokio::spawn(async move {
        while let Some(message) = control_rx.recv().await {
            if codec::write_frame(&mut send, &message).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
    });

    // Inbound control frames.
    tokio::spawn({
        let events = event_tx.clone();
        async move {
            loop {
                match codec::read_frame::<_, ServerControl>(&mut recv).await {
                    Ok(message) => {
                        if let Some(event) = translate(message) {
                            if events.send(event).is_err() {
                                break; // receiver dropped
                            }
                        }
                    }
                    Err(e) => {
                        let reason = if e.is_clean_close() {
                            "the server closed the connection".to_string()
                        } else {
                            e.to_string()
                        };
                        let _ = events.send(ClientEvent::Disconnected { reason });
                        break;
                    }
                }
            }
        }
    });

    // Inbound voice, kept off the control task so an audio burst cannot delay
    // chat and a long chat frame cannot delay audio.
    tokio::spawn({
        let events = event_tx;
        let connection = connection.clone();
        async move {
            while let Ok(datagram) = connection.read_datagram().await {
                match VoiceDownstream::decode(datagram) {
                    Ok(packet) => {
                        if events.send(ClientEvent::Voice(packet)).is_err() {
                            break;
                        }
                    }
                    Err(e) => debug!(error = %e, "discarding a malformed voice datagram"),
                }
            }
        }
    });

    Ok((
        Client {
            connection,
            control: control_tx,
            session,
            _endpoint: endpoint,
        },
        event_rx,
    ))
}

/// Lowercase and trim, so `Chat.Example.com:42071` and `chat.example.com:42071`
/// are the same pin rather than two.
fn normalise_server_key(key: &str) -> String {
    key.trim().to_ascii_lowercase()
}

fn apply_trust_policy(
    store: &mut TrustStore,
    policy: TrustPolicy,
    address: &str,
    legacy_key: &str,
    fingerprint: Fingerprint,
    server_name: &str,
) -> Result<(), ConnectError> {
    if policy == TrustPolicy::Insecure {
        return Ok(());
    }

    match store.check(address, fingerprint) {
        TrustDecision::Recognised => Ok(()),

        TrustDecision::FirstContact { fingerprint } => {
            // Pins used to be filed under the resolved address. One recorded
            // that way, for this same identity, is a pin this user already
            // made — adopt it under the new key rather than calling it first
            // contact, which would otherwise quietly re-pin on upgrade and
            // throw away the very decision being migrated.
            //
            // A legacy entry with a *different* fingerprint is not adopted: an
            // address can legitimately be reused by another server, so that
            // case falls through to the normal first-contact rules.
            if legacy_key != address
                && matches!(
                    store.check(legacy_key, fingerprint),
                    TrustDecision::Recognised
                )
            {
                store.trust(address, fingerprint, server_name);
                store.forget(legacy_key);
                if let Err(e) = store.save() {
                    debug!(error = %e, "could not persist the migrated server pin");
                }
                return Ok(());
            }

            if policy == TrustPolicy::Strict {
                return Err(ConnectError::NotTrusted {
                    address: address.to_string(),
                    fingerprint,
                });
            }
            store.trust(address, fingerprint, server_name);
            // A failure to persist should not stop the session; the pin simply
            // will not survive a restart.
            if let Err(e) = store.save() {
                debug!(error = %e, "could not persist the server pin");
            }
            Ok(())
        }

        // Never resolved automatically, under any policy. Re-pinning has to be
        // a deliberate act by the user after checking with the operator.
        TrustDecision::Changed { expected, actual } => Err(ConnectError::IdentityChanged {
            address: address.to_string(),
            expected,
            actual,
        }),
    }
}

fn peer_certificate_hash(connection: &quinn::Connection) -> Result<[u8; 32], ConnectError> {
    let certificates = connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .ok_or(ConnectError::NoPeerCertificate)?;

    let end_entity = certificates
        .first()
        .ok_or(ConnectError::NoPeerCertificate)?;

    Ok(Sha256::digest(end_entity.as_ref()).into())
}

/// Map a protocol message onto a client event, dropping the handshake frames
/// that have no meaning after login.
fn translate(message: ServerControl) -> Option<ClientEvent> {
    Some(match message {
        ServerControl::UserJoined(info) => ClientEvent::UserJoined(*info),
        ServerControl::UserLeft { client, reason } => ClientEvent::UserLeft { client, reason },
        ServerControl::UserMoved { client, from, to } => {
            ClientEvent::UserMoved { client, from, to }
        }
        ServerControl::UserUpdated(info) => ClientEvent::UserUpdated(*info),
        ServerControl::VoiceActivity { client, speaking } => {
            ClientEvent::VoiceActivity { client, speaking }
        }

        ServerControl::ChannelCreated(channel) => ClientEvent::ChannelCreated(channel),
        ServerControl::ChannelUpdated(channel) => ClientEvent::ChannelUpdated(channel),
        ServerControl::ChannelRemoved(id) => ClientEvent::ChannelRemoved(id),

        ServerControl::MessagePosted { message, nonce } => ClientEvent::MessagePosted {
            message: *message,
            nonce,
        },
        ServerControl::MessageEdited {
            id,
            content,
            edited_at_unix_ms,
        } => ClientEvent::MessageEdited {
            id,
            content,
            edited_at_unix_ms,
        },
        ServerControl::MessageDeleted { id } => ClientEvent::MessageDeleted { id },
        ServerControl::History {
            channel,
            messages,
            reached_start,
        } => ClientEvent::History {
            channel,
            messages,
            reached_start,
        },
        ServerControl::Typing { client, channel } => ClientEvent::Typing { client, channel },

        ServerControl::Pong { nonce } => ClientEvent::Pong { nonce },
        ServerControl::Error { code, detail } => ClientEvent::ServerError { code, detail },

        // Reactions arrive as an updated reaction set; surfaced through the
        // message store once persistence exists.
        ServerControl::ReactionUpdated { .. } => return None,

        ServerControl::RoleCreated(role) => ClientEvent::RoleCreated(role),
        ServerControl::RoleUpdated(role) => ClientEvent::RoleUpdated(role),
        ServerControl::RoleDeleted { id } => ClientEvent::RoleDeleted { id },
        ServerControl::RolesReordered { positions } => ClientEvent::RolesReordered { positions },
        ServerControl::BanList { bans } => ClientEvent::BanList { bans },
        ServerControl::Ack { nonce } => ClientEvent::Ack { nonce },
        ServerControl::CommandFailed {
            nonce,
            code,
            detail,
        } => ClientEvent::CommandFailed {
            nonce,
            code,
            detail,
        },

        // Handshake frames; meaningless once the session is running.
        ServerControl::Hello(_) | ServerControl::AuthOk(_) | ServerControl::AuthFailed(_) => {
            return None
        }
    })
}

fn describe(message: &ServerControl) -> &'static str {
    match message {
        ServerControl::Hello(_) => "Hello",
        ServerControl::AuthOk(_) => "AuthOk",
        ServerControl::AuthFailed(_) => "AuthFailed",
        ServerControl::Error { .. } => "Error",
        _ => "an unexpected message",
    }
}

/// Convenience for the common `Arc<Client>` sharing pattern in a UI.
pub type SharedClient = Arc<Client>;

#[cfg(test)]
mod tests {
    use super::*;
    use pickle_identity::Identity;

    #[test]
    fn strict_policy_refuses_an_unknown_server() {
        let mut store = TrustStore::ephemeral();
        let fingerprint = Identity::generate().fingerprint();
        let result = apply_trust_policy(
            &mut store,
            TrustPolicy::Strict,
            "1.2.3.4:42071",
            "1.2.3.4:42071",
            fingerprint,
            "Server",
        );
        assert!(matches!(result, Err(ConnectError::NotTrusted { .. })));
    }

    #[test]
    fn first_use_policy_pins_an_unknown_server() {
        let mut store = TrustStore::ephemeral();
        let fingerprint = Identity::generate().fingerprint();
        apply_trust_policy(
            &mut store,
            TrustPolicy::OnFirstUse,
            "1.2.3.4:42071",
            "1.2.3.4:42071",
            fingerprint,
            "Server",
        )
        .unwrap();
        assert_eq!(
            store.check("1.2.3.4:42071", fingerprint),
            TrustDecision::Recognised
        );
    }

    #[test]
    fn a_changed_identity_is_refused_under_every_safe_policy() {
        for policy in [TrustPolicy::OnFirstUse, TrustPolicy::Strict] {
            let mut store = TrustStore::ephemeral();
            let original = Identity::generate().fingerprint();
            let impostor = Identity::generate().fingerprint();
            store.trust("1.2.3.4:42071", original, "Server");

            let result = apply_trust_policy(
                &mut store,
                policy,
                "1.2.3.4:42071",
                "1.2.3.4:42071",
                impostor,
                "Server",
            );
            assert!(
                matches!(result, Err(ConnectError::IdentityChanged { .. })),
                "{policy:?} must not silently accept a new identity"
            );
        }
    }

    #[test]
    fn a_deliberate_repin_resolves_a_changed_identity() {
        // The resolution path the client UI drives: the user is shown the new
        // fingerprint, agrees to it, the pin is replaced with exactly that
        // value — and only then does the same connection succeed. Trusting is
        // an act on the store, never a policy loosening.
        let mut store = TrustStore::ephemeral();
        let original = Identity::generate().fingerprint();
        let replacement = Identity::generate().fingerprint();
        store.trust("1.2.3.4:42071", original, "Server");

        let check = |store: &mut TrustStore| {
            apply_trust_policy(
                store,
                TrustPolicy::OnFirstUse,
                "1.2.3.4:42071",
                "1.2.3.4:42071",
                replacement,
                "Server",
            )
        };

        assert!(matches!(
            check(&mut store),
            Err(ConnectError::IdentityChanged { .. })
        ));

        store.trust("1.2.3.4:42071", replacement, "Server");
        check(&mut store).expect("the replaced pin must be honoured");

        // And a server that changes identity *again* after the user agreed is
        // refused again — nothing was pinned sight-unseen.
        let third = Identity::generate().fingerprint();
        let result = apply_trust_policy(
            &mut store,
            TrustPolicy::OnFirstUse,
            "1.2.3.4:42071",
            "1.2.3.4:42071",
            third,
            "Server",
        );
        assert!(matches!(result, Err(ConnectError::IdentityChanged { .. })));
    }

    #[test]
    fn insecure_policy_pins_nothing() {
        let mut store = TrustStore::ephemeral();
        let fingerprint = Identity::generate().fingerprint();
        apply_trust_policy(
            &mut store,
            TrustPolicy::Insecure,
            "1.2.3.4:42071",
            "1.2.3.4:42071",
            fingerprint,
            "Server",
        )
        .unwrap();
        assert!(store.get("1.2.3.4:42071").is_none());
    }

    #[test]
    fn handshake_frames_do_not_leak_into_the_event_stream() {
        assert!(translate(ServerControl::AuthFailed(AuthFailure::ServerFull)).is_none());
        assert!(translate(ServerControl::Pong { nonce: 1 }).is_some());
    }

    #[test]
    fn auth_failures_map_to_actionable_messages() {
        let reason: RejectionReason = AuthFailure::SecurityLevelTooLow {
            required: 20,
            provided: 8,
        }
        .into();
        let text = reason.to_string();
        assert!(text.contains("20") && text.contains('8'), "{text}");
    }
}
